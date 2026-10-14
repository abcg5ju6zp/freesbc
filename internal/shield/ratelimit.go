package shield

import (
	"container/list"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// bucketCap is the hard ceiling on per-source buckets, the same bound as
// the ban table (banCap): a flood of distinct sources must not grow the
// map without bound. At the cap the least recently used bucket is evicted.
const bucketCap = banCap

// bucketKey identifies a bucket: the source (bucketKey: an IPv6 source by
// its /64) plus the shield rule generation the bucket was born under. A
// rule change starts fresh buckets; old buckets are never charged again
// and leave once they would have refilled (see prune). The zero address
// marks the global bucket (one per generation).
type bucketKey struct {
	addr netip.Addr
	gen  string
}

// bucket is a token bucket: tokens refill continuously toward capacity.
// rate and interval are the rule it was born with, so prune can tell when
// it has refilled to full and a snapshot can carry the facts needed to
// continue it without knowing the config.
type bucket struct {
	key      bucketKey
	tokens   float64
	last     time.Time
	interval time.Duration
	rate     int
}

// rateLimiter is a per-source (or single global) token-bucket limiter.
// The rate/interval/perIP parameters are passed per call so a hot-reloaded
// config takes effect without rebuilding the limiter, but each call names
// the active rule generation: only a matching bucket is charged, so a
// threshold change never spends or refills an old bucket under new rules
// (only the buckets carry state). Per-source buckets are keyed by bucketKey
// (an IPv6 source by its /64) and held in an LRU capped at bucketCap. now
// is injectable for tests.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[bucketKey]*list.Element // of *bucket
	lru     *list.List                  // front = most recently used
	now     func() time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{buckets: make(map[bucketKey]*list.Element), lru: list.New(), now: time.Now}
}

// bucketKeyFor is the per-source bucket key: an IPv4 address (4in6
// unmapped) as is, an IPv6 address by its /64. One IPv6 host is normally
// given a whole /64, so keying by address would hand one host unlimited
// buckets.
func bucketKeyFor(src netip.Addr) netip.Addr {
	src = src.Unmap()
	if src.Is6() {
		return netip.PrefixFrom(src.WithZone(""), 64).Masked().Addr()
	}
	return src
}

// allow consumes one token for src under gen and reports whether it was
// available. Capacity (burst) = rate; refill = rate tokens per interval.
func (r *rateLimiter) allow(src netip.Addr, rate int, interval time.Duration, perIP bool, gen string) bool {
	if rate <= 0 || interval <= 0 {
		return true // misconfigured → don't throttle
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	key := bucketKey{gen: gen}
	if perIP {
		key.addr = bucketKeyFor(src)
	}
	var b *bucket
	if e := r.buckets[key]; e != nil {
		r.lru.MoveToFront(e)
		b = e.Value.(*bucket)
	} else {
		if r.lru.Len() >= bucketCap {
			oldest := r.lru.Back()
			r.lru.Remove(oldest)
			delete(r.buckets, oldest.Value.(*bucket).key)
		}
		b = &bucket{key: key, tokens: float64(rate), last: now, interval: interval, rate: rate}
		r.buckets[key] = r.lru.PushFront(b)
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.interval = interval
	b.rate = rate
	b.tokens = math.Min(float64(rate), b.tokens+elapsed*float64(rate)/interval.Seconds())
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// prune drops per-source buckets that have been idle for at least their own
// refill interval: such a bucket has refilled to full, and a fresh one
// starts full, so removing it loses no state. A superseded-generation
// bucket is never charged again, so this is also what eventually reclaims
// it. A partly drained bucket is kept, so an N/h limit is not reset by an
// idle minute. Call periodically.
func (r *rateLimiter) prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	// A full walk (buckets can carry different intervals), bounded by
	// bucketCap and run once a minute.
	for e := r.lru.Back(); e != nil; {
		prev := e.Prev()
		if b := e.Value.(*bucket); now.Sub(b.last) >= b.interval {
			r.lru.Remove(e)
			delete(r.buckets, b.key)
		}
		e = prev
	}
}

// storedBucket is one persisted, still-drained bucket. Full buckets are
// never stored (a fresh bucket starts full).
type storedBucket struct {
	Src        netip.Addr // zero for the global bucket
	Generation string
	Tokens     float64
	Last       time.Time
	Interval   time.Duration
	Rate       int
}

// drained copies buckets that have not refilled to full; these are the only
// "rate time facts" a restart needs. Idle-full buckets are omitted just as
// prune deletes them.
func (r *rateLimiter) drained() []storedBucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]storedBucket, 0, len(r.buckets))
	for _, e := range r.buckets {
		b := e.Value.(*bucket)
		elapsed := now.Sub(b.last).Seconds()
		tokens := math.Min(float64(b.rate), b.tokens+elapsed*float64(b.rate)/b.interval.Seconds())
		if tokens >= float64(b.rate) {
			continue // refilled to full: nothing worth carrying
		}
		out = append(out, storedBucket{Src: b.key.addr, Generation: b.key.gen, Tokens: b.tokens,
			Last: b.last, Interval: b.interval, Rate: b.rate})
	}
	return out
}

// restore loads validated, still-drained buckets.
func (r *rateLimiter) restore(in []storedBucket) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	restored := 0
	for _, e := range in {
		key := bucketKey{addr: e.Src, gen: e.Generation}
		if _, dup := r.buckets[key]; dup {
			continue
		}
		if r.lru.Len() >= bucketCap {
			oldest := r.lru.Back()
			r.lru.Remove(oldest)
			delete(r.buckets, oldest.Value.(*bucket).key)
		}
		b := &bucket{key: key, tokens: e.Tokens, last: e.Last, interval: e.Interval, rate: e.Rate}
		r.buckets[key] = r.lru.PushFront(b)
		restored++
	}
	return restored
}

// Limiter is a single global token bucket: Allow consumes one token from a
// bucket of capacity rl.Rate that refills rl.Rate tokens per rl.Interval.
// The limit is passed per call, so a hot-reloaded value applies at once;
// rl.PerIP is ignored (the bucket is always global). Safe for concurrent
// use. The zero value is not usable; call NewLimiter.
type Limiter struct{ rl *rateLimiter }

// NewLimiter returns an empty (full) global limiter.
func NewLimiter() *Limiter { return &Limiter{rl: newRateLimiter()} }

// globalGeneration tags the edge-owned global limiter's single bucket; it
// is never snapshotted, and the limit is passed per call as before.
const globalGeneration = "global"

// Allow reports whether a token was available and consumes it. A limit with
// no rate or interval never refuses.
func (l *Limiter) Allow(rl config.RateLimit) bool {
	return l.rl.allow(netip.Addr{}, rl.Rate, rl.Interval, false, globalGeneration)
}

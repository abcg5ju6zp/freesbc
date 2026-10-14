package shield

import (
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// banCap is the hard ceiling on distinct banned sources: a
// unique-source flood within one shield.ban window (default 1h) must
// not grow the table without bound. 64k entries is far beyond any realistic
// deployment's distinct-source count while bounding memory to ~a few MiB.
const banCap = 65536

// sweepEvery bounds how often a full expired-entry sweep runs at the cap:
// without it, every refused unique source would pay an O(cap) scan, letting
// a sustained flood of fresh source IPs burn a core sweeping an
// already-fresh table. Refusals between sweeps are O(1); the background
// pruneLoop keeps clearing expired entries regardless.
const sweepEvery = time.Second

// Ban reasons recorded at insert: a scanner User-Agent verdict, and a
// source over a strike threshold (Strike). Rate limiting and REGISTER
// enumeration only drop.
const (
	BanReasonScanner  = "scanner"
	BanReasonRegister = "register"
	// BanReasonAdmission is a source whose requests admission kept
	// dropping (shield.admission_ban).
	BanReasonAdmission = "admission"
)

// Ban kinds: which of the two tables an entry lives in.
const (
	BanKindIP        = "ip"
	BanKindUDPSocket = "udp_socket"
	// BanKindUDPIP bans an IP on UDP only: its TCP, TLS, WS and WSS
	// connections and reads are unaffected (see Shield.StrikeOn).
	BanKindUDPIP = "udp_ip"
)

// banEntry is one ban: when it expires, when it was first recorded, why,
// and the shield rule generation it was created under.
type banEntry struct {
	until  time.Time
	since  time.Time
	reason string
	gen    string
}

// banList is an in-memory ban table: a source key mapped, per shield rule
// generation, to the instant its ban expires (plus when and why it
// started), with lazy expiry on read. The Shield keeps three: source IPs
// for connection-oriented verdicts, UDP source IPs (UDP only) and UDP
// source sockets (see Shield.CheckFrom). Separate tables mean a
// forged-datagram flood that fills the socket table can never keep a real
// scanner's IP out of the IP table.
//
// A source can carry one live entry per generation at once: a rule change
// starts a new generation without touching the old entry, which stays in
// force until its own deadline; a lookup is banned when ANY generation is.
type banList[K comparable] struct {
	mu    sync.Mutex
	until map[K]map[string]banEntry
	now   func() time.Time

	// lastSweep is the (b.now-based) instant of the most recent full sweep
	// at the cap; zero value means "never", so the first refusal always
	// sweeps.
	lastSweep time.Time

	// overflow counts ban additions refused at the hard cap (cumulative,
	// exposed via Shield.Stats).
	overflow atomic.Int64
}

func newBanList() *banList[netip.Addr] { return newBanTable[netip.Addr]() }

func newBanTable[K comparable]() *banList[K] {
	return &banList[K]{until: make(map[K]map[string]banEntry), now: time.Now}
}

// ban blocks key for dur under generation gen. An existing ban of the same
// generation is extended, never shortened: the expiry becomes the later of
// the two (P2-SHD-008). A ban under another generation is an independent
// entry (it completes on its own deadline). It reports whether the ban was
// recorded: when the table is at banCap and key is not already banned,
// expired entries are swept lazily first, and if the table is still full
// the addition is refused (the overflow counter increments).
func (b *banList[K]) ban(key K, dur time.Duration, reason, gen string) bool {
	b.mu.Lock()
	gens, tracked := b.until[key]
	if !tracked && len(b.until) >= banCap {
		if b.now().Sub(b.lastSweep) >= sweepEvery {
			now := b.now()
			for k, gs := range b.until {
				for g, e := range gs {
					if !now.Before(e.until) {
						delete(gs, g)
					}
				}
				if len(gs) == 0 {
					delete(b.until, k)
				}
			}
			b.lastSweep = now
		}
		if len(b.until) >= banCap {
			b.mu.Unlock()
			b.overflow.Add(1)
			return false
		}
	}
	now := b.now()
	if !tracked {
		b.until[key] = map[string]banEntry{gen: {until: now.Add(dur), since: now, reason: reason, gen: gen}}
	} else if old, ok := gens[gen]; !ok {
		// A new generation for an already-banned source: its own entry.
		gens[gen] = banEntry{until: now.Add(dur), since: now, reason: reason, gen: gen}
	} else if until := now.Add(dur); until.After(old.until) {
		// An extension keeps the original start time and reason.
		old.until = until
		gens[gen] = old
	}
	b.mu.Unlock()
	return true
}

// overflowed returns the cumulative number of ban additions refused at the
// hard cap.
func (b *banList[K]) overflowed() int64 { return b.overflow.Load() }

// banned reports whether key is currently banned under ANY generation,
// deleting entries once their ban has expired (lazy expiry).
func (b *banList[K]) banned(key K) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	gens, ok := b.until[key]
	if !ok {
		return false
	}
	now := b.now()
	live := false
	for g, e := range gens {
		if !now.Before(e.until) { // now >= expiry
			delete(gens, g)
			continue
		}
		live = true
	}
	if len(gens) == 0 {
		delete(b.until, key)
	}
	return live
}

// unban removes exactly key's ban of generation gen; an empty generation
// matches nothing. Other generations of the same key are untouched. It
// reports whether an entry was removed.
func (b *banList[K]) unban(key K, gen string) bool {
	if gen == "" {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	gens, ok := b.until[key]
	if !ok {
		return false
	}
	if _, ok := gens[gen]; !ok {
		return false
	}
	delete(gens, gen)
	if len(gens) == 0 {
		delete(b.until, key)
	}
	return true
}

// size returns the number of distinct tracked keys (possibly expired).
func (b *banList[K]) size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.until)
}

// prune drops expired entries across every generation.
func (b *banList[K]) prune() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for key, gens := range b.until {
		for g, e := range gens {
			if !now.Before(e.until) {
				delete(gens, g)
			}
		}
		if len(gens) == 0 {
			delete(b.until, key)
		}
	}
}

// listed is one live ban copied out of the table.
type listed[K comparable] struct {
	key K
	banEntry
}

// live copies the unexpired entries out under the lock, without deleting
// any. The caller sorts and slices outside it.
func (b *banList[K]) live() []listed[K] {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	out := make([]listed[K], 0, len(b.until))
	for k, gens := range b.until {
		for _, e := range gens {
			if now.Before(e.until) {
				out = append(out, listed[K]{k, e})
			}
		}
	}
	return out
}

// storedBan is one ban as persisted: the validated key with the rule
// generation and the absolute times the ban runs by.
type storedBan[K comparable] struct {
	Key        K
	Generation string
	Reason     string
	Since      time.Time
	Until      time.Time
}

// restore loads validated entries, skipping any already expired. The
// caller has validated the input (bounds, reasons, generations), so the
// table inserts without the hard cap; it reports how many became live and
// how many were past their deadline.
func (b *banList[K]) restore(in []storedBan[K]) (restored, expired int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	for _, e := range in {
		if !now.Before(e.Until) {
			expired++
			continue
		}
		gens, ok := b.until[e.Key]
		if !ok {
			gens = map[string]banEntry{}
			b.until[e.Key] = gens
		}
		gens[e.Generation] = banEntry{until: e.Until, since: e.Since, reason: e.Reason, gen: e.Generation}
		restored++
	}
	return restored, expired
}

// dump copies the live entries in the persistence record shape.
func (b *banList[K]) dump() []storedBan[K] {
	live := b.live()
	out := make([]storedBan[K], 0, len(live))
	for _, e := range live {
		out = append(out, storedBan[K]{Key: e.key, Generation: e.gen, Reason: e.reason, Since: e.since, Until: e.until})
	}
	return out
}

// sortBans orders newest first, then by source string, then generation, so
// a page boundary is stable between calls.
func sortBans(in []BanInfo) {
	sort.Slice(in, func(i, j int) bool {
		if !in[i].Since.Equal(in[j].Since) {
			return in[i].Since.After(in[j].Since)
		}
		if in[i].Source != in[j].Source {
			return in[i].Source < in[j].Source
		}
		if in[i].Kind != in[j].Kind {
			return in[i].Kind < in[j].Kind
		}
		return in[i].Generation < in[j].Generation
	})
}

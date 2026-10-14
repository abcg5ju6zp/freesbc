package shield

import (
	"container/list"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Strike reasons: what a plane reports through Shield.Strike. Each has its
// own threshold key and is also the reason recorded on the ban it leads
// to.
const (
	// StrikeRegister is a failed REGISTER credential attempt
	// (shield.register_ban).
	StrikeRegister = BanReasonRegister
	// StrikeAdmission is a public request dropped by edge admission
	// (shield.admission_ban).
	StrikeAdmission = BanReasonAdmission
	// StrikeAdmissionUDP is the offender-table reason of admission strikes
	// from UDP, counted apart from stream ones (see StrikeOn).
	StrikeAdmissionUDP = StrikeAdmission + "_udp"
)

// offenderCap bounds the offender table. A flood of distinct sources only
// evicts the least recently struck entries, so memory stays bounded and a
// source that keeps failing stays tracked (it is always the most recent).
const offenderCap = 16384

type offenderKey struct {
	src    netip.Addr // bucketKey: an IPv4 address, an IPv6 /64
	reason string
	// gen is the shield rule generation the window opened under. Strikes
	// under a newer generation open a separate window; the old one runs to
	// its own deadline under the rules it was born with.
	gen string
}

// offender is one source's strikes of one reason within a fixed window
// that opens at its first strike. n is the threshold and banDur the ban
// duration captured when the window opened, so a restored or
// superseded-generation window always completes under its own rules.
type offender struct {
	key    offenderKey
	start  time.Time
	window time.Duration
	banDur time.Duration
	n      int
	count  int
	over   bool // the threshold was crossed in this window (WARN once)
}

// offenderTable is an LRU-capped table of per-source strike counters.
type offenderTable struct {
	mu      sync.Mutex
	entries map[offenderKey]*list.Element // of *offender
	lru     *list.List                    // front = most recently struck
	max     int
	now     func() time.Time
}

func newOffenderTable() *offenderTable {
	return &offenderTable{entries: map[offenderKey]*list.Element{}, lru: list.New(), max: offenderCap, now: time.Now}
}

// strike adds one strike under lim and generation gen and returns the
// window's count, whether it is over lim.N, and whether this strike is the
// one that crossed it. banDur is the ban duration this generation applies
// when the window crosses.
func (t *offenderTable) strike(key offenderKey, lim config.StrikeLimit, banDur time.Duration) (count int, over, crossed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var o *offender
	if el, ok := t.entries[key]; ok {
		o = el.Value.(*offender)
		t.lru.MoveToFront(el)
		if now.Sub(o.start) >= o.window {
			o.start, o.count, o.over = now, 0, false
		}
	} else {
		if t.lru.Len() >= t.max {
			oldest := t.lru.Back()
			delete(t.entries, oldest.Value.(*offender).key)
			t.lru.Remove(oldest)
		}
		o = &offender{key: key, start: now, window: lim.Window, banDur: banDur, n: lim.N}
		t.entries[key] = t.lru.PushFront(o)
	}
	o.count++
	if o.count <= o.n {
		return o.count, false, false
	}
	crossed = !o.over
	o.over = true
	return o.count, true, crossed
}

// clear forgets every generation of src's strikes of reason.
func (t *offenderTable) clear(src netip.Addr, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, el := range t.entries {
		if k.src == src && k.reason == reason {
			delete(t.entries, k)
			t.lru.Remove(el)
		}
	}
}

// prune drops the entries whose window has ended.
func (t *offenderTable) prune() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, el := range t.entries {
		if o := el.Value.(*offender); now.Sub(o.start) >= o.window {
			delete(t.entries, k)
			t.lru.Remove(el)
		}
	}
}

func (t *offenderTable) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// live copies the entries whose window is still open.
func (t *offenderTable) live() []offender {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	out := make([]offender, 0, len(t.entries))
	for _, el := range t.entries {
		if o := el.Value.(*offender); now.Sub(o.start) < o.window {
			out = append(out, *o)
		}
	}
	return out
}

// storedOffender is one persisted strike window.
type storedOffender struct {
	Src        netip.Addr
	Reason     string
	Generation string
	Start      time.Time
	Window     time.Duration
	BanDur     time.Duration
	N          int
	Count      int
	Over       bool
}

// restore loads validated windows, skipping any already closed.
func (t *offenderTable) restore(in []storedOffender) (restored, expired int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, e := range in {
		if now.Sub(e.Start) >= e.Window {
			expired++
			continue
		}
		key := offenderKey{src: e.Src, reason: e.Reason, gen: e.Generation}
		if _, dup := t.entries[key]; dup {
			continue
		}
		if t.lru.Len() >= t.max {
			oldest := t.lru.Back()
			delete(t.entries, oldest.Value.(*offender).key)
			t.lru.Remove(oldest)
		}
		o := &offender{key: key, start: e.Start, window: e.Window, banDur: e.BanDur, n: e.N, count: e.Count, over: e.Over}
		t.entries[key] = t.lru.PushFront(o)
		restored++
	}
	return restored, expired
}

// dump copies the open windows in the persistence record shape.
func (t *offenderTable) dump() []storedOffender {
	live := t.live()
	out := make([]storedOffender, 0, len(live))
	for _, o := range live {
		out = append(out, storedOffender{Src: o.key.src, Reason: o.key.reason, Generation: o.key.gen,
			Start: o.start, Window: o.window, BanDur: o.banDur, N: o.n, Count: o.count, Over: o.over})
	}
	return out
}

// Strike records one strike of reason (StrikeRegister) against src and
// reports whether src is banned as a result. Over the reason's threshold
// (a hot key, e.g. shield.register_ban) every further strike within the
// window bans src's IP for shield.ban with reason as the ban reason, under
// the rule generation active now; the first is logged at WARN. Strikes are
// counted per source key (an IPv6 source by its /64, so an attacker
// rotating addresses inside its /64 shares one count), while the ban names
// the struck address.
//
// A carrier source is never struck, and an unknown reason or a threshold
// of "off" counts nothing. The caller is responsible for the strike being
// trustworthy: a forgeable datagram must not be able to strike a victim's
// address (see the edge's REGISTER guard).
func (s *Shield) Strike(src netip.Addr, reason string) bool {
	return s.strike(src, reason, false)
}

// StrikeOn is Strike for a request that arrived on transport. A UDP source
// address can be forged, so strikes from UDP are counted apart from stream
// strikes (offender reason StrikeAdmissionUDP) and ban the IP on UDP only
// (BanKindUDPIP): a forged datagram flood can silence the victim's UDP,
// never its TCP, TLS, WS or WSS. A stream source survived a handshake, so
// its strikes ban the IP on every transport. An unknown transport is
// treated as UDP.
func (s *Shield) StrikeOn(src netip.Addr, reason, transport string) bool {
	return s.strike(src, reason, !bannableTransport(transport))
}

func (s *Shield) strike(src netip.Addr, reason string, udp bool) bool {
	src = src.Unmap()
	if s.isCarrier(src) {
		return false
	}
	cfg := s.store.Current()
	lim := s.strikeLimit(cfg, reason)
	if lim.Off || lim.N <= 0 || lim.Window <= 0 {
		return false
	}
	gen := s.generation()
	table, key := s.bans, offenderKey{src: bucketKeyFor(src), reason: reason, gen: string(gen)}
	if udp {
		table, key.reason = s.udpBans, reason+"_udp"
	}
	count, over, crossed := s.offenders.strike(key, lim, cfg.Shield.Ban.Std())
	if !over {
		return false
	}
	if !table.ban(src, cfg.Shield.Ban.Std(), reason, string(gen)) {
		s.log.Debug("shield ban table at hard cap; strike ban refused", "source", src, "reason", reason)
		return false
	}
	s.markDirty()
	if crossed {
		s.log.Warn("shield banned source for repeated failures", "source", src, "reason", reason,
			"strikes", count, "window", lim.Window.String(), "ban", cfg.Shield.Ban.Std().String(),
			"generation", gen.Short())
	} else {
		s.log.Debug("shield extended strike ban", "source", src, "reason", reason, "strikes", count)
	}
	return true
}

// ClearStrikes forgets src's strikes of reason: the plane saw src succeed
// (a 2xx registration), so its earlier failures were not an attack. Every
// rule generation of the reason is cleared, including a superseded one.
func (s *Shield) ClearStrikes(src netip.Addr, reason string) {
	src = bucketKeyFor(src.Unmap())
	s.offenders.clear(src, reason)
	s.markDirty()
	if reason == StrikeAdmission {
		s.offenders.clear(src, StrikeAdmissionUDP)
	}
}

// strikeLimit parses reason's threshold from cfg, cached until the string
// changes.
func (s *Shield) strikeLimit(cfg *config.Config, reason string) config.StrikeLimit {
	var str string
	switch reason {
	case StrikeRegister:
		str = cfg.Shield.RegisterBan
	case StrikeAdmission:
		str = cfg.Shield.AdmissionBan
	default:
		return config.StrikeLimit{Off: true}
	}
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	if s.strikeStr == nil {
		s.strikeStr = map[string]string{}
		s.strikeOpts = map[string]config.StrikeLimit{}
	}
	if s.strikeStr[reason] != str {
		lim, err := config.ParseStrikeLimit(str)
		if err != nil {
			lim = config.StrikeLimit{Off: true}
		}
		s.strikeOpts[reason] = lim
		s.strikeStr[reason] = str
	}
	return s.strikeOpts[reason]
}

// OffenderInfo is one source with strikes in an open window.
type OffenderInfo struct {
	// Source is the struck IPv4 address, or an IPv6 /64 prefix.
	Source string
	// Reason is the strike reason (StrikeRegister).
	Reason string
	// Generation is the shield rule generation the window opened under.
	Generation string
	// Strikes is the count in the current window, which opened at Since
	// and closes at Until.
	Strikes      int
	Since, Until time.Time
}

// maxOffenders bounds one Offenders list.
const maxOffenders = 1000

// Offenders returns up to limit (clamped to 1..1000) sources with strikes
// in an open window, most strikes first, and the total number of such
// sources. The table is copied under its lock and sorted outside it.
func (s *Shield) Offenders(limit int) (top []OffenderInfo, total int) {
	limit = min(max(limit, 1), maxOffenders)
	live := s.offenders.live()
	sort.Slice(live, func(i, j int) bool {
		if live[i].count != live[j].count {
			return live[i].count > live[j].count
		}
		if !live[i].start.Equal(live[j].start) {
			return live[i].start.Before(live[j].start)
		}
		if live[i].key.src != live[j].key.src {
			return live[i].key.src.Less(live[j].key.src)
		}
		if live[i].key.reason != live[j].key.reason {
			return live[i].key.reason < live[j].key.reason
		}
		return live[i].key.gen < live[j].key.gen
	})
	total = len(live)
	top = make([]OffenderInfo, 0, min(limit, total))
	for _, o := range live[:min(limit, total)] {
		src := o.key.src.String()
		if o.key.src.Is6() {
			src = netip.PrefixFrom(o.key.src, 64).String()
		}
		top = append(top, OffenderInfo{Source: src, Reason: o.key.reason, Generation: o.key.gen, Strikes: o.count,
			Since: o.start, Until: o.start.Add(o.window)})
	}
	return top, total
}

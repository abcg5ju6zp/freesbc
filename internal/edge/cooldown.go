package edge

import (
	"sync"
	"time"
)

// cooldownTable tracks per-name cooldowns passively: a target that produced no response at all across a
// whole attempt (a failDial) is Penalized and then skipped in favour of
// alternatives until the cooldown window elapses — lazily, with no
// background sweeper — or a later successful exchange Recovers it. There is
// deliberately no active probing (no OPTIONS): an upstream
// switch receives only the traffic it is answering, and a
// health-check cadence of its own is exactly the sort of unsolicited traffic
// a carrier's edge will drop or penalize.
//
// Keyed by NAME, never by address (a bounded, operator-chosen name set).
// Safe for concurrent use.
type cooldownTable struct {
	mu    sync.Mutex
	until map[string]time.Time // name → cooldown-until
	// lastFail is when each name was last Penalized. Recover clears the
	// cooldown but keeps this, so an operator still sees the last failure.
	lastFail map[string]time.Time
	// reg is the per-node REGISTER circuit breaker (see regBreaker).
	reg map[string]*regBreaker
}

func newCooldownTable() *cooldownTable {
	return &cooldownTable{
		until:    make(map[string]time.Time),
		lastFail: make(map[string]time.Time),
		reg:      make(map[string]*regBreaker),
	}
}

// regBreaker is one node's REGISTER circuit breaker. After
// registerBreakerThreshold consecutive unanswered REGISTER attempts it
// opens: until openUntil the node is not dialed for a REGISTER at all.
// Once that passes it is half-open and admits one probe at a time; any
// answer closes it, another silence re-opens it with a longer window
// (registerBreakerBackoff). Unlike the cooldown, which only reorders, an
// open breaker stops the dialing.
type regBreaker struct {
	fails     int       // consecutive unanswered attempts
	level     int       // index into registerBreakerBackoff of the next open
	open      bool      // opened and not yet closed by an answer
	openUntil time.Time // no dial before this
	probeBy   time.Time // a half-open probe is in flight until this
	lastWarn  time.Time // last unanswered WARN logged for the node
}

const (
	// registerBreakerThreshold is how many consecutive unanswered REGISTER
	// attempts open a node's breaker.
	registerBreakerThreshold = 3
	// registerWarnWindow bounds the unanswered-REGISTER WARN to one per
	// node per window.
	registerWarnWindow = 30 * time.Second
)

// registerBreakerBackoff is the open window per consecutive opening: 30 s,
// 1 m, then 5 m.
var registerBreakerBackoff = [...]time.Duration{30 * time.Second, time.Minute, 5 * time.Minute}

// RegisterAllow reports whether a REGISTER may be dialed to the node now.
// A closed breaker always allows. An open one refuses until its window has
// passed, then admits a single probe (the first caller, probe=true) and
// refuses the rest until that probe is answered, fails, is released
// (RegisterRelease) or its budget (probeBudget) is spent.
func (h *cooldownTable) RegisterAllow(name string, probeBudget time.Duration) (allow, probe bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.reg[name]
	if b == nil || !b.open {
		return true, false
	}
	now := time.Now()
	if now.Before(b.openUntil) || now.Before(b.probeBy) {
		return false, false
	}
	b.probeBy = now.Add(probeBudget)
	return true, true
}

// RegisterRelease gives up an admitted probe that ended without a verdict
// (the attempt was never sent, or the shared budget ran out first), so the
// next caller may probe instead of waiting out the probe budget.
func (h *cooldownTable) RegisterRelease(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if b := h.reg[name]; b != nil {
		b.probeBy = time.Time{}
	}
}

// RegisterAnswered closes the node's breaker: any response proves the
// registrar is answering.
func (h *cooldownTable) RegisterAnswered(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if b := h.reg[name]; b != nil {
		b.fails, b.level, b.open = 0, 0, false
		b.openUntil, b.probeBy = time.Time{}, time.Time{}
	}
}

// RegisterUnanswered records one REGISTER attempt that drew no response.
// probe is true only for the attempt RegisterAllow admitted as the
// half-open probe. It reports whether this attempt opened (or re-opened)
// the breaker, the open window, and whether the caller should log a WARN
// now (at most one per node per registerWarnWindow, and always when the
// breaker opens). An attempt dialed before the breaker opened that
// finishes unanswered while it is open (probe=false) is only counted: it
// neither escalates the backoff nor forces a WARN.
func (h *cooldownTable) RegisterUnanswered(name string, probe bool) (opened bool, window time.Duration, warn bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b := h.reg[name]
	if b == nil {
		b = &regBreaker{}
		h.reg[name] = b
	}
	now := time.Now()
	b.fails++
	if (b.open && probe) || (!b.open && b.fails >= registerBreakerThreshold) {
		// A failed half-open probe, or the threshold reached.
		window = registerBreakerBackoff[min(b.level, len(registerBreakerBackoff)-1)]
		b.level++
		b.open, opened = true, true
		b.openUntil = now.Add(window)
		b.probeBy = time.Time{}
	}
	if opened || now.Sub(b.lastWarn) >= registerWarnWindow {
		b.lastWarn = now
		warn = true
	}
	return opened, window, warn
}

// Available reports whether the target may be used now — true unless it is
// inside an unexpired cooldown window.
func (h *cooldownTable) Available(name string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	t, ok := h.until[name]
	return !ok || !time.Now().Before(t) // now >= t ⇒ expired ⇒ available
}

// Penalize starts (or extends) the target's cooldown window.
func (h *cooldownTable) Penalize(name string, cooldown time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.until[name] = now.Add(cooldown)
	h.lastFail[name] = now
}

// Recover clears any cooldown on the target, making it immediately
// available — a target that just answered is, by construction, healthy.
func (h *cooldownTable) Recover(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.until, name)
}

// Switch node states.
const (
	NodeHealthy     = "healthy"
	NodeCoolingDown = "cooling_down"
)

// SwitchNodeInfo is the operator view of one switch node's passive health.
type SwitchNodeInfo struct {
	Address string // "IP:port", the node's name
	State   string // NodeHealthy or NodeCoolingDown
	// CooldownRemaining and CooldownUntil are zero unless cooling down.
	CooldownRemaining time.Duration
	CooldownUntil     time.Time
	// LastFailure is when the node was last penalized; zero if never.
	LastFailure time.Time
}

// snapshot reports the state of each of names, in the order given, as of
// now. A name the table has never seen is healthy.
func (h *cooldownTable) snapshot(names []string, now time.Time) []SwitchNodeInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]SwitchNodeInfo, 0, len(names))
	for _, n := range names {
		info := SwitchNodeInfo{Address: n, State: NodeHealthy, LastFailure: h.lastFail[n]}
		until, ok := h.until[n]
		if b := h.reg[n]; b != nil && b.open && b.openUntil.After(until) {
			// An open REGISTER breaker outlasts the 30 s cooldown.
			until, ok = b.openUntil, true
		}
		if ok && now.Before(until) {
			info.State = NodeCoolingDown
			info.CooldownUntil = until
			info.CooldownRemaining = until.Sub(now)
		}
		out = append(out, info)
	}
	return out
}

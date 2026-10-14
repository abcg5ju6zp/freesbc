package edge

import (
	"net/netip"
	"sync"
)

// This file owns the identity of a stream connection (a "flow") and the
// one ordered teardown a flow goes through when its connection is lost.
//
// Why a flow identity exists at all: the cleanup of a stream registration
// used to be keyed by the connection's remote transport address
// (transport + IP:port). A client that loses a TCP/TLS/WS connection and
// reconnects immediately can come back with the SAME source address — the
// old socket is still closing while the REGISTER on the new one succeeds.
// The old connection's delayed close callback then matched the address and
// deleted the NEW binding, or the two paths interleaved with an expiry
// scan and left state still aimed at a socket nobody held. Every teardown
// path therefore acts on a flow ID fixed at the connection's birth and a
// binding version fixed at each successful REGISTER, never on an address.

// flowID identifies one accepted or dialed stream connection for the life
// of the process. Zero is "no flow": a UDP registration owns no connection
// FreeSBC can close, and nothing ever retires it by a flow.
type flowID uint64

// flowKey is the address a flow currently occupies. It is only a lookup
// key: registrations bind to the flow ID, not to this.
type flowKey struct {
	transport string
	ap        netip.AddrPort
}

// flowEntry is one open flow and the connection that carries it.
type flowEntry struct {
	id      flowID
	key     flowKey
	carrier bool
	conn    *streamConn
}

// flowRegistry hands out flow IDs and remembers which flow currently owns
// each (transport, source address). A newer issue for the same key
// replaces the mapping, while every connection keeps the ID it was born
// with: the old connection retires itself by that ID and can never name
// the new one.
type flowRegistry struct {
	mu      sync.Mutex
	next    flowID
	current map[flowKey]flowID
	open    map[flowID]*flowEntry
}

func newFlowRegistry() *flowRegistry {
	return &flowRegistry{current: map[flowKey]flowID{}, open: map[flowID]*flowEntry{}}
}

// issue assigns a fresh flow ID and records c as the current owner of its
// (transport, source address).
func (r *flowRegistry) issue(transport string, ap netip.AddrPort, c *streamConn, carrier bool) flowID {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	id := r.next
	key := flowKey{transport: transport, ap: ap}
	r.current[key] = id
	r.open[id] = &flowEntry{id: id, key: key, carrier: carrier, conn: c}
	return id
}

// currentID is the flow now owning (transport, ap), or 0 once it has
// retired. A REGISTER stamps its binding with this value, so a response
// arriving after the flow's own retirement cannot install on a dead
// connection.
func (r *flowRegistry) currentID(transport string, ap netip.AddrPort) flowID {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current[flowKey{transport: transport, ap: ap}]
}

// alive reports whether flow id is still open. It is the check Location
// runs before accepting a registrar response for a stream binding.
func (r *flowRegistry) alive(id flowID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.open[id]
	return ok
}

// entry returns the open record for flow id, or nil once it retired.
func (r *flowRegistry) entry(id flowID) *flowEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.open[id]
}

// retire forgets a flow as the current owner of its address — but only
// while it still IS the current owner, so a replacement mapping is never
// deleted by an older flow — and removes its open record.
func (r *flowRegistry) retire(id flowID) *flowEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.open[id]
	if e == nil {
		return nil
	}
	if r.current[e.key] == id {
		delete(r.current, e.key)
	}
	delete(r.open, id)
	return e
}

// openFlows snapshots the still-open flows; shutdown's bounded sweep
// closes every one of them itself rather than waiting for a peer to.
func (r *flowRegistry) openFlows() []*flowEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*flowEntry, 0, len(r.open))
	for _, e := range r.open {
		out = append(out, e)
	}
	return out
}

// flowReaper runs the single ordered teardown every stream connection goes
// through:
//
//  1. block selection — retire the flow's bindings from Location, so no
//     new admission (HasSource) or delivery (ByToken) can pick the dying
//     transport;
//  2. converge what those bindings owned — their SUBSCRIBE records and the
//     unestablished (early) dialogs whose route was the flow;
//  3. release the connection — close the socket, give back its connection
//     slot and leave the metrics and management views.
//
// A retirement keeps the per-item result of each step, so a repeated close
// callback, a partial failure or an expiry scan interleaving with it only
// ever redoes an item that was not confirmed: confirmed bindings are gone
// from Location, ended subscriptions miss the token index, an ended dialog
// misses the table, and the slot is released once. A binding a newer flow
// installed for the same AoR — even from the same source address — is
// never touched, because phase 1 matches the flow ID.
type flowReaper struct {
	s *Server

	mu     sync.Mutex
	active map[flowID]*flowRetirement
}

func newFlowReaper(s *Server) *flowReaper {
	return &flowReaper{s: s, active: map[flowID]*flowRetirement{}}
}

// flowRetirement is the per-item teardown state of one flow. Every field
// is guarded by mu. A nil flow id (0) is never retired.
type flowRetirement struct {
	mu sync.Mutex

	// bindingsDone: phase 1 ran. bindings holds the bindings it confirmed
	// removed, by token.
	bindingsDone bool
	bindings     map[string]Binding
	// subsPending lists the tokens whose SUBSCRIBE records still need
	// converging. It drains as phase 2 confirms them; the Location remove
	// hook usually drains them first, in which case the explicit sweep is
	// a confirmed no-op.
	subsPending map[string]struct{}
	// dialogsDone: the flow's early-dialog convergence ran.
	dialogsDone bool
	// released: phase 3 (socket close's bookkeeping) ran.
	released bool
}

// state returns the flow's retirement record, creating it on first use.
func (rp *flowReaper) state(id flowID) *flowRetirement {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	st := rp.active[id]
	if st == nil {
		st = &flowRetirement{bindings: map[string]Binding{}, subsPending: map[string]struct{}{}}
		rp.active[id] = st
	}
	return st
}

// converge runs phases 1 and 2 for the flow. It is idempotent: each phase
// skips what an earlier call already confirmed.
func (rp *flowReaper) converge(id flowID) {
	if id == 0 {
		return
	}
	st := rp.state(id)
	// Phase 1: stop new requests selecting this flow, and learn which
	// bindings it owned. RetireFlow removes by flow ID only, so a binding
	// a newer flow put at the same address stays, and a binding the expiry
	// scan or an un-REGISTER already removed is simply absent.
	st.mu.Lock()
	if !st.bindingsDone {
		rp.s.flows.retire(id)
		for _, b := range rp.s.loc.RetireFlow(id) {
			st.bindings[b.Token] = b
			st.subsPending[b.Token] = struct{}{}
		}
		st.bindingsDone = true
		if len(st.bindings) > 0 {
			rp.s.metrics.SetRegistrations(rp.s.loc.Count())
		}
	}
	pending := make([]string, 0, len(st.subsPending))
	for tok := range st.subsPending {
		pending = append(pending, tok)
	}
	dialogsDue := !st.dialogsDone
	st.mu.Unlock()

	// Phase 2a: the SUBSCRIBE records charged to the retired bindings. The
	// Location remove hook normally ends them first; this is the explicit
	// confirmation and only has work left when it did not.
	if len(pending) > 0 {
		rp.s.subs.dropTokens(pending)
		st.mu.Lock()
		st.subsPending = map[string]struct{}{}
		st.mu.Unlock()
	}
	// Phase 2b: the unestablished dialogs routed over the flow. A dialog
	// that never connected can never deliver, so end it (its media and
	// session slot are released with it) and quiet its in-flight INVITE; a
	// confirmed dialog is left to BYE and the media watchdog, as on any
	// connection loss.
	if dialogsDue {
		for _, a := range rp.s.dialogs.retireFlow(id) {
			if a.sent {
				go rp.s.sendCancel(a)
			} else {
				a.cancel()
			}
		}
		st.mu.Lock()
		st.dialogsDone = true
		st.mu.Unlock()
	}
}

// finish records phase 3 for the flow and runs release exactly once. It is
// called by streamConn.Close, whose closeOnce already serialises callers;
// the released flag is the reaper's own confirmation.
func (rp *flowReaper) finish(c *streamConn) {
	id := c.flowID
	if id == 0 {
		return
	}
	s := c.l.s
	st := rp.state(id)
	st.mu.Lock()
	first := !st.released
	st.released = true
	n := len(st.bindings)
	st.mu.Unlock()
	if first {
		s.streams.release(c.ap.Addr(), c.carrier)
		s.metrics.StreamConnClosed(c.l.transport)
		if n > 0 {
			s.log.Debug("stream connection closed; dropped its registration bindings",
				"transport", c.l.transport, "public_remote", c.remote, "flow", uint64(id), "count", n)
		}
	}
	rp.mu.Lock()
	if st.bindingsDone && st.dialogsDone && st.released && len(st.subsPending) == 0 {
		delete(rp.active, id)
	}
	rp.mu.Unlock()
}

// closeOpenFlows runs the full ordered teardown of every flow that is
// still open at process shutdown: bounded work (map operations and local
// socket closes, no network waits), so shutdown cannot hang on a peer that
// is already gone. Listeners have stopped accepting by the time it runs.
func (rp *flowReaper) closeOpenFlows() {
	for _, e := range rp.s.flows.openFlows() {
		if e.conn != nil {
			_ = e.conn.Close()
			continue
		}
		// Defensive only — every issued flow records its connection. Run
		// the phases directly and balance the slot the admission took.
		rp.converge(e.id)
		rp.s.flows.retire(e.id)
		rp.s.streams.release(e.key.ap.Addr(), e.carrier)
		rp.s.metrics.StreamConnClosed(e.key.transport)
	}
}

// activeRetirements is how many flows have teardown state unfinished
// (tests and the shutdown residual report).
func (rp *flowReaper) activeRetirements() int {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return len(rp.active)
}

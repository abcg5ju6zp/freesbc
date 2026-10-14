package edge

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// The flow registry hands each connection its own generation. A newer
// connection taking the same (transport, address) replaces the lookup but
// cannot make the old generation retire anything it does not own.
func TestFlowRegistryGenerations(t *testing.T) {
	r := newFlowRegistry()
	c1, c2 := &streamConn{}, &streamConn{}
	ap := netip.MustParseAddrPort("203.0.113.9:41000")
	id1 := r.issue("tcp", ap, c1, false)
	if id1 == 0 || !r.alive(id1) {
		t.Fatalf("flow %d not alive after issue", id1)
	}
	if got := r.currentID("tcp", ap); got != id1 {
		t.Fatalf("currentID = %d, want %d", got, id1)
	}
	// A reconnect reusing the exact address gets a new generation.
	id2 := r.issue("tcp", ap, c2, false)
	if id2 == id1 {
		t.Fatal("the replacement connection reused the flow ID")
	}
	if got := r.currentID("tcp", ap); got != id2 {
		t.Fatalf("currentID = %d, want %d", got, id2)
	}
	// The old flow retiring must not unmap the new flow's address.
	if e := r.retire(id1); e == nil {
		t.Fatal("retire found no record for the old flow")
	}
	if r.alive(id1) {
		t.Error("retired flow still alive")
	}
	if !r.alive(id2) {
		t.Error("the new flow was retired by the old generation")
	}
	if got := r.currentID("tcp", ap); got != id2 {
		t.Fatalf("currentID after old retire = %d, want %d", got, id2)
	}
	// Retiring twice is a no-op.
	if e := r.retire(id1); e != nil {
		t.Error("the old flow retired twice")
	}
}

// contactRURI builds the Request-URI the switch uses to reach a registered
// binding.
func contactRURI(h *harness, token string) sip.Uri {
	ruri := sip.Uri{User: "1001", Host: "127.0.0.1", Port: portOf(h.privateSIP), UriParams: sip.NewParams()}
	ruri.UriParams.Add(contactTokenParam, token)
	return ruri
}

// Phase ordering of a flow retirement: the bindings leave the selection
// plane first, then their subscriptions converge; the connection slot
// survives until finish. Repeating the earlier phases changes nothing.
func TestFlowReaperPhasesAreOrderedAndResumable(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
	phone := newStreamClient(t, "tcp")
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	b, ok := h.binding("1001@example.com")
	if !ok || b.FlowID == 0 {
		t.Fatalf("binding %+v ok=%v: no flow stamped", b, ok)
	}
	id := b.FlowID
	if h.srv.streams.open() != 1 {
		t.Fatalf("connections = %d, want 1", h.srv.streams.open())
	}

	// Run phases 1 and 2 directly, the way Close does before the socket
	// goes.
	h.srv.reaper.converge(id)

	// Phase 1: selection is blocked and the binding is gone everywhere.
	if _, ok := h.srv.loc.ByToken(b.Token); ok {
		t.Error("the retired binding still resolves after phase 1")
	}
	if h.srv.loc.HasSource("tcp", b.Source) {
		t.Error("the retired source is still admitted after phase 1")
	}
	if h.srv.flows.alive(id) {
		t.Error("the flow is still alive after phase 1")
	}
	// Phase 3 has not run: the connection slot and gauge still hold.
	if h.srv.streams.open() != 1 {
		t.Errorf("slot released before finish: %d", h.srv.streams.open())
	}
	// A repeated converge is a confirmed no-op.
	h.srv.reaper.converge(id)
	if h.srv.loc.Count() != 0 || h.srv.streams.open() != 1 {
		t.Errorf("repeated converge changed state: bindings=%d conns=%d", h.srv.loc.Count(), h.srv.streams.open())
	}

	// Phase 3: closing the connection releases its slot and forgets the
	// retirement.
	phone.cancel()
	waitFor(t, 5*time.Second, "the connection slot to be released", func() bool { return h.srv.streams.open() == 0 })
	if n := h.srv.reaper.activeRetirements(); n != 0 {
		t.Errorf("finished retirement still tracked: %d", n)
	}
}

// The new flow's same-AoR binding must survive the old connection's close,
// even when both sat on the identical transport and source address — the
// race that address-keyed cleanup could not survive.
func TestFlowReaperOldGenerationSparesSameAddressBinding(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
	phone := newStreamClient(t, "tcp")
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	first, ok := h.binding("1001@example.com")
	if !ok {
		t.Fatal("no binding after REGISTER")
	}
	oldConn := h.srv.flows.entry(first.FlowID)
	if oldConn == nil || oldConn.conn == nil {
		t.Fatal("the registered flow has no connection record")
	}

	// Simulate the reconnect-from-the-same-address race: a new generation
	// at the exact key with a real (pipe-backed) connection and slot, and
	// a replacement binding on it.
	pipeA, pipeB := net.Pipe()
	defer pipeB.Close()
	if _, ok := h.srv.streams.acquire(first.Source.Addr(), false, h.srv.streamLim); !ok {
		t.Fatal("could not acquire a slot for the replacement flow")
	}
	newConn := &streamConn{Conn: pipeA, l: oldConn.conn.l, ap: first.Source, remote: "replacement",
		lim: h.srv.streamLim}
	newID := h.srv.flows.issue("tcp", first.Source, newConn, false)
	if newID == first.FlowID {
		t.Fatal("replacement flow got the same ID")
	}
	repl := first
	repl.FlowID = newID
	stored, err := h.srv.loc.Commit(repl, first.gen)
	if err != nil {
		t.Fatalf("replacement commit: %v", err)
	}
	if stored.FlowID != newID {
		t.Fatalf("replacement flow = %d, want %d", stored.FlowID, newID)
	}

	// The old connection closes (its read loop ending runs the full
	// teardown for its own generation only).
	_ = oldConn.conn.Close()
	waitFor(t, 5*time.Second, "the old flow's retirement to finish",
		func() bool { return h.srv.reaper.activeRetirements() == 0 })
	got, live := h.srv.loc.ByToken(first.Token)
	if !live {
		t.Fatal("the new generation's binding was deleted by the old flow")
	}
	if got.FlowID != newID {
		t.Errorf("surviving binding flow = %d, want %d", got.FlowID, newID)
	}

	// Converge the replacement flow too, so the harness stops with no
	// residue from this test.
	_ = newConn.Close()
}

// A switch->client INVITE that never establishes is owned by the binding's
// flow: when that connection closes mid-ring the attempt is converged, the
// switch gets its failure response and the dialog (and its media) is gone
// without waiting for the INVITE backstop.
func TestFlowCloseConvergesUnestablishedDialog(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
	phone := newStreamClient(t, "tcp")
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	b, ok := h.binding("1001@example.com")
	if !ok {
		t.Fatal("no binding")
	}
	ruri := contactRURI(h, b.Token)

	finals := make(chan *sip.Response, 1)
	go func() {
		finals <- h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	}()
	// The client must actually be ringing on its connection first.
	select {
	case got := <-phone.inbound:
		if got.Method != sip.INVITE {
			t.Fatalf("client got %s, want INVITE", got.Method)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client never saw the INVITE")
	}

	// Connection gone while ringing: the unestablished dialog converges
	// promptly, not on the 5-minute backstop.
	phone.cancel()
	select {
	case res := <-finals:
		if res.StatusCode == 200 {
			t.Error("the switch got a 200 after the client's connection closed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the switch was never told the call could not connect")
	}
	// The early dialog, its session slot and any media allocated for the
	// ringing attempt are released with the flow, not on the 5-minute
	// INVITE backstop.
	waitForRelease(t, h)
}

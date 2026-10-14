package edge

import (
	"testing"
	"time"
)

// Process shutdown completes a BOUNDED cleanup and says what is left:
// stream flows are converged locally (bindings, subscriptions, early
// dialogs, connection slots), while UDP registrations own no connection to
// close and are expected to age out on their registrar-granted expiry.
func TestShutdownConvergesStreamFlowsAndReportsResidual(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true, tls: true})
	// A stream registration: its whole cleanup is local.
	tcpPhone := newStreamClient(t, "tcp")
	if res := tcpPhone.do(t, tcpPhone.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("tcp REGISTER: %d", res.StatusCode)
	}
	// A UDP registration on the same proxy: left to its expiry, reported,
	// not force-removed.
	udpPhone := newUDPClient(t)
	if res := udpPhone.do(t, udpPhone.buildRegister("1002", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("udp REGISTER: %d", res.StatusCode)
	}
	if c := h.srv.loc.Count(); c != 2 {
		t.Fatalf("bindings = %d, want 2", c)
	}
	if h.srv.streams.open() != 1 {
		t.Fatalf("stream connections = %d, want 1", h.srv.streams.open())
	}

	h.stop()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}

	r := h.srv.shutdownResidual()
	if r.streamBindings != 0 {
		t.Errorf("stream bindings left after shutdown: %d", r.streamBindings)
	}
	if r.udpBindings != 1 {
		t.Errorf("UDP bindings left: %d, want 1 (they expire at the registrar)", r.udpBindings)
	}
	if r.subscriptions != 0 || r.dialogs != 0 {
		t.Errorf("subscriptions=%d dialogs=%d left after shutdown", r.subscriptions, r.dialogs)
	}
	if r.streamConns != 0 || r.retirements != 0 {
		t.Errorf("stream connections=%d unfinished cleanups=%d after shutdown",
			r.streamConns, r.retirements)
	}
}

// With only UDP state present, the shutdown report classifies it as the
// expected residue and every local resource as clean.
func TestShutdownResidualClassifiesUDPOnly(t *testing.T) {
	h := startHarness(t, false)
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	phone := newUDPClient(t)
	if res := phone.do(t, phone.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("REGISTER: %d", res.StatusCode)
	}
	h.stop()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
	r := h.srv.shutdownResidual()
	if r.udpBindings != 1 || r.streamBindings != 0 || r.streamConns != 0 ||
		r.subscriptions != 0 || r.dialogs != 0 || r.retirements != 0 {
		t.Errorf("residual = %+v, want one UDP binding and nothing else", r)
	}
}

package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// TestNon2xxAckIsAbsorbedWithoutAckMissed: the switch challenges the INVITE
// with 407 and the caller's hop-by-hop ACK reuses the INVITE branch, so
// sipgo hands it to the server transaction. Nothing may park on it: no
// "ACK missed" Warn once the transaction ends (Timer I, 5 s on UDP), and the
// ACK is not relayed (the edge's own client transaction ACKs the switch).
func TestNon2xxAckIsAbsorbedWithoutAckMissed(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	phone := newUDPClient(t)
	h.fs.setInviteHook(func(req *sip.Request, tx sip.ServerTransaction) bool {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 407, "Proxy Authentication Required", nil))
		return true
	})

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 407 {
		t.Fatalf("INVITE: got %d, want 407", res.StatusCode)
	}
	callID := invite.CallID().Value()

	deadline := time.Now().Add(3 * time.Second)
	absorbed := false
	for !absorbed && time.Now().Before(deadline) {
		for _, r := range rec.snapshot() {
			if r.msg == "ACK to a non-2xx final absorbed" && r.attrs["sip_call_id"] == callID {
				absorbed = true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !absorbed {
		t.Error("the caller's non-2xx ACK never reached the drainer")
	}

	// Past Timer I, where sipgo would have logged "ACK missed" on the edge.
	time.Sleep(6 * time.Second)
	for _, r := range rec.snapshot() {
		if r.msg == "ACK missed" {
			t.Errorf("sipgo logged %q at %v", r.msg, r.level)
		}
	}
	// The edge's own hop ACK for the 407 is the transaction layer's and never
	// reaches the switch's ACK handler; a relayed one would.
	if acks := h.fs.received(sip.ACK); len(acks) != 0 {
		t.Errorf("switch saw %d relayed ACKs, want none", len(acks))
	}
}

// TestAckReusingInviteBranchTo2xxIsForwarded: a client that reuses the
// INVITE branch for the ACK of a 2xx matches the server transaction, so
// sipgo never calls the ACK handler. The edge must still forward it.
func TestAckReusingInviteBranchTo2xxIsForwarded(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)

	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(30099))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	branch, _ := invite.Via().Params.Get("branch")
	if branch == "" {
		t.Fatal("INVITE carries no branch")
	}
	sendAckBranch(t, phone, invite, res, h.publicUDP, branch)
	if acks := h.fs.waitFor(sip.ACK, 1, 3*time.Second); len(acks) != 1 {
		t.Fatalf("switch saw %d ACKs, want 1", len(acks))
	}

	bye := buildBye(phone, invite, res)
	if r := phone.do(t, bye, h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: got %d", r.StatusCode)
	}
	waitForRelease(t, h)
}

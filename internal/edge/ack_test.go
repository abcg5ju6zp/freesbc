package edge

import (
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// A 2xx whose ACK never arrives (issue #163): reason ack_timeout, the
// freesbc_edge_ack_missed_total counter and terminated_by in the "call
// ended" line.
//
// Timing-based over real UDP loopback: re-run once before treating a flake
// as failure.

// ackMissed is the ACK-miss counter of every plane.
func ackMissed(h *harness) map[string]uint64 { return h.srv.metrics.Snapshot().AckMissed }

func assertAckMissed(t *testing.T, h *harness, public, private uint64) {
	t.Helper()
	got := ackMissed(h)
	if got["public"] != public || got["private"] != private || len(got) != 2 {
		t.Errorf("ack_missed = %v, want public=%d private=%d", got, public, private)
	}
}

func assertTerminatedBy(t *testing.T, rec *logRecorder, callID string, want terminator) {
	t.Helper()
	if got := callEndedLine(t, rec, callID).attrs["terminated_by"]; got != string(want) {
		t.Errorf("terminated_by = %q, want %q", got, want)
	}
}

// The callee's BYE arrives while the phone's ACK is still owed: the callee
// gave up on the ACK.
func TestAckMissedCalleeByeBeforeAck(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(auditUDPPort(auditUDP(t))))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	tag := <-tags
	waitForDialog(t, h, fsip.CallID(invite))
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	if r := h.fs.inDialog(t, sip.BYE, up, tag); r.StatusCode != 200 {
		t.Fatalf("BYE from the switch: %d", r.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endAckTimeout, false, true)
	assertTerminatedBy(t, rec, fsip.CallID(invite), byCallee)
	assertAckMissed(t, h, 1, 0)
}

// Nobody hangs up: FreeSBC's own backstop ends the call and BYEs both ends.
func TestAckMissedProxyTimer(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	h.srv.ackWait.Store(int64(600 * time.Millisecond))
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(auditUDPPort(auditUDP(t))))
	if res := phone.do(t, invite, h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	waitReceived(t, h.fs, sip.BYE, 1)
	if waitInbound(phone, sip.BYE, 3*time.Second) == nil {
		t.Error("the phone was never sent a BYE")
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endAckTimeout, false, true)
	assertTerminatedBy(t, rec, fsip.CallID(invite), byProxy)
	time.Sleep(200 * time.Millisecond)
	assertAckMissed(t, h, 1, 0)
	waitForRelease(t, h)
}

// A call the switch placed whose ACK never comes: the private plane missed it.
func TestAckMissedPrivatePlane(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.srv.ackWait.Store(int64(600 * time.Millisecond))
	phone := newUDPClient(t)
	ruri := auditRegisterPhone(t, h, phone, "1001")
	rtp := auditUDP(t)
	auditPhoneAnswers(phone, auditUDPPort(rtp), nil)
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(res), endAckTimeout, false, false)
	assertTerminatedBy(t, rec, fsip.CallID(res), byProxy)
	assertAckMissed(t, h, 0, 1)
}

// An ACKed call whose callee then hangs up is an ordinary bye_callee.
func TestAckReceivedCalleeByeIsByeCallee(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	tags := make(chan string, 1)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, tags, nil))
	h.srv.ackWait.Store(int64(600 * time.Millisecond))
	phone := newUDPClient(t)
	invite, _, _ := auditPhoneCall(t, h, phone)
	tag := <-tags
	waitForDialog(t, h, fsip.CallID(invite))
	up := waitReceived(t, h.fs, sip.INVITE, 1)[0]
	time.Sleep(900 * time.Millisecond) // past the (shortened) backstop
	if r := h.fs.inDialog(t, sip.BYE, up, tag); r.StatusCode != 200 {
		t.Fatalf("BYE from the switch: %d", r.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endByeCallee, false, true)
	assertTerminatedBy(t, rec, fsip.CallID(invite), byCallee)
	assertAckMissed(t, h, 0, 0)
}

// A caller that hangs up before ACKing is still bye_caller.
func TestAckMissingCallerByeIsByeCaller(t *testing.T) {
	h, rec := startHarnessRecorded(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(auditUDPPort(auditUDP(t))))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: %d", res.StatusCode)
	}
	waitForDialog(t, h, fsip.CallID(invite))
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Fatalf("BYE: %d", r.StatusCode)
	}
	assertEnded(t, h, rec, fsip.CallID(invite), endByeCaller, false, true)
	assertTerminatedBy(t, rec, fsip.CallID(invite), byCaller)
	assertAckMissed(t, h, 0, 0)
}

// An offerless call whose ACK (and so its answer) never comes stays
// answer_timeout, and the missing ACK is counted once.
func TestAckMissedOfferlessStaysAnswerTimeout(t *testing.T) {
	o := startOfferlessToSwitch(t, func(h *harness) func(*sip.Request, sip.ServerTransaction) bool {
		return offerIn200(h.fs, "uas-ol-ackmiss", sdpWith(h.fs.rtpPort, "sendrecv"))
	})
	o.h.srv.ackWait.Store(int64(600 * time.Millisecond))
	o.call.final200(t)
	waitReceived(t, o.h.fs, sip.BYE, 1)
	waitForRelease(t, o.h)
	time.Sleep(200 * time.Millisecond)
	snap := o.h.srv.metrics.Snapshot()
	if snap.CallsEnded[endAnswerTimeout.String()] != 1 || snap.CallsEnded[endAckTimeout.String()] != 0 {
		t.Errorf("calls_ended = %v, want one answer_timeout", snap.CallsEnded)
	}
	if snap.AckMissed["public"] != 1 || snap.AckMissed["private"] != 0 {
		t.Errorf("ack_missed = %v, want public=1", snap.AckMissed)
	}
}

func TestAckMissedStartsAtZero(t *testing.T) {
	snap := NewMetrics().Snapshot()
	if n, ok := snap.AckMissed["public"]; !ok || n != 0 {
		t.Errorf("ack_missed{public} = %d, present %v", n, ok)
	}
	if n, ok := snap.AckMissed["private"]; !ok || n != 0 {
		t.Errorf("ack_missed{private} = %d, present %v", n, ok)
	}
	if len(snap.AckMissed) != 2 {
		t.Errorf("ack_missed has %d planes, want 2", len(snap.AckMissed))
	}
}

// The WARN is first-then-once-per-minute per plane, folding the rest into
// a suppressed count; the recent count ages out of its window.
func TestAckMissTracker(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	tr := &ackMissTracker{now: func() time.Time { return now }}
	if n, ok := tr.record(planePublic, "sip:a"); !ok || n != 0 {
		t.Fatalf("first miss: suppressed=%d warn=%v, want 0 true", n, ok)
	}
	for i := 0; i < 2; i++ {
		now = now.Add(10 * time.Second)
		if _, ok := tr.record(planePublic, "sip:b"); ok {
			t.Fatal("a miss within the minute earned a WARN")
		}
	}
	// The other plane has its own limiter.
	if _, ok := tr.record(planePrivate, "sip:p"); !ok {
		t.Error("first private miss earned no WARN")
	}
	now = now.Add(ackMissWarnEvery)
	if n, ok := tr.record(planePublic, "sip:c"); !ok || n != 2 {
		t.Fatalf("after the interval: suppressed=%d warn=%v, want 2 true", n, ok)
	}
	got := tr.recent(10 * time.Minute)
	if got[0].Plane != "public" || got[0].Recent != 4 || got[0].Endpoint != "sip:c" {
		t.Errorf("public recent = %+v, want 4 misses ending at sip:c", got[0])
	}
	if got[1].Plane != "private" || got[1].Recent != 1 {
		t.Errorf("private recent = %+v", got[1])
	}
	now = now.Add(11 * time.Minute)
	if got := tr.recent(10 * time.Minute); got[0].Recent != 0 || got[1].Recent != 0 {
		t.Errorf("misses did not age out: %+v", got)
	}
}

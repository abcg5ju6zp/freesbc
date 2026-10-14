package edge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// This file tests the carrier address-generation contract end to end:
// a DNS handoff sends new requests to the new gateway while calls and
// registrations stay on the carrier, transport and target address they
// began on, and the old generation's connections close and source
// qualification is revoked only once nothing is pinned to it any more.

// forceCarrierRefresh makes the next refresh re-resolve immediately.
func forceCarrierRefresh(t *testing.T, srv *Server) {
	t.Helper()
	srv.carriers.mu.Lock()
	for _, e := range srv.carriers.entries {
		e.expiry = time.Time{}
	}
	srv.carriers.mu.Unlock()
	srv.carriers.refresh(context.Background())
}

// drainInbound empties a test client's inbound request queue.
func drainInbound(c *client) {
	for {
		select {
		case <-c.inbound:
		default:
			return
		}
	}
}

// genUDPRig is a DNS-name UDP carrier ("alpha") resolved through SRV,
// with two fake gateways the test switches between.
type genUDPRig struct {
	*carrierRig
	stub    *dnsStub
	gw1     *fakeSwitch
	gw2     *fakeSwitch
	p1, p2  int
	dnsName string
}

func startGenUDPRig(t *testing.T) *genUDPRig {
	t.Helper()
	p1, p2 := freePort(t), freePort(t)
	gw1 := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", p1))
	gw2 := startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", p2))
	for _, g := range []*fakeSwitch{gw1, gw2} {
		g.mu.Lock()
		g.challenge = false
		g.mu.Unlock()
		answerWithTag(g)
	}
	stub := &dnsStub{
		srv: map[string][]*net.SRV{
			"sip.carrier.example": {{Target: "gw1.carrier.example.", Port: uint16(p1), Priority: 10, Weight: 1}},
		},
		ips: map[string][]string{
			"gw1.carrier.example": {"127.0.0.1"},
			"gw2.carrier.example": {"127.0.0.1"},
		},
	}
	rig := startCarrierRig(t, `alpha: {host: sip.carrier.example}`, "", func(s *Server) {
		s.carriers.lookupSRV = stub.lookupSRV
		s.carriers.lookupIP = stub.lookupIP
	})
	rig.upstreams["gw1"] = gw1
	rig.upstreams["gw2"] = gw2
	waitFor(t, 5*time.Second, "the first gateway to resolve", func() bool {
		g, ok := rig.srv.carriers.currentGen("alpha")
		return ok && len(g.addrs) == 1 && int(g.addrs[0].Port()) == p1
	})
	return &genUDPRig{carrierRig: rig, stub: stub, gw1: gw1, gw2: gw2, p1: p1, p2: p2, dnsName: "sip.carrier.example"}
}

func (r *genUDPRig) switchTo(t *testing.T, gateway int) {
	t.Helper()
	target := "gw1.carrier.example."
	port := r.p1
	if gateway == 2 {
		target, port = "gw2.carrier.example.", r.p2
	}
	r.stub.mu.Lock()
	r.stub.srv["sip.carrier.example"] = []*net.SRV{{Target: target, Port: uint16(port), Priority: 10, Weight: 1}}
	r.stub.mu.Unlock()
	forceCarrierRefresh(t, r.srv)
	want := fmt.Sprintf("127.0.0.1:%d", port)
	waitFor(t, 5*time.Second, "the new gateway to resolve", func() bool {
		g, ok := r.srv.carriers.currentGen("alpha")
		return ok && g.addrs[0].String() == want
	})
}

// A call established on the old gateway stays on it through a DNS handoff:
// its in-dialog BYE still reaches gateway 1, while a brand-new OPTIONS
// goes to gateway 2.
func TestCarrierGenerationPinsUDPCall(t *testing.T) {
	r := startGenUDPRig(t)
	ruri := sip.Uri{User: "+442071234567", Host: r.dnsName}

	res := r.fs.call(t, ruri, r.privateSIP, phoneOfferSDP(r.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("INVITE: got %d, want 200", res.StatusCode)
	}
	invs := r.gw1.waitFor(sip.INVITE, 1, 3*time.Second)
	if len(invs) != 1 {
		t.Fatalf("gw1 saw %d INVITEs, want 1", len(invs))
	}
	r.fs.sendAckTo2xx(t, res)
	r.gw1.waitFor(sip.ACK, 1, 3*time.Second)

	// Hand over while the call is up: generation 2 becomes current,
	// generation 1 stays retained for this dialog.
	r.switchTo(t, 2)
	info := r.srv.Carriers()[0]
	if info.GenerationID != 2 || len(info.Generations) < 2 {
		t.Fatalf("carrier info after handoff = %+v", info)
	}
	var retained *CarrierGenerationInfo
	for i := range info.Generations {
		if info.Generations[i].State == "retained" {
			retained = &info.Generations[i]
		}
	}
	if retained == nil || retained.Refs.Dialogs != 1 || retained.ID != 1 {
		t.Fatalf("generation 1 not retained by the dialog: %+v", info.Generations)
	}

	// The in-dialog BYE still leaves for the old gateway address.
	if bye := r.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE: got %d, want 200", bye.StatusCode)
	}
	r.gw1.waitFor(sip.BYE, 1, 3*time.Second)
	if n := len(r.gw2.received(sip.BYE)); n != 0 {
		t.Errorf("gw2 saw %d BYEs, the pinned dialog migrated", n)
	}
	waitForRelease(t, r.harness)

	// Generation 1 drained with the dialog: no retained generation left.
	waitFor(t, 3*time.Second, "generation 1 to retire", func() bool {
		for _, g := range r.srv.Carriers()[0].Generations {
			if g.State == "retained" {
				return false
			}
		}
		return true
	})

	// A new stateless request (OPTIONS) takes the current generation only.
	res2 := switchRequest(t, r.fs, sip.OPTIONS, sip.Uri{Host: r.dnsName}, r.privateSIP)
	if res2.StatusCode != 200 {
		t.Fatalf("OPTIONS after handoff: %d, want 200", res2.StatusCode)
	}
	r.gw2.waitFor(sip.OPTIONS, 1, 3*time.Second)
	if n := len(r.gw1.received(sip.OPTIONS)); n != 0 {
		t.Errorf("gw1 saw %d OPTIONS after it retired", n)
	}
}

// A carrier REGISTER and every refresh stay on the gateway the binding
// was created on; a new registration and a keepalive take the current
// gateway, and the un-REGISTER goes back to the binding's gateway.
func TestCarrierGenerationPinsRegistration(t *testing.T) {
	r := startGenUDPRig(t)
	ruri := sip.Uri{Host: r.dnsName}
	orig := sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(r.fs.addr), UriParams: sip.NewParams()}
	orig.UriParams.Add("transport", "udp")
	node := r.fs.addr

	send := func(cseq uint32, expires int, user string) *sip.Response {
		contact := orig
		if user != "" {
			contact.User = user
		}
		req := carrierRegister(r.fs, r.privateSIP, ruri, contact, expires, "gen-reg", cseq, "")
		return sendFromSwitch(t, r.fs, req)
	}

	if res := send(1, 3600, ""); res.StatusCode != 200 {
		t.Fatalf("first REGISTER: %d, want 200", res.StatusCode)
	}
	r.gw1.waitFor(sip.REGISTER, 1, 3*time.Second)
	token := carrierToken(node, orig.String())
	b, found := r.srv.carrierRegs.lookup(token)
	if !found || b.gen.id != 1 {
		t.Fatalf("binding = %+v found=%v, want gen 1", b, found)
	}

	// Handoff: the refresh goes to the old gateway.
	r.switchTo(t, 2)
	if res := send(2, 3600, ""); res.StatusCode != 200 {
		t.Fatalf("refresh REGISTER: %d, want 200", res.StatusCode)
	}
	if n := len(r.gw1.received(sip.REGISTER)); n != 2 {
		t.Errorf("gw1 saw %d REGISTERs, want 2 (the refresh stayed pinned)", n)
	}
	if n := len(r.gw2.received(sip.REGISTER)); n != 0 {
		t.Errorf("gw2 saw %d REGISTERs, a refresh migrated", n)
	}
	b, _ = r.srv.carrierRegs.lookup(token)
	if b.gen.id != 1 {
		t.Errorf("the binding moved to generation %d", b.gen.id)
	}

	// A brand-new registration (another Contact) takes the new gateway.
	if res := send(3, 3600, "gw-b"); res.StatusCode != 200 {
		t.Fatalf("new REGISTER: %d, want 200", res.StatusCode)
	}
	r.gw2.waitFor(sip.REGISTER, 1, 3*time.Second)

	// The old gateway keeps its source qualification for the
	// registration return path: an inbound call to the registered
	// Contact from gateway 1's address is admitted and delivered to the
	// switch's carrier port.
	phone := newUDPClient(t)
	invite := phone.buildInvite("+442071234567", "15551230000", r.dnsName, phoneOfferSDP(freePort(t)))
	invite.Recipient = sip.Uri{User: "gw", Host: "127.0.0.1", Port: portOf(r.publicUDP)}
	invite.Recipient.UriParams = sip.NewParams()
	invite.Recipient.UriParams.Add(contactTokenParam, token)
	res := phone.do(t, invite, r.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("carrier return call on the retained gateway: %d, want 200", res.StatusCode)
	}
	r.cs.waitFor(sip.INVITE, 1, 3*time.Second)
	sendAck(t, phone, invite, res, r.publicUDP)
	if bye := phone.do(t, buildBye(phone, invite, res), r.publicUDP); bye.StatusCode != 200 {
		t.Fatalf("carrier return BYE: %d, want 200", bye.StatusCode)
	}

	// Expires 0 goes back to the pinned gateway and releases its
	// generation.
	if res := send(4, 0, ""); res.StatusCode != 200 {
		t.Fatalf("un-REGISTER: %d, want 200", res.StatusCode)
	}
	if n := len(r.gw1.received(sip.REGISTER)); n != 3 {
		t.Errorf("gw1 saw %d REGISTERs, want 3 (un-REGISTER pinned)", n)
	}
	if _, found := r.srv.carrierRegs.lookup(token); found {
		t.Error("the binding survived Expires 0")
	}
}

// A call placed over a TCP connection to the old gateway keeps using that
// connection after a DNS handoff; new calls dial the new gateway, and the
// old connection is closed once the old call ends.
func TestCarrierGenerationPinsTCPConnection(t *testing.T) {
	gw1 := startStreamCarrier(t, "tcp", nil, insecureClient())
	gw2 := startStreamCarrier(t, "tcp", nil, insecureClient())

	pubUDP, priv, up, cp := freePort(t), freePort(t), freePort(t), freePort(t)
	mediaBase := nextMediaBase(t)
	stub := &dnsStub{
		srv: map[string][]*net.SRV{
			"sip.carrier.example": {{Target: "gw1.carrier.example.", Port: uint16(gw1.port), Priority: 10, Weight: 1}},
		},
		ips: map[string][]string{
			"gw1.carrier.example": {"127.0.0.1"},
			"gw2.carrier.example": {"127.0.0.1"},
		},
	}
	yaml := harnessYAML(t, []string{fmt.Sprintf("127.0.0.1:%d", up)}, pubUDP, 0, 0, mediaBase, "")
	yaml = strings.Replace(yaml, "edge:\n", fmt.Sprintf(
		"edge:\n  switch_carrier_port: %d\n  carriers:\n    alpha: {host: sip.carrier.example, transport: tcp}\n", cp), 1)
	h := newHarness(t, yaml, priv)
	h.upstream = fmt.Sprintf("127.0.0.1:%d", up)
	h.fs = startFakeSwitch(t, h.upstream)
	h.upstreams["carrier-port"] = startFakeSwitch(t, fmt.Sprintf("127.0.0.1:%d", cp))
	h.srv.carriers.lookupSRV, h.srv.carriers.lookupIP = stub.lookupSRV, stub.lookupIP
	h.run()
	waitFor(t, 5*time.Second, "gw1 to resolve", func() bool {
		g, ok := h.srv.carriers.currentGen("alpha")
		return ok && int(g.addrs[0].Port()) == gw1.port
	})

	ruri := sip.Uri{User: "+442071234567", Host: "sip.carrier.example"}
	res := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res.StatusCode != 200 {
		t.Fatalf("call 1: %d, want 200", res.StatusCode)
	}
	gw1.waitInbound(t, sip.INVITE)
	h.fs.sendAckTo2xx(t, res)
	gw1.waitInbound(t, sip.ACK)

	// Handoff to gw2.
	stub.mu.Lock()
	stub.srv["sip.carrier.example"] = []*net.SRV{{Target: "gw2.carrier.example.", Port: uint16(gw2.port), Priority: 10, Weight: 1}}
	stub.mu.Unlock()
	forceCarrierRefresh(t, h.srv)
	waitFor(t, 5*time.Second, "gw2 to resolve", func() bool {
		g, ok := h.srv.carriers.currentGen("alpha")
		return ok && int(g.addrs[0].Port()) == gw2.port
	})

	// A new call dials gw2, not gw1.
	res2 := h.fs.call(t, ruri, h.privateSIP, phoneOfferSDP(h.fs.rtpPort))
	if res2.StatusCode != 200 {
		t.Fatalf("call 2: %d, want 200", res2.StatusCode)
	}
	gw2.waitInbound(t, sip.INVITE)
	h.fs.sendAckTo2xx(t, res2)
	gw2.waitInbound(t, sip.ACK)
	if n := gw1.ln.accepted(); n != 1 {
		t.Errorf("gw1 accepted %d connections, want the one reused for the pinned call", n)
	}
	if n := gw2.ln.accepted(); n != 1 {
		t.Errorf("gw2 accepted %d connections, want the new call's dial", n)
	}

	// Ending the first call leaves over the pinned old connection; the
	// BYE still reaches gw1 on it, never gw2.
	drainInbound(gw2.client)
	if bye := h.fs.uacBye(t, res); bye.StatusCode != 200 {
		t.Fatalf("BYE call 1: %d, want 200", bye.StatusCode)
	}
	gw1.waitInbound(t, sip.BYE)
	select {
	case r := <-gw2.inbound:
		t.Errorf("gw2 saw call 1's %s, the pinned call migrated", r.Method)
	case <-time.After(300 * time.Millisecond):
	}
	if n := gw1.ln.accepted(); n != 1 {
		t.Errorf("the pinned connection was redialed: %d accepts", n)
	}

	// With no dialog left on generation 1 its connection is closed.
	waitFor(t, 5*time.Second, "the old generation's connection to close", func() bool {
		c, err := h.srv.srv.TransportLayer().GetConnection("tcp", fmt.Sprintf("127.0.0.1:%d", gw1.port))
		if err == nil && c != nil {
			_, _ = c.TryClose()
			return false
		}
		return true
	})

	// Call 2 is unaffected and ends over gw2.
	if bye := h.fs.uacBye(t, res2); bye.StatusCode != 200 {
		t.Fatalf("BYE call 2: %d, want 200", bye.StatusCode)
	}
	gw2.waitInbound(t, sip.BYE)
}

package edge

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/shield"
)

// A UDP-sourced admission ban silences the IP on UDP only: a TCP
// connection and its REGISTER from the same IP still work, because a UDP
// source can be forged and must not cut off a victim's stream clients.
// Timing-based over real loopback: re-run once before treating a flake as
// failure.
func TestAdmissionBanFromUDPLeavesStreamsAlone(t *testing.T) {
	h := startStreamHarness(t, streamOpts{tcp: true})
	setAdmissionBan(h, "2/5m")
	for i := 0; i < 3; i++ {
		scanOnce(t, h)
	}
	waitDrops(t, h, 3)
	sh := h.srv.currentShield()
	if !sh.BannedFrom(netip.MustParseAddrPort("127.0.0.1:5999"), "udp") {
		t.Fatal("UDP from the struck IP is not banned")
	}
	if sh.BannedFrom(netip.MustParseAddrPort("127.0.0.1:5999"), "tcp") || sh.BannedFrom(netip.MustParseAddrPort("127.0.0.1:5999"), "ws") || bannedLoopback(h) {
		t.Fatal("a UDP-sourced admission ban reached the stream transports")
	}
	page, _, _ := h.srv.Bans(10, 0)
	if len(page) != 1 || page[0].Kind != shield.BanKindUDPIP || page[0].Reason != shield.BanReasonAdmission {
		t.Errorf("bans = %+v", page)
	}

	// The same IP still opens a TCP connection and registers over it.
	conn, err := net.DialTimeout("tcp", h.publicTCP, 3*time.Second)
	if err != nil {
		t.Fatalf("tcp connect from the UDP-banned IP: %v", err)
	}
	conn.Close()
	h.fs.mu.Lock()
	h.fs.challenge = false
	h.fs.mu.Unlock()
	c := newTCPClient(t)
	if res := c.do(t, c.buildRegister("1001", "example.com", 600, ""), h.publicTCP); res.StatusCode != 200 {
		t.Fatalf("REGISTER over tcp from the UDP-banned IP: got %d, want 200", res.StatusCode)
	}
}

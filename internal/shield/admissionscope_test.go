package shield

import (
	"net/netip"
	"testing"
)

func admissionShield(t *testing.T, ban string) *Shield {
	t.Helper()
	s, store := strikeShield(t, "100/10m", nil)
	next := *store.Current()
	next.Shield.AdmissionBan = ban
	store.Replace(&next)
	return s
}

// UDP strikes ban the IP on UDP only; a stream stays unaffected.
func TestStrikeOnUDPBansUDPOnly(t *testing.T) {
	s := admissionShield(t, "2/10m")
	ip := netip.MustParseAddr("198.51.100.30")
	for i := 0; i < 2; i++ {
		s.StrikeOn(ip, StrikeAdmission, "udp")
	}
	if s.BannedFrom(netip.AddrPortFrom(ip, 5060), "udp") {
		t.Fatal("banned at the threshold")
	}
	if !s.StrikeOn(ip, StrikeAdmission, "udp") {
		t.Fatal("the strike over the threshold did not ban")
	}
	for _, port := range []uint16{5060, 9999} {
		if !s.BannedFrom(netip.AddrPortFrom(ip, port), "udp") {
			t.Errorf("udp:%d not banned", port)
		}
	}
	for _, tr := range []string{"tcp", "tls", "ws", "wss"} {
		if s.BannedFrom(netip.AddrPortFrom(ip, 5060), tr) {
			t.Errorf("%s banned by a UDP-sourced strike ban", tr)
		}
	}
	if s.Banned(ip) {
		t.Error("the all-transport table holds a UDP-scoped ban")
	}
	page, _ := s.Bans(10, 0)
	if len(page) != 1 || page[0].Kind != BanKindUDPIP || page[0].Reason != BanReasonAdmission {
		t.Errorf("bans = %+v", page)
	}
}

// Stream strikes ban the IP on every transport, and UDP and stream strikes
// are counted separately: neither adds up to the other's ban.
func TestStrikeOnStreamBansAllTransports(t *testing.T) {
	s := admissionShield(t, "3/10m")
	ip := netip.MustParseAddr("198.51.100.31")
	for i := 0; i < 3; i++ {
		s.StrikeOn(ip, StrikeAdmission, "udp") // 3 UDP strikes: at the threshold
	}
	for i := 0; i < 3; i++ {
		s.StrikeOn(ip, StrikeAdmission, "wss") // 3 stream strikes: at the threshold
	}
	if s.Banned(ip) || s.BannedFrom(netip.AddrPortFrom(ip, 1), "udp") {
		t.Fatal("UDP and stream strikes were added together")
	}
	if !s.StrikeOn(ip, StrikeAdmission, "wss") {
		t.Fatal("the 4th stream strike did not ban")
	}
	for _, tr := range []string{"udp", "tcp", "tls", "ws", "wss"} {
		if !s.BannedFrom(netip.AddrPortFrom(ip, 5060), tr) {
			t.Errorf("%s not banned by a stream-sourced ban", tr)
		}
	}
	top, _ := s.Offenders(10)
	got := map[string]int{}
	for _, o := range top {
		got[o.Reason] = o.Strikes
	}
	if got[StrikeAdmission] != 4 || got[StrikeAdmissionUDP] != 3 {
		t.Errorf("offender counts = %v, want admission 4, admission_udp 3", got)
	}
}

// A narrower (UDP-only) ban never replaces or shortens a wider one.
func TestNarrowBanKeepsWideBan(t *testing.T) {
	s := admissionShield(t, "1/10m")
	ip := netip.MustParseAddr("198.51.100.32")
	s.StrikeOn(ip, StrikeAdmission, "tcp")
	s.StrikeOn(ip, StrikeAdmission, "tcp") // all-transport ban
	s.StrikeOn(ip, StrikeAdmission, "udp")
	s.StrikeOn(ip, StrikeAdmission, "udp") // UDP-only ban too
	for _, tr := range []string{"udp", "tcp", "ws"} {
		if !s.BannedFrom(netip.AddrPortFrom(ip, 5060), tr) {
			t.Errorf("%s not banned: the wide ban was lost", tr)
		}
	}
	if !s.Banned(ip) {
		t.Fatal("the all-transport ban was replaced")
	}
}

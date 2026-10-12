package shield

import (
	"net/netip"
	"testing"
)

// A forged-source flood of admission strikes holds the offender table at
// its cap and the ban table under banCap. The ban table's own hard cap is
// covered by TestBanListCap (banlist_test.go) and the forged-UDP fill in
// audit_shield_test.go.
func TestAdmissionStrikeFloodBounded(t *testing.T) {
	s, store := strikeShield(t, "5/10m", nil)
	next := *store.Current()
	next.Shield.AdmissionBan = "1/10m"
	store.Replace(&next)
	s.offenders.max = 256
	for i := 0; i < 5000; i++ {
		ip := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		s.Strike(ip, StrikeAdmission)
		s.Strike(ip, StrikeAdmission) // over 1/10m: banned
	}
	if n := s.offenders.size(); n > 256 {
		t.Errorf("offender table holds %d, cap 256", n)
	}
	if n := s.bans.size(); n > banCap {
		t.Errorf("ban table holds %d, banCap %d", n, banCap)
	}
}

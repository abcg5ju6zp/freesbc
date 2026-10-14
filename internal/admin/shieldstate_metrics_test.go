package admin

import (
	"strings"
	"testing"
)

// The shield-state series render the enabled gauge, one-hot recovery
// result, save counters and restored counts; every label has a baseline.
func TestMetricsShieldState(t *testing.T) {
	deps := emptyDeps()
	deps.ShieldState = func() ShieldState {
		return ShieldState{
			Enabled: true, Phase: "restored", RecoveryResult: "stale_generation",
			SavesOK: 4, SavesFailed: 2,
			Restored: ShieldStateRestored{IPBans: 1, UDPIPBans: 2, UDPSocketBans: 3, Offenders: 4, Buckets: 5},
		}
	}
	body := string(authGET(t, newTestServer(t, deps), "/metrics"))
	for _, want := range []string{
		"freesbc_shield_state_enabled 1",
		`freesbc_shield_state_recovery_result{result="stale_generation"} 1`,
		`freesbc_shield_state_recovery_result{result="fatal"} 0`,
		`freesbc_shield_state_recovery_result{result="same_generation"} 0`,
		`freesbc_shield_state_recovery_result{result="empty"} 0`,
		`freesbc_shield_state_recovery_result{result="disabled"} 0`,
		`freesbc_shield_state_saves_total{result="ok"} 4`,
		`freesbc_shield_state_saves_total{result="failed"} 2`,
		`freesbc_shield_state_restored_entries{kind="ip_ban"} 1`,
		`freesbc_shield_state_restored_entries{kind="udp_ip_ban"} 2`,
		`freesbc_shield_state_restored_entries{kind="udp_socket_ban"} 3`,
		`freesbc_shield_state_restored_entries{kind="offender"} 4`,
		`freesbc_shield_state_restored_entries{kind="bucket"} 5`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q\n---\n%s", want, body)
		}
	}
}

// Without the closure the whole family is absent.
func TestMetricsShieldStateAbsent(t *testing.T) {
	body := string(authGET(t, newTestServer(t, emptyDeps()), "/metrics"))
	if strings.Contains(body, "freesbc_shield_state_") {
		t.Errorf("shield-state series must be absent without the closure:\n%s", body)
	}
}

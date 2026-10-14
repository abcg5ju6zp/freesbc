package app

import (
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/admin"
)

func TestHealthShieldStateConditions(t *testing.T) {
	h, clk := newTestHealth()
	base := clk.t

	// Disabled persistence (zero ShieldHealth) raises nothing.
	if conds := h.derive(healthInputs{}); len(conds) != 0 {
		t.Fatalf("disabled shield state raised %v", ids(conds))
	}

	enabled := func() ShieldHealth {
		return ShieldHealth{Enabled: true, Phase: "restored", RecoveryResult: "same_generation", Path: "/s/state"}
	}

	// A healthy same-generation restore with a good last save raises nothing.
	ok := enabled()
	ok.LastSaveAt = base.Add(-time.Second)
	if conds := h.derive(healthInputs{Shield: ok}); len(conds) != 0 {
		t.Fatalf("healthy restore raised %v", ids(conds))
	}

	// Fatal verification: critical, listener-closed wording.
	fatal := enabled()
	fatal.Phase = "fatal"
	fatal.RecoveryResult = "fatal"
	fatal.FatalError = "HMAC mismatch"
	conds := h.derive(healthInputs{Shield: fatal})
	c, found := find(t, conds, "shield_state_corrupt")
	if !found || c.Severity != admin.HealthCritical {
		t.Fatalf("fatal = %+v", conds)
	}

	// Stale generation: degraded, naming the short generation.
	stale := enabled()
	stale.RecoveryResult = "stale_generation"
	stale.StaleGenerations = []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	conds = h.derive(healthInputs{Shield: stale})
	if c, found := find(t, conds, "shield_state_stale_generation"); !found || c.Severity != admin.HealthDegraded {
		t.Fatalf("stale = %+v", conds)
	} else if !contains(c.Detail, "0123456789ab") {
		t.Errorf("detail %q lacks the short generation", c.Detail)
	}

	// Save failure newer than the last good save: degraded; a later good
	// save clears it.
	saveFail := enabled()
	saveFail.LastSaveErrorAt = base
	if conds := h.derive(healthInputs{Shield: saveFail}); len(conds) != 1 {
		t.Fatalf("save failure = %v", conds)
	} else if _, found := find(t, conds, "shield_state_save_failed"); !found || conds[0].Severity != admin.HealthDegraded {
		t.Fatalf("want one degraded save_failed, got %+v", conds)
	}
	saveFail.LastSaveAt = base.Add(time.Second)
	if conds := h.derive(healthInputs{Shield: saveFail}); len(conds) != 0 {
		t.Fatalf("a later successful save must clear the condition: %v", ids(conds))
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

package shield

import (
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

func genCfg(t *testing.T, yaml string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// The generation is deterministic and stable across equivalent spellings
// and restarts.
func TestGenerationStable(t *testing.T) {
	a := GenerationOf(genCfg(t, shieldCfg))
	b := GenerationOf(genCfg(t, shieldCfg))
	if a == "" || a != b {
		t.Fatalf("generation not stable: %q vs %q", a, b)
	}
	// Equivalent duration spellings normalize to the same generation.
	cfgM := shieldCfg + "  register_ban: 10/10m\n"
	cfgS := shieldCfg + "  register_ban: 10/600s\n"
	if g := GenerationOf(genCfg(t, cfgM)); g != GenerationOf(genCfg(t, cfgS)) {
		t.Fatalf("equivalent strike-window spellings differ in generation: %q vs %q", g.Short(), GenerationOf(genCfg(t, cfgS)).Short())
	}
	alt := strings.ReplaceAll(shieldCfg, "ban: 1h", "ban: 3600s")
	if g := GenerationOf(genCfg(t, alt)); g != a {
		t.Fatalf("equivalent ban spelling changed generation: %q vs %q", g.Short(), a.Short())
	}
	if len(string(a)) != 64 {
		t.Fatalf("generation = %d chars, want 64 hex", len(string(a)))
	}
}

// Editing any shield rule that shapes persisted state starts a new
// generation; the session/INVITE limits (no persisted state) do not.
func TestGenerationChangesWithRules(t *testing.T) {
	base := genCfg(t, shieldCfg)
	g0 := GenerationOf(base)
	for _, tc := range []struct {
		name  string
		apply func(*config.Config)
	}{
		{"ban", func(c *config.Config) { c.Shield.Ban = config.Duration(2 * time.Hour) }},
		{"rate_limit", func(c *config.Config) { c.Shield.RateLimit = "9/s per_ip" }},
		{"carrier_rate_limit", func(c *config.Config) { c.Shield.CarrierRateLimit = "9/s per_ip" }},
		{"register_ban", func(c *config.Config) { c.Shield.RegisterBan = "9/10m" }},
		{"admission_ban", func(c *config.Config) { c.Shield.AdmissionBan = "9/5m" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := *base
			tc.apply(&c)
			if GenerationOf(&c) == g0 {
				t.Fatalf("changing %s did not start a new generation", tc.name)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		apply func(*config.Config)
	}{
		{"max_sessions", func(c *config.Config) { c.Shield.MaxSessions = 7 }},
		{"invite_rate_limit", func(c *config.Config) { c.Shield.InviteRateLimit = "3/s" }},
	} {
		t.Run("unchanged/"+tc.name, func(t *testing.T) {
			c := *base
			tc.apply(&c)
			if GenerationOf(&c) != g0 {
				t.Fatalf("changing %s changed the security-state generation", tc.name)
			}
		})
	}
}

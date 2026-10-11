package config

import (
	"testing"
	"time"
)

func TestDurationUnmarshalYAML(t *testing.T) {
	var d Duration
	if err := d.UnmarshalYAML([]byte("90s")); err != nil {
		t.Fatalf("unmarshal 90s: %v", err)
	}
	if d.Std() != 90*time.Second {
		t.Errorf("got %v, want 90s", d.Std())
	}
	if err := d.UnmarshalYAML([]byte("not-a-duration")); err == nil {
		t.Error("expected error for invalid duration")
	}
	if err := d.UnmarshalYAML([]byte(`"90s"`)); err != nil {
		t.Fatalf("quoted duration must parse: %v", err)
	}
	if d.Std() != 90*time.Second {
		t.Errorf("quoted: got %v, want 90s", d.Std())
	}
}

func TestPortRangeUnmarshalYAML(t *testing.T) {
	var p PortRange
	if err := p.UnmarshalYAML([]byte("16384-32768")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Min != 16384 || p.Max != 32768 {
		t.Errorf("got %d-%d, want 16384-32768", p.Min, p.Max)
	}
	for _, bad := range []string{"16384", "32768-16384", "0-70000", "0-100", "a-b"} {
		if err := p.UnmarshalYAML([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	if err := p.UnmarshalYAML([]byte(`"16384-32768"`)); err != nil {
		t.Fatalf("quoted port range must parse: %v", err)
	}
	if p.Min != 16384 || p.Max != 32768 {
		t.Errorf("quoted: got %d-%d", p.Min, p.Max)
	}
}

func TestParseRateLimit(t *testing.T) {
	rl, err := ParseRateLimit("20/s per_ip")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rl.Rate != 20 || rl.Interval != time.Second || !rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	rl, err = ParseRateLimit("100/m")
	if err != nil {
		t.Fatalf("parse global: %v", err)
	}
	if rl.Rate != 100 || rl.Interval != time.Minute || rl.PerIP {
		t.Errorf("got %+v", rl)
	}
	for _, bad := range []string{"", "20", "0/s", "20/d", "20/s per_call"} {
		if _, err := ParseRateLimit(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestParseStrikeLimit(t *testing.T) {
	sl, err := ParseStrikeLimit("10/10m")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sl.N != 10 || sl.Window != 10*time.Minute || sl.Off {
		t.Errorf("got %+v", sl)
	}
	if sl, err := ParseStrikeLimit("off"); err != nil || !sl.Off {
		t.Errorf("off: got %+v, %v", sl, err)
	}
	if _, err := ParseStrikeLimit(DefaultRegisterBan); err != nil {
		t.Errorf("default %q: %v", DefaultRegisterBan, err)
	}
	for _, bad := range []string{"", "10", "0/10m", "-1/10m", "10/0s", "10/500ms", "10/25h", "10/m", "x/10m", "100001/1m", "OFF"} {
		if _, err := ParseStrikeLimit(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

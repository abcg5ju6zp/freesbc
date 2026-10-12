package edge

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The summary names the total, the number of sources and the top one, and
// an interval with no drops yields nothing.
func TestDropSummary(t *testing.T) {
	var d dropSummary
	if msg, ok := d.take(time.Minute); ok {
		t.Fatalf("empty interval produced %q", msg)
	}
	a, b := netip.MustParseAddr("51.15.26.108"), netip.MustParseAddr("198.51.100.4")
	for i := 0; i < 5; i++ {
		d.add(a)
	}
	d.add(b)
	d.add(netip.MustParseAddr("::ffff:198.51.100.4")) // mapped form is the same source
	msg, ok := d.take(time.Minute)
	want := "admission drops: 7 in 1m0s from 2 sources, top=51.15.26.108 (5)"
	if !ok || msg != want {
		t.Fatalf("summary = %q, %v; want %q", msg, ok, want)
	}
	if msg, ok := d.take(time.Minute); ok {
		t.Fatalf("interval after take produced %q", msg)
	}
}

// Sources past the tally cap still count in the total and never grow the map.
func TestDropSummaryBounded(t *testing.T) {
	var d dropSummary
	n := maxSummarySources + 500
	for i := 0; i < n; i++ {
		d.add(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if len(d.bySrc) != maxSummarySources {
		t.Fatalf("tally holds %d sources, want the cap %d", len(d.bySrc), maxSummarySources)
	}
	msg, ok := d.take(time.Minute)
	if !ok || !strings.HasPrefix(msg, fmt.Sprintf("admission drops: %d in", n)) || !strings.Contains(msg, "+ sources") {
		t.Fatalf("summary = %q", msg)
	}
}

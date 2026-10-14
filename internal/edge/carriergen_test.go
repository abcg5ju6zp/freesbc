package edge

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// genTestDirectory builds a standalone directory for one explicit-port
// DNS carrier (A-record lookups only), with a recording conn closer.
func genTestDirectory(t *testing.T, clk *fakeClock, stub *dnsStub) (*carrierDirectory, *[]string) {
	t.Helper()
	d := &carrierDirectory{
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		carriers:  []config.Carrier{{Name: "a", Host: "gw.example", Port: 5060, ExplicitPort: true, Transport: config.CarrierTCP}},
		lookupSRV: stub.lookupSRV,
		lookupIP:  stub.lookupIP,
		now:       clk.now,
		entries:   map[string]*carrierEntry{},
		statics:   map[string]*carrierGen{},
		rnd:       rand.New(rand.NewSource(1)),
	}
	var closedMu sync.Mutex
	var closed []string
	d.closeConn = func(network, addr string) {
		closedMu.Lock()
		closed = append(closed, network+":"+addr)
		closedMu.Unlock()
	}
	d.buildStatics()
	d.publish()
	return d, &closed
}

func genRefresh(d *carrierDirectory) { d.refresh(context.Background()) }

func genClock() *fakeClock { return &fakeClock{t: time.Unix(1000, 0)} }

func genStub(ips ...string) *dnsStub {
	m := map[string][]string{"gw.example": ips}
	return &dnsStub{ips: m}
}

func curGen(d *carrierDirectory, name string) *carrierGen {
	g, ok := d.currentGen(name)
	if !ok {
		return nil
	}
	return g
}

// A changed address set opens a new current generation.
func TestCarrierGenerationChangeOpensNewGeneration(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")
	if g1 == nil || g1.id != 1 || g1.born != genBirthStartup {
		t.Fatalf("first generation = %+v", g1)
	}
	if dest, _, ok := d.currentGenDest(t, "a"); !ok || dest != "192.0.2.1:5060" {
		t.Fatalf("current dest = %q, %v", dest, ok)
	}

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)
	g2 := curGen(d, "a")
	if g2 == nil || g2.id != 2 || g2.born != genBirthRefresh {
		t.Fatalf("second generation = %+v", g2)
	}
	// A new request only ever selects the current generation.
	if dest, _, ok := d.currentGenDest(t, "a"); !ok || dest != "192.0.2.2:5060" {
		t.Fatalf("current dest after handoff = %q", dest)
	}
}

// currentGenDest is the t.Helper-shaped carrierDest for a directory.
func (d *carrierDirectory) currentGenDest(t *testing.T, name string) (string, *carrierGen, bool) {
	t.Helper()
	g, ok := d.currentGen(name)
	if !ok {
		return "", nil, false
	}
	return g.addrs[0].String(), g, true
}

// With no pinned traffic the old generation retires at the handoff and
// its connection is closed; its address stops being a carrier source.
func TestCarrierGenerationRetiresWithNoReferences(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, closed := genTestDirectory(t, clk, stub)
	genRefresh(d)
	old := curGen(d, "a")

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)

	if got := d.snapshot().isSource(netip.MustParseAddr("192.0.2.1")); got {
		t.Error("the retired address is still a carrier source")
	}
	if _, _, ok := d.genByDest("tcp", "192.0.2.1:5060"); ok {
		t.Error("genByDest still dials the retired address")
	}
	if old.state != genRetired || old.retiredWhy != genRetireReplaced {
		t.Errorf("old gen state = %s/%s, want retired/%s", old.state, old.retiredWhy, genRetireReplaced)
	}
	if len(*closed) != 1 || (*closed)[0] != "tcp:192.0.2.1:5060" {
		t.Errorf("closed conns = %v, want [tcp:192.0.2.1:5060]", *closed)
	}
}

// A pinned registration/dialog/exchange keeps the old generation
// retained: its address still admits and routes traffic, but no new
// request selects it; releasing the last such pin retires it and closes
// the connection that only carried it. A connection alone is not work.
func TestCarrierGenerationRetainedThenDrained(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, closed := genTestDirectory(t, clk, stub)
	genRefresh(d)
	old := curGen(d, "a")
	if !d.acquire(old, refReg) {
		t.Fatal("acquire on the current generation failed")
	}
	// A connection to the gateway alone never retains the generation.
	if !d.acquire(old, refConn) {
		t.Fatal("acquire refConn")
	}

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)

	if old.state != genRetained {
		t.Fatalf("pinned old gen state = %s, want retained", old.state)
	}
	if !d.snapshot().isSource(netip.MustParseAddr("192.0.2.1")) {
		t.Error("the retained address lost its carrier source")
	}
	if name, g, ok := d.sourceGen(ap("192.0.2.1:5060"), "tcp"); !ok || name != "a" || g != old {
		t.Errorf("sourceGen old = %q,%p,%v; want a,%p,true", name, g, ok, old)
	}
	if name, g, ok := d.genByDest("tcp", "192.0.2.1:5060"); !ok || name != "a" || g != old {
		t.Errorf("genByDest old = %q,%p,%v", name, g, ok)
	}
	if dest, _, _ := d.currentGenDest(t, "a"); dest != "192.0.2.2:5060" {
		t.Errorf("a new request still selects the retained gen: %s", dest)
	}
	if len(*closed) != 0 {
		t.Errorf("the pinned connection was closed: %v", *closed)
	}

	// Dialog and exchange pins keep it alive as well.
	for _, k := range []refKind{refDialog, refTx} {
		if !d.acquire(old, k) {
			t.Fatalf("acquire %d failed", k)
		}
	}
	d.release(old, refReg)
	if old.state != genRetained {
		t.Error("the generation retired while dialog/tx pins remained")
	}
	d.release(old, refTx)
	d.release(old, refDialog)
	if old.state != genRetired {
		t.Errorf("state after the last live pin = %s, want retired", old.state)
	}
	if len(*closed) != 1 {
		t.Errorf("closed conns = %v, want exactly one on retirement", *closed)
	}
	// Its connection pin is released when the close lands; it is a no-op.
	d.release(old, refConn)
	if _, _, ok := d.genByDest("tcp", "192.0.2.1:5060"); ok {
		t.Error("a retired generation still authorizes a dial")
	}
}

// A resolution failure neither opens a generation nor touches a healthy
// retained one: the current (last good) generation stays in use.
func TestCarrierGenerationFailureKeepsCurrent(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	cur := curGen(d, "a")

	stub.mu.Lock()
	stub.ipErr = errors.New("resolver down")
	stub.mu.Unlock()
	clk.advance(carrierDNSTTL + time.Second)
	genRefresh(d)

	if curGen(d, "a") != cur {
		t.Fatal("a failed refresh replaced the current generation")
	}
	info := d.snapshotInfo()[0]
	if !info.Failing || info.GenerationID != cur.id || info.LastError == "" {
		t.Errorf("info after failure = %+v", info)
	}
	if !d.snapshot().isSource(netip.MustParseAddr("192.0.2.1")) {
		t.Error("a failed refresh revoked the source qualification")
	}

	// Recovery keeps the same generation (same set) and clears Failing.
	stub.mu.Lock()
	stub.ipErr = nil
	stub.mu.Unlock()
	clk.advance(carrierDNSNegTTL + time.Second)
	genRefresh(d)
	info = d.snapshotInfo()[0]
	if info.Failing || curGen(d, "a") != cur {
		t.Errorf("recovery did not keep/clear the generation: %+v same=%v", info, curGen(d, "a") == cur)
	}
}

// An address set that returns to a still-retained generation readopts
// it instead of opening another one.
func TestCarrierGenerationSwitchback(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")
	if !d.acquire(g1, refReg) {
		t.Fatal("acquire g1")
	}

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)
	g2 := curGen(d, "a")
	if g2 == g1 {
		t.Fatal("the handoff did not open a new generation")
	}
	// A second registration on the new gateway pins g2 as well: both
	// generations stay live until their own bindings end.
	if !d.acquire(g2, refReg) {
		t.Fatal("acquire g2")
	}
	if g1.state != genRetained {
		t.Fatalf("g1 = %s, want retained", g1.state)
	}

	// Back to the first set while g1 is still pinned.
	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.1"}
	genRefresh(d)
	if cur := curGen(d, "a"); cur != g1 {
		t.Errorf("switchback current = gen %d, want readopted gen %d", cur.id, g1.id)
	}
	if g1.born != genBirthSwitchback || g1.promotedAt.IsZero() {
		t.Errorf("readopted gen not marked: born=%q promotedAt=%v", g1.born, g1.promotedAt)
	}
	if g2.state != genRetained {
		t.Errorf("the displaced generation is %s, want retained", g2.state)
	}
}

// A switchback to a generation that already retired opens a fresh
// generation: dead generations are never resurrected.
func TestCarrierGenerationSwitchbackAfterRetirement(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d) // g1 retires immediately (no pins)
	if g1.state != genRetired {
		t.Fatalf("g1 = %s", g1.state)
	}

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.1"}
	genRefresh(d)
	cur := curGen(d, "a")
	if cur == g1 || cur.id == g1.id {
		t.Fatalf("the retired generation was resurrected: %+v", cur)
	}
	if cur.id != 3 || cur.born != genBirthRefresh {
		t.Errorf("new generation = %d/%s, want 3/refresh", cur.id, cur.born)
	}
}

// Addresses shared with the current generation are not closed when the
// old one retires.
func TestCarrierGenerationSharedAddressesStayOpen(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1", "192.0.2.2")
	d, closed := genTestDirectory(t, clk, stub)
	genRefresh(d)

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2", "192.0.2.3"}
	genRefresh(d)
	// Only 192.0.2.1 is exclusive to the retired generation.
	if len(*closed) != 1 || (*closed)[0] != "tcp:192.0.2.1:5060" {
		t.Errorf("closed = %v, want only the address no live gen names", *closed)
	}
}

// acquire fails on a retired generation and release is balanced.
func TestCarrierGenerationAcquireAfterRetireFails(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")

	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)
	if d.acquire(g1, refTx) {
		t.Error("acquire on an already retired generation succeeded")
	}
	// Releasing an unacquired pin never drives a count negative.
	d.release(g1, refConn)
	if g1.refs[refConn] != 0 {
		t.Errorf("refs = %d, want 0", g1.refs[refConn])
	}
}

// shutdown records a final closed handoff for every live generation.
func TestCarrierGenerationShutdownLedger(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")
	if !d.acquire(g1, refDialog) {
		t.Fatal("acquire")
	}
	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d) // g1 retained with one dialog pin

	d.shutdown()
	if g1.state != genClosed || curGen2(d).state != genClosed {
		t.Errorf("states = %s, %s; want both closed", g1.state, curGen2(d).state)
	}
	// After shutdown no new pin is taken and releases are no-ops.
	if d.acquire(curGen2(d), refTx) {
		t.Error("acquire after shutdown succeeded")
	}
	infos := d.snapshotInfo()[0].Generations
	if len(infos) < 2 {
		t.Fatalf("ledger = %d generations", len(infos))
	}
	var closedN int
	for _, gi := range infos {
		if gi.State == genClosed.String() {
			closedN++
		}
	}
	if closedN != 2 {
		t.Errorf("closed generations in ledger = %d, want 2", closedN)
	}
}

func curGen2(d *carrierDirectory) *carrierGen { return curGen(d, "a") }

// The operator view shows the ledger with refs and handoffs.
func TestCarrierGenerationInfoLedger(t *testing.T) {
	clk := genClock()
	stub := genStub("192.0.2.1")
	d, _ := genTestDirectory(t, clk, stub)
	genRefresh(d)
	g1 := curGen(d, "a")
	if !d.acquire(g1, refReg) {
		t.Fatal("acquire")
	}
	clk.advance(carrierDNSTTL + time.Second)
	stub.ips["gw.example"] = []string{"192.0.2.2"}
	genRefresh(d)

	info := d.snapshotInfo()[0]
	if info.GenerationID != 2 || len(info.Addresses) != 1 || !info.Addresses[0].InUse {
		t.Errorf("current view = %+v", info)
	}
	var cur, retained *CarrierGenerationInfo
	for i := range info.Generations {
		switch info.Generations[i].State {
		case "current":
			cur = &info.Generations[i]
		case "retained":
			retained = &info.Generations[i]
		}
	}
	if cur == nil || cur.ID != 2 || cur.Born != genBirthRefresh {
		t.Errorf("current ledger entry = %+v", cur)
	}
	if retained == nil || retained.ID != 1 || retained.Refs.Registrations != 1 {
		t.Errorf("retained ledger entry = %+v", retained)
	}
	if len(retained.Handoffs) == 0 {
		t.Error("the retained generation recorded no handoff")
	}
}

// A literal carrier always presents one static current generation that
// references neither open nor close.
func TestCarrierGenerationLiteralStatic(t *testing.T) {
	c := config.Carrier{Name: "lit", Host: "198.51.100.4", Port: 5061, ExplicitPort: true,
		Addr: netip.MustParseAddr("198.51.100.4"), Transport: config.CarrierTCP}
	d := &carrierDirectory{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), carriers: []config.Carrier{c},
		now: genClock().now, entries: map[string]*carrierEntry{}, statics: map[string]*carrierGen{},
		rnd: rand.New(rand.NewSource(1)),
	}
	d.buildStatics()
	d.publish()
	g := curGen(d, "lit")
	if g == nil || !g.static || g.born != genBirthLiteral {
		t.Fatalf("static gen = %+v", g)
	}
	if !d.acquire(g, refConn) {
		t.Error("acquire on the static generation failed")
	}
	d.release(g, refConn) // no-op
	genRefresh(d)         // never resolved
	if curGen(d, "lit") != g {
		t.Error("the static generation was replaced")
	}
}

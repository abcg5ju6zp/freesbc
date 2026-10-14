package edge

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

func binding(aor, callID string, src string, ttl time.Duration) Binding {
	return Binding{
		AOR: aor, User: aor[:len(aor)-len("@example.com")],
		CallID: callID, Transport: "udp",
		Source:    netip.MustParseAddrPort(src),
		ExpiresAt: time.Now().Add(ttl),
	}
}

func TestLocationPutAndLookup(t *testing.T) {
	l := NewLocation()
	b, err := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if b.Token == "" {
		t.Fatal("no token assigned")
	}
	got, ok := l.ByToken(b.Token)
	if !ok || got.AOR != "1001@example.com" {
		t.Fatalf("ByToken = %+v %v", got, ok)
	}
	if bs := l.ByAOR("1001@example.com"); len(bs) != 1 {
		t.Fatalf("ByAOR = %d bindings", len(bs))
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d", l.Count())
	}
}

// A refresh must keep the SAME token: FreeSWITCH stored that contact and
// will use it as the Request-URI of every inbound call, so a new token
// would strand the registration.
func TestLocationRefreshKeepsToken(t *testing.T) {
	l := NewLocation()
	first, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	second, err := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:6000", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Token != first.Token {
		t.Fatalf("token changed on refresh: %q → %q", first.Token, second.Token)
	}
	if l.Count() != 1 {
		t.Errorf("refresh created a second binding: %d", l.Count())
	}
	// ...but the source address must follow the client's new port.
	got, _ := l.ByToken(first.Token)
	if got.Source.Port() != 6000 {
		t.Errorf("source not updated: %v", got.Source)
	}
}

// Two devices for one user are two bindings with two tokens.
func TestLocationMultipleDevices(t *testing.T) {
	l := NewLocation()
	a, _ := l.Put(binding("1001@example.com", "desk-phone", "198.51.100.5:5060", time.Hour))
	b, _ := l.Put(binding("1001@example.com", "browser", "203.0.113.9:41000", time.Hour))
	if a.Token == b.Token {
		t.Fatal("two devices share a token")
	}
	if got := len(l.ByAOR("1001@example.com")); got != 2 {
		t.Fatalf("ByAOR = %d, want 2", got)
	}
}

func TestLocationRemove(t *testing.T) {
	l := NewLocation()
	b, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour))
	if l.Remove("1001@example.com", "call-a") == nil {
		t.Fatal("Remove reported nothing removed")
	}
	if _, ok := l.ByToken(b.Token); ok {
		t.Error("binding still resolvable after Remove")
	}
	if l.Count() != 0 {
		t.Errorf("Count = %d after Remove", l.Count())
	}
	if l.Remove("1001@example.com", "call-a") != nil {
		t.Error("second Remove reported a removal")
	}
}

func TestLocationExpiry(t *testing.T) {
	l := NewLocation()
	b, _ := l.Put(binding("1001@example.com", "call-a", "198.51.100.5:5060", -time.Second))
	if _, ok := l.ByToken(b.Token); ok {
		t.Error("expired binding resolvable")
	}
	if got := l.ByAOR("1001@example.com"); len(got) != 0 {
		t.Error("expired binding listed")
	}
	if n := l.Prune(); n != 1 {
		t.Errorf("Prune removed %d, want 1", n)
	}
	if l.Count() != 0 {
		t.Errorf("Count = %d after Prune", l.Count())
	}
}

// A stream connection that closes takes the bindings owned by ITS flow:
// keeping them would make FreeSBC accept inbound calls it cannot deliver.
// A UDP binding has no flow and stays for its expiry.
func TestLocationRetireFlow(t *testing.T) {
	l := NewLocation()
	mk := func(aor, callID string, flow flowID) Binding {
		b := binding(aor, callID, "203.0.113.9:41000", time.Hour)
		b.Transport = "ws"
		b.FlowID = flow
		return b
	}
	l.Put(mk("1001@example.com", "ws-a", 7))
	l.Put(mk("1002@example.com", "ws-b", 7))
	l.Put(binding("1003@example.com", "udp", "198.51.100.5:5060", time.Hour))
	if n := len(l.RetireFlow(7)); n != 2 {
		t.Fatalf("retired %d, want 2", n)
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d, want 1", l.Count())
	}
	// Retiring a flow that owns nothing (again, or the UDP zero flow) is a
	// no-op.
	if n := len(l.RetireFlow(7)); n != 0 {
		t.Errorf("second RetireFlow removed %d", n)
	}
	if n := len(l.RetireFlow(0)); n != 0 {
		t.Errorf("RetireFlow(0) removed %d UDP bindings", n)
	}
}

// The whole point of the flow identity: a NEW connection that reuses the
// same transport and source address must not lose its binding to the OLD
// connection's delayed retirement.
func TestLocationRetireFlowSparesReusedAddress(t *testing.T) {
	l := NewLocation()
	src := netip.MustParseAddrPort("203.0.113.9:41000")
	old := binding("1001@example.com", "call-a", src.String(), time.Hour)
	old.Transport, old.FlowID = "tcp", 1
	stored, err := l.Put(old)
	if err != nil {
		t.Fatal(err)
	}
	// The device reconnects: same AoR and Call-ID, same address, new flow.
	repl := old
	repl.Token, repl.FlowID = stored.Token, 2
	if _, err := l.Commit(repl, 1); err != nil {
		t.Fatalf("replacement Commit: %v", err)
	}
	// The old connection's close must observe nothing of the new flow.
	if n := len(l.RetireFlow(1)); n != 0 {
		t.Fatalf("old flow retired %d bindings, want 0", n)
	}
	got, ok := l.ByToken(stored.Token)
	if !ok {
		t.Fatal("the new flow's binding was deleted by the old generation")
	}
	if got.FlowID != 2 {
		t.Errorf("binding flow = %d, want 2", got.FlowID)
	}
	if !l.HasSource("tcp", src) {
		t.Error("source no longer admitted after the old flow retired")
	}
	// The new connection's own close then takes it.
	if n := len(l.RetireFlow(2)); n != 1 {
		t.Fatalf("new flow retired %d, want 1", n)
	}
	if l.Count() != 0 {
		t.Errorf("Count = %d, want 0", l.Count())
	}
}

// A registrar response observed an earlier binding version than the one now
// installed: Commit neither overwrites it nor moves it back onto the
// response's source and flow.
func TestLocationCommitStaleGeneration(t *testing.T) {
	l := NewLocation()
	src := netip.MustParseAddrPort("203.0.113.9:41000")
	first := binding("1001@example.com", "call-a", src.String(), time.Hour)
	first.Transport, first.FlowID = "tcp", 1
	stored, err := l.Commit(first, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stored.gen != 1 {
		t.Fatalf("first gen = %d, want 1", stored.gen)
	}
	token := stored.Token
	// Refresh on a new connection bumps the gen.
	next := first
	next.Token, next.FlowID = token, 2
	if _, err := l.Commit(next, 1); err != nil {
		t.Fatalf("refresh Commit: %v", err)
	}
	got, _ := l.ByToken(token)
	if got.gen != 2 || got.FlowID != 2 {
		t.Fatalf("after refresh gen=%d flow=%d, want 2/2", got.gen, got.FlowID)
	}
	// A first-registration response (observed gen 0) arriving late cannot
	// install a second copy.
	lateFirst := first
	lateFirst.Token = token
	if _, err := l.Commit(lateFirst, 0); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("stale first response: err=%v, want ErrStaleBinding", err)
	}
	// The old flow's delayed granted response (observed gen 1) cannot move
	// the binding back to the closed socket.
	stale := first
	stale.Token = token
	stale.Source = netip.MustParseAddrPort("203.0.113.9:9999")
	if _, err := l.Commit(stale, 1); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("stale refresh response: err=%v, want ErrStaleBinding", err)
	}
	got, _ = l.ByToken(token)
	if got.FlowID != 2 || got.Source.Port() != src.Port() {
		t.Errorf("stale response overwrote the binding: flow=%d source=%v", got.FlowID, got.Source)
	}
	// A response for a version already removed is stale as well.
	if _, err := l.Commit(lateFirst, 99); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("removed-version response: err=%v, want ErrStaleBinding", err)
	}
}

// A renewal whose previous binding expired and was pruned while its fresh
// 200 was in flight installs again with the token it kept: the registrar
// has just re-granted the lifetime, so this is a live registration, not a
// stale response.
func TestLocationCommitRenewsAfterPrune(t *testing.T) {
	l := NewLocation()
	b := binding("1001@example.com", "call-a", "198.51.100.5:5060", -time.Second)
	stored, _ := l.Commit(b, 0)
	if n := l.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	renewed := b
	renewed.Token = stored.Token
	renewed.ExpiresAt = time.Now().Add(time.Hour)
	got, err := l.Commit(renewed, stored.gen)
	if err != nil {
		t.Fatalf("renewal after prune: %v", err)
	}
	if got.Token != stored.Token || got.gen != 1 {
		t.Errorf("renewed binding = token %s gen %d, want %s / 1", got.Token, got.gen, stored.Token)
	}
	if _, ok := l.ByToken(stored.Token); !ok {
		t.Error("renewed binding is not resolvable")
	}
}

// Commit refuses a stream binding whose flow has already retired, so a
// delayed 200 cannot resurrect a dead connection.
func TestLocationCommitRejectsDeadFlow(t *testing.T) {
	flows := newFlowRegistry()
	l := NewLocation()
	l.flowAlive = flows.alive
	conn := &streamConn{}
	id := flows.issue("tcp", netip.MustParseAddrPort("203.0.113.9:41000"), conn, false)
	b := binding("1001@example.com", "call-a", "203.0.113.9:41000", time.Hour)
	b.Transport, b.FlowID = "tcp", id
	if _, err := l.Commit(b, 0); err != nil {
		t.Fatalf("Commit on the open flow: %v", err)
	}
	flows.retire(id)
	b2 := binding("1001@example.com", "call-b", "203.0.113.9:41000", time.Hour)
	b2.Transport, b2.FlowID = "tcp", id
	if _, err := l.Commit(b2, 0); !errors.Is(err, ErrStaleBinding) {
		t.Fatalf("Commit on a retired flow: err=%v, want ErrStaleBinding", err)
	}
}

// RetireObserved removes only the version the un-REGISTER response saw; a
// replacement with a newer gen stays. RetireAOR applies the same rule to
// the set a wildcard un-REGISTER saw.
func TestLocationRetireObservedGenerations(t *testing.T) {
	l := NewLocation()
	b1 := binding("1001@example.com", "call-a", "198.51.100.5:5060", time.Hour)
	stored, _ := l.Commit(b1, 0)
	other := binding("1001@example.com", "call-b", "198.51.100.6:5060", time.Hour)
	l.Commit(other, 0)
	obs := []bindingObs{{Token: stored.Token, Gen: stored.gen}}
	// Wrong gen: nothing moves.
	if l.RetireObserved("1001@example.com", "call-a", stored.gen+1) != nil {
		t.Fatal("RetireObserved removed a newer generation")
	}
	if l.Count() != 2 {
		t.Fatalf("Count = %d, want 2", l.Count())
	}
	// Wildcard with the same stale observation removes nothing.
	if n := len(l.RetireAOR("1001@example.com", []bindingObs{{Token: stored.Token, Gen: stored.gen + 1}})); n != 0 {
		t.Fatalf("stale wildcard retired %d", n)
	}
	// Exact versions retire.
	if l.RetireObserved("1001@example.com", "call-a", stored.gen) == nil {
		t.Fatal("RetireObserved with the observed gen removed nothing")
	}
	if n := len(l.RetireAOR("1001@example.com", obs)); n != 0 {
		t.Fatalf("RetireAOR re-removed %d", n)
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d, want 1", l.Count())
	}
}

func TestLocationBounds(t *testing.T) {
	l := NewLocation()
	l.maxPerAOR = 2
	for i, id := range []string{"a", "b"} {
		if _, err := l.Put(binding("1001@example.com", id, "198.51.100.5:5060", time.Hour)); err != nil {
			t.Fatalf("device %d rejected: %v", i, err)
		}
	}
	if _, err := l.Put(binding("1001@example.com", "c", "198.51.100.5:5060", time.Hour)); err == nil {
		t.Fatal("per-AoR cap not enforced")
	}

	l2 := NewLocation()
	l2.maxTotal = 2
	l2.Put(binding("1001@example.com", "a", "198.51.100.5:5060", time.Hour))
	l2.Put(binding("1002@example.com", "b", "198.51.100.5:5060", time.Hour))
	if _, err := l2.Put(binding("1003@example.com", "c", "198.51.100.5:5060", time.Hour)); err == nil {
		t.Fatal("total cap not enforced")
	}
}

func TestTokensAreUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := fsip.NewToken()
		if len(tok) < 16 {
			t.Fatalf("token %q too short to resist guessing", tok)
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}

// streamBinding is a binding with a flow set, for the index tests.
func streamBinding(aor, callID, src string, flow flowID) Binding {
	b := binding(aor, callID, src, time.Hour)
	b.Transport = "tcp"
	b.FlowID = flow
	return b
}

// checkSourceIndex fails the test unless the source and flow indexes hold
// exactly the bindings the token index holds, each under its own Source and
// FlowID.
func checkSourceIndex(t *testing.T, l *Location) {
	t.Helper()
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := 0
	for src, list := range l.bySource {
		if len(list) == 0 {
			t.Errorf("source index keeps an empty list for %v", src)
		}
		for _, b := range list {
			n++
			if b.Source != src {
				t.Errorf("binding %s indexed under %v, its source is %v", b.Token, src, b.Source)
			}
			if l.byToken[b.Token] != b {
				t.Errorf("source index holds binding %s the token index does not", b.Token)
			}
		}
	}
	if n != len(l.byToken) {
		t.Errorf("source index holds %d bindings, token index %d", n, len(l.byToken))
	}
	nf := 0
	for id, list := range l.byFlow {
		if id == 0 {
			t.Error("a UDP binding is in the flow index")
		}
		if len(list) == 0 {
			t.Errorf("flow index keeps an empty list for %d", id)
		}
		for _, b := range list {
			nf++
			if b.FlowID != id {
				t.Errorf("binding %s indexed under flow %d, its flow is %d", b.Token, id, b.FlowID)
			}
			if l.byToken[b.Token] != b {
				t.Errorf("flow index holds binding %s the token index does not", b.Token)
			}
		}
	}
	for _, b := range l.byToken {
		if b.FlowID != 0 {
			nf--
		}
	}
	if nf != 0 {
		t.Errorf("flow index and stream bindings disagree by %d", nf)
	}
}

// The source and flow indexes (HasSource, RetireFlow) must stay consistent
// with the token index through every way a binding enters or leaves.
func TestLocationSourceIndexConsistency(t *testing.T) {
	l := NewLocation()
	srcA := netip.MustParseAddrPort("198.51.100.5:5060")
	srcB := netip.MustParseAddrPort("198.51.100.5:6000")

	// add: two AoRs over one socket share a source.
	if _, err := l.Put(binding("1001@example.com", "call-a", srcA.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("1002@example.com", "call-b", srcA.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)
	if !l.HasSource("udp", srcA) || !l.HasSource("UDP", srcA) {
		t.Fatal("HasSource misses a registered udp source")
	}
	if l.HasSource("ws", srcA) {
		t.Error("HasSource matched the wrong transport")
	}
	if l.HasSource("udp", srcB) {
		t.Error("HasSource matched a different port of the same IP")
	}

	// refresh from a new source: re-indexed, the old source keeps only the
	// other AoR.
	if _, err := l.Put(binding("1001@example.com", "call-a", srcB.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)
	if !l.HasSource("udp", srcB) || !l.HasSource("udp", srcA) {
		t.Fatal("refresh lost a source")
	}

	// remove (un-REGISTER): srcA's last binding goes, and so does srcA.
	if l.Remove("1002@example.com", "call-b") == nil {
		t.Fatal("Remove found nothing")
	}
	checkSourceIndex(t, l)
	if l.HasSource("udp", srcA) {
		t.Error("source still admitted after its only binding was removed")
	}

	// RetireFlow: every binding owned by the flow, and nothing else.
	if _, err := l.Put(streamBinding("1003@example.com", "call-c", srcB.String(), 5)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(streamBinding("1004@example.com", "call-d", srcA.String(), 5)); err != nil {
		t.Fatal(err)
	}
	if n := len(l.RetireFlow(5)); n != 2 {
		t.Fatalf("RetireFlow removed %d, want 2", n)
	}
	checkSourceIndex(t, l)
	if l.HasSource("tcp", srcB) || l.HasSource("tcp", srcA) || !l.HasSource("udp", srcB) || l.Count() != 1 {
		t.Fatalf("RetireFlow: srcB=%v srcA=%v udpAtB=%v count=%d",
			l.HasSource("tcp", srcB), l.HasSource("tcp", srcA), l.HasSource("udp", srcB), l.Count())
	}

	// expiry: an expired binding is not a live source even before Prune,
	// and Prune takes it out of the index.
	if _, err := l.Put(binding("1005@example.com", "call-e", "198.51.100.9:5060", -time.Second)); err != nil {
		t.Fatal(err)
	}
	if l.HasSource("udp", netip.MustParseAddrPort("198.51.100.9:5060")) {
		t.Error("an expired binding admits its source")
	}
	if n := l.Prune(); n != 1 {
		t.Fatalf("Prune = %d, want 1", n)
	}
	checkSourceIndex(t, l)

	// The per-AoR sweep in Put removes an expired binding from the index
	// too.
	if _, err := l.Put(binding("1004@example.com", "call-x", srcB.String(), -time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Put(binding("1004@example.com", "call-y", srcB.String(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	checkSourceIndex(t, l)

	// A refused Put (per-AoR cap) must leave no trace in the index.
	for i := 0; i < defaultMaxPerAOR+2; i++ {
		_, _ = l.Put(binding("1006@example.com", "cap-"+string(rune('a'+i)), "198.51.100.10:5060", time.Hour))
	}
	checkSourceIndex(t, l)
	if got := len(l.ByAOR("1006@example.com")); got != defaultMaxPerAOR {
		t.Fatalf("per-AoR cap: %d bindings, want %d", got, defaultMaxPerAOR)
	}
}

// The removal hook (used to end subscription records) hears about every way
// a binding leaves the table, after the table's lock is released, and not
// about a refresh in place.
func TestLocationRemoveHook(t *testing.T) {
	newTable := func() (*Location, *[]string) {
		l := NewLocation()
		var got []string
		l.SetOnRemove(func(tokens []string) {
			// The hook runs outside the lock: it may call back in.
			_ = l.Count()
			got = append(got, tokens...)
		})
		return l, &got
	}
	mustPut := func(t *testing.T, l *Location, b Binding) *Binding {
		t.Helper()
		p, err := l.Put(b)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("Remove", func(t *testing.T) {
		l, got := newTable()
		b := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", time.Hour))
		l.Remove("1001@example.com", "c1")
		if len(*got) != 1 || (*got)[0] != b.Token {
			t.Errorf("hook tokens = %v, want [%s]", *got, b.Token)
		}
	})
	t.Run("RetireFlow", func(t *testing.T) {
		l, got := newTable()
		a := mustPut(t, l, streamBinding("1001@example.com", "c1", "198.51.100.5:5060", 9))
		b := mustPut(t, l, streamBinding("1002@example.com", "c2", "198.51.100.5:5060", 9))
		mustPut(t, l, streamBinding("1003@example.com", "c3", "198.51.100.6:5060", 10))
		l.RetireFlow(9)
		if len(*got) != 2 {
			t.Fatalf("hook tokens = %v, want the two bindings of that flow", *got)
		}
		seen := map[string]bool{(*got)[0]: true, (*got)[1]: true}
		if !seen[a.Token] || !seen[b.Token] {
			t.Errorf("hook tokens = %v", *got)
		}
	})
	t.Run("Prune", func(t *testing.T) {
		l, got := newTable()
		old := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", -time.Second))
		mustPut(t, l, binding("1002@example.com", "c2", "198.51.100.6:5060", time.Hour))
		if n := l.Prune(); n != 1 {
			t.Fatalf("Prune = %d", n)
		}
		if len(*got) != 1 || (*got)[0] != old.Token {
			t.Errorf("hook tokens = %v, want [%s]", *got, old.Token)
		}
	})
	t.Run("sweep inside Put", func(t *testing.T) {
		l, got := newTable()
		old := mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", -time.Second))
		mustPut(t, l, binding("1001@example.com", "c2", "198.51.100.5:5062", time.Hour))
		if len(*got) != 1 || (*got)[0] != old.Token {
			t.Errorf("hook tokens = %v, want the lapsed binding [%s]", *got, old.Token)
		}
	})
	t.Run("refresh in place is not a removal", func(t *testing.T) {
		l, got := newTable()
		mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:5060", time.Hour))
		mustPut(t, l, binding("1001@example.com", "c1", "198.51.100.5:6000", time.Hour))
		if len(*got) != 0 {
			t.Errorf("hook tokens = %v, want none", *got)
		}
	})
}

// A closing stream connection removes only its own flow's bindings: a UDP
// binding from the same IP:port (no flow) is another client's, and so is a
// stream binding of a different connection even at the same address.
func TestLocationRetireFlowScopesByFlow(t *testing.T) {
	l := NewLocation()
	src := netip.MustParseAddrPort("203.0.113.9:41000")
	tcp := binding("1001@example.com", "tcp-a", src.String(), time.Hour)
	tcp.Transport, tcp.FlowID = "tcp", 11
	udp := binding("1002@example.com", "udp-a", src.String(), time.Hour)
	other := binding("1003@example.com", "tcp-b", src.String(), time.Hour)
	other.Transport, other.FlowID = "tcp", 12
	l.Put(tcp)
	l.Put(udp)
	otherStored, _ := l.Put(other)
	if n := len(l.RetireFlow(11)); n != 1 {
		t.Fatalf("retired %d, want 1", n)
	}
	// The UDP binding at the same address and the OTHER connection's
	// binding both survive: retirement is by flow, not by address.
	if !l.HasSource("udp", src) {
		t.Error("the UDP binding at the same address was retired")
	}
	if _, ok := l.ByToken(otherStored.Token); !ok {
		t.Error("the other connection's binding was removed by flow 11")
	}
	if l.Count() != 2 {
		t.Errorf("Count = %d, want 2", l.Count())
	}
	if n := len(l.RetireFlow(12)); n != 1 {
		t.Fatalf("flow 12 retired %d, want 1", n)
	}
	if l.Count() != 1 {
		t.Errorf("Count = %d after both flows retired, want 1 (UDP)", l.Count())
	}
}

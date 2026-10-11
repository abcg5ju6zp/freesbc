package edge

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/freesbc/freesbc/internal/shield"
)

// Tests for the REGISTER credential guard (regguard.go, issue #181).
// Timing-based over real UDP guardSrc: re-run once before treating a flake
// as failure.

var guardSrc = netip.MustParseAddr("127.0.0.1")

// setRegisterBan hot-reloads shield.register_ban.
func setRegisterBan(h *harness, v string) {
	next := *h.store.Current()
	next.Shield.RegisterBan = v
	h.store.Replace(&next)
}

func setAuthStatus(h *harness, code int) {
	h.fs.mu.Lock()
	h.fs.authStatus = code
	h.fs.mu.Unlock()
}

func authFailures(h *harness) uint64 { return h.srv.metrics.Snapshot().RegisterAuthFailures }

func bannedLoopback(h *harness) bool { return h.srv.currentShield().Banned(guardSrc) }

// digest is an Authorization value answering the fake switch's challenge
// (nonce "abc123nonce") with a guessed response.
func digest(user, nonce, response string) string {
	return fmt.Sprintf(`Digest username="%s", realm="example.com", nonce="%s", uri="sip:example.com", response="%s", algorithm=MD5`,
		user, nonce, response)
}

// challengeThenGuess runs one challenge-and-guess cycle from c: a
// credential-less REGISTER (401 with the nonce), then one with a wrong
// credential, returning the second's final status.
func challengeThenGuess(t *testing.T, h *harness, c *client, user string, i int) int {
	t.Helper()
	if res := c.do(t, c.buildRegister(user, "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("challenge %d: got %d, want 401", i, res.StatusCode)
	}
	return c.do(t, c.buildRegister(user, "example.com", 600, digest(user, "abc123nonce", fmt.Sprintf("guess%d", i))), h.publicUDP).StatusCode
}

// A source whose credential attempts keep failing is banned past
// shield.register_ban, and its REGISTERs stop reaching the switch.
func TestRegisterGuardBansBruteForce(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "3/10m")
	setAuthStatus(h, 401)
	c := newUDPClient(t)

	for i := 0; i < 3; i++ {
		if code := challengeThenGuess(t, h, c, fmt.Sprintf("u%d", i), i); code != 401 {
			t.Fatalf("guess %d: got %d, want 401", i, code)
		}
		if bannedLoopback(h) {
			t.Fatalf("banned after %d failures; the threshold is 3", i+1)
		}
	}
	challengeThenGuess(t, h, c, "u3", 3)
	if !bannedLoopback(h) {
		t.Fatal("the 4th failed credential did not ban the source")
	}
	if n := authFailures(h); n != 4 {
		t.Errorf("register_auth_failures = %d, want 4", n)
	}
	page, _, _ := h.srv.Bans(10, 0)
	if len(page) != 1 || page[0].Reason != shield.BanReasonRegister {
		t.Errorf("bans = %+v", page)
	}

	before := len(h.fs.received(sip.REGISTER))
	expectSilence(t, c, c.buildRegister("u-next", "example.com", 600, ""), h.publicUDP)
	if got := len(h.fs.received(sip.REGISTER)); got != before {
		t.Fatalf("the switch saw %d REGISTERs after the ban, want %d", got, before)
	}
}

// rawUDP is a bare UDP socket on 127.0.0.1, for requests sipgo's client
// would not send (a credential retry on the challenged branch).
func rawUDP(t *testing.T) (*net.UDPConn, int) {
	t.Helper()
	port := nextPort(t)
	c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(guardSrc, uint16(port))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, port
}

func rawGuardRegister(port int, user, branch string, cseq int, auth string) []byte {
	msg := fmt.Sprintf("REGISTER sip:example.com SIP/2.0\r\n"+
		"Via: SIP/2.0/UDP 127.0.0.1:%d;rport;branch=%s\r\n"+
		"Max-Forwards: 70\r\n"+
		"From: <sip:%s@example.com>;tag=f%s\r\n"+
		"To: <sip:%s@example.com>\r\n"+
		"Call-ID: raw-%s@127.0.0.1\r\n"+
		"CSeq: %d REGISTER\r\n"+
		"Contact: <sip:%s@127.0.0.1:%d>\r\n"+
		"Expires: 600\r\n", port, branch, user, branch, user, branch, cseq, user, port)
	if auth != "" {
		msg += "Authorization: " + auth + "\r\n"
	}
	return []byte(msg + "Content-Length: 0\r\n\r\n")
}

// readFinal reads the next final response on c, or nil after wait.
func readFinal(t *testing.T, c *net.UDPConn, wait time.Duration) *sip.Response {
	t.Helper()
	buf := make([]byte, 8192)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		_ = c.SetReadDeadline(deadline)
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		msg, err := sip.ParseMessage(buf[:n])
		if err != nil {
			continue
		}
		if res, ok := msg.(*sip.Response); ok && res.StatusCode >= 200 {
			return res
		}
	}
	return nil
}

func sendRaw(t *testing.T, c *net.UDPConn, to string, b []byte) {
	t.Helper()
	if _, err := c.WriteToUDP(b, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(to))); err != nil {
		t.Fatal(err)
	}
}

// The scanner pattern seen in production: the credential retry reuses the
// challenged request's Via branch, so sipgo answers it with the cached 401
// and onRegister never runs. The read filter still counts it, and the
// source is banned.
func TestRegisterGuardCountsSameBranchReplay(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "3/10m")
	c, port := rawUDP(t)

	for i := 0; i < 4; i++ {
		branch := fmt.Sprintf("z9hG4bK-replay-%d", i)
		sendRaw(t, c, h.publicUDP, rawGuardRegister(port, "100", branch, 1, ""))
		if res := readFinal(t, c, 5*time.Second); res == nil || res.StatusCode != 401 {
			t.Fatalf("cycle %d: challenge = %v, want 401", i, res)
		}
		upstream := len(h.fs.received(sip.REGISTER))
		sendRaw(t, c, h.publicUDP, rawGuardRegister(port, "100", branch, 2, digest("100", "abc123nonce", fmt.Sprintf("g%d", i))))
		res := readFinal(t, c, 2*time.Second)
		if i < 3 && (res == nil || res.StatusCode != 401) {
			t.Fatalf("cycle %d: replayed answer = %v, want the cached 401", i, res)
		}
		if got := len(h.fs.received(sip.REGISTER)); got != upstream {
			t.Fatalf("cycle %d: the replay reached the switch (%d REGISTERs, want %d)", i, got, upstream)
		}
		if n := authFailures(h); n != uint64(i+1) {
			t.Fatalf("cycle %d: register_auth_failures = %d, want %d", i, n, i+1)
		}
	}
	if !bannedLoopback(h) {
		t.Fatal("4 replayed guesses over a 3/10m threshold did not ban the source")
	}
	before := len(h.fs.received(sip.REGISTER))
	sendRaw(t, c, h.publicUDP, rawGuardRegister(port, "100", "z9hG4bK-after", 1, ""))
	if res := readFinal(t, c, silenceWait); res != nil {
		t.Fatalf("banned source got %d", res.StatusCode)
	}
	if got := len(h.fs.received(sip.REGISTER)); got != before {
		t.Fatalf("the switch saw %d REGISTERs after the ban, want %d", got, before)
	}
}

// A UDP retransmission of one failed attempt counts once.
func TestRegisterGuardRetransmissionCountsOnce(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "1/10m")
	setAuthStatus(h, 401)
	c, port := rawUDP(t)

	sendRaw(t, c, h.publicUDP, rawGuardRegister(port, "200", "z9hG4bK-ch", 1, ""))
	if res := readFinal(t, c, 5*time.Second); res == nil || res.StatusCode != 401 {
		t.Fatalf("challenge = %v, want 401", res)
	}
	attempt := rawGuardRegister(port, "200", "z9hG4bK-try", 2, digest("200", "abc123nonce", "wrong"))
	sendRaw(t, c, h.publicUDP, attempt)
	if res := readFinal(t, c, 5*time.Second); res == nil || res.StatusCode != 401 {
		t.Fatalf("attempt = %v, want 401", res)
	}
	for i := 0; i < 3; i++ {
		sendRaw(t, c, h.publicUDP, attempt) // answered from the transaction
		readFinal(t, c, 500*time.Millisecond)
	}
	if n := authFailures(h); n != 1 {
		t.Errorf("register_auth_failures = %d, want 1", n)
	}
	if bannedLoopback(h) {
		t.Error("one failed attempt and its retransmissions banned a 1/10m source")
	}
}

// Healthy 401 -> 200 registrations never count, however many accounts one
// source registers, and a 2xx clears earlier failures.
func TestRegisterGuardHealthyRegistrationsNeverCount(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "1/10m")
	c := newUDPClient(t)
	for i := 0; i < 15; i++ {
		user := fmt.Sprintf("ok%d", i)
		if res := c.do(t, c.buildRegister(user, "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
			t.Fatalf("%s challenge: %d", user, res.StatusCode)
		}
		if res := c.do(t, c.buildRegister(user, "example.com", 600, digest(user, "abc123nonce", "right")), h.publicUDP); res.StatusCode != 200 {
			t.Fatalf("%s: got %d, want 200", user, res.StatusCode)
		}
	}
	if n := authFailures(h); n != 0 || bannedLoopback(h) {
		t.Fatalf("healthy registrations: %d strikes, banned=%v", n, bannedLoopback(h))
	}

	// One failure, then a success: the count is cleared, so another
	// failure does not cross a 1/10m threshold.
	setAuthStatus(h, 403)
	if code := challengeThenGuess(t, h, c, "mixed", 0); code != 403 {
		t.Fatalf("guess: %d", code)
	}
	setAuthStatus(h, 0)
	if res := c.do(t, c.buildRegister("ok0", "example.com", 600, digest("ok0", "abc123nonce", "right")), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("success: %d", res.StatusCode)
	}
	setAuthStatus(h, 403)
	challengeThenGuess(t, h, c, "mixed", 1)
	if bannedLoopback(h) {
		t.Fatal("a 2xx did not clear the source's strikes")
	}
	if n := authFailures(h); n != 2 {
		t.Errorf("register_auth_failures = %d, want 2", n)
	}
}

// A registered client refreshing its binding (same AoR and Call-ID, from a
// new source port) is never struck, even when the registrar refuses the
// refresh.
func TestRegisterGuardRefreshOfLiveBindingExempt(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "1/10m")
	c := newUDPClient(t)
	if res := c.do(t, c.buildRegister("1001", "example.com", 600, ""), h.publicUDP); res.StatusCode != 401 {
		t.Fatalf("challenge: %d", res.StatusCode)
	}
	if res := c.do(t, c.buildRegister("1001", "example.com", 600, digest("1001", "abc123nonce", "right")), h.publicUDP); res.StatusCode != 200 {
		t.Fatalf("register: %d", res.StatusCode)
	}

	setAuthStatus(h, 401)
	moved := newUDPClient(t) // the phone's NAT mapping changed: a new source port
	for i := 0; i < 5; i++ {
		res := moved.do(t, moved.buildRegister("1001", "example.com", 600, digest("1001", "abc123nonce", fmt.Sprintf("r%d", i))), h.publicUDP)
		if res.StatusCode != 401 {
			t.Fatalf("refresh %d: got %d, want 401", i, res.StatusCode)
		}
	}
	if n := authFailures(h); n != 0 || bannedLoopback(h) {
		t.Fatalf("refreshes of a live binding: %d strikes, banned=%v", n, bannedLoopback(h))
	}
}

// A carrier source is never struck or banned.
func TestRegisterGuardCarrierSourceNeverBanned(t *testing.T) {
	h := startHarness(t, false) // 127.0.0.1 is a carrier source
	setRegisterBan(h, "1/10m")
	setAuthStatus(h, 401)
	c := newUDPClient(t)
	for i := 0; i < 5; i++ {
		challengeThenGuess(t, h, c, fmt.Sprintf("c%d", i), i)
	}
	if n := authFailures(h); n != 0 || bannedLoopback(h) {
		t.Fatalf("carrier source: %d strikes, banned=%v", n, bannedLoopback(h))
	}
}

// An attempt whose nonce was never relayed to its source does not count:
// a forger that never saw the challenge cannot strike the address it
// claims.
func TestRegisterGuardUnissuedNonceNeverCounts(t *testing.T) {
	h := startHarnessStrict(t, false, false)
	setRegisterBan(h, "1/10m")
	setAuthStatus(h, 401)
	c := newUDPClient(t)
	for i := 0; i < 5; i++ {
		res := c.do(t, c.buildRegister(fmt.Sprintf("f%d", i), "example.com", 600, digest("x", "forged-nonce", "r")), h.publicUDP)
		if res.StatusCode != 401 {
			t.Fatalf("attempt %d: %d", i, res.StatusCode)
		}
	}
	if n := authFailures(h); n != 0 || bannedLoopback(h) {
		t.Fatalf("unissued nonces: %d strikes, banned=%v", n, bannedLoopback(h))
	}
}

// Unit: the guard counts only nonces issued to the same source key, counts
// an attempt once, honours the replay window and the nonce TTL, and stays
// within its cap under a many-source flood.
func TestRegGuardCountable(t *testing.T) {
	g := newRegGuard()
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	a, b := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("198.51.100.2")

	if g.countable(a, "br", "n1", 1, false) {
		t.Fatal("a source never challenged was countable")
	}
	g.challenged(a, "br", []string{"n1"})
	if g.countable(b, "br", "n1", 1, false) {
		t.Fatal("another source's nonce was countable")
	}
	if g.countable(a, "br", "n2", 1, false) {
		t.Fatal("an unissued nonce was countable")
	}
	if !g.countable(a, "br", "n1", 1, true) {
		t.Fatal("a replay on the challenged branch was not countable")
	}
	if g.countable(a, "br", "n1", 1, false) {
		t.Fatal("the same attempt counted twice")
	}
	if !g.countable(a, "br2", "n1", 2, false) {
		t.Fatal("a new attempt was not countable")
	}
	if g.countable(a, "other", "n1", 3, true) {
		t.Fatal("a replay on an unchallenged branch was countable")
	}
	now = now.Add(regReplayWindow)
	if g.countable(a, "br", "n1", 4, true) {
		t.Fatal("a replay after the transaction's life was countable")
	}
	if !g.countable(a, "br", "n1", 5, false) {
		t.Fatal("a forwarded attempt within the nonce TTL was not countable")
	}
	now = now.Add(regNonceTTL)
	if g.countable(a, "br", "n1", 6, false) {
		t.Fatal("an expired nonce was countable")
	}
	// IPv6 sources share a /64.
	g.challenged(netip.MustParseAddr("2001:db8::1"), "v6", []string{"n6"})
	if !g.countable(netip.MustParseAddr("2001:db8::2"), "v6", "n6", 1, false) {
		t.Fatal("a nonce issued within the /64 was not countable")
	}
}

func TestRegGuardCapped(t *testing.T) {
	g := newRegGuard()
	g.max = 128
	for i := 0; i < 10000; i++ {
		g.challenged(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), "b", []string{"n"})
	}
	if n := g.size(); n != 128 {
		t.Errorf("guard holds %d sources, want the cap 128", n)
	}
}

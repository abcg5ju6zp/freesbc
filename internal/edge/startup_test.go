package edge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/freesbc/freesbc/internal/config"
	fsip "github.com/freesbc/freesbc/internal/sip"
)

// regression: edge startup race
//
// Run used to close Ready as soon as it had started the goroutines serving
// its listeners, but sipgo adds a UDP listener to its connection pool only
// from inside that goroutine. A phone INVITE arriving in between was
// forwarded upstream pinned to the private bind's address, missed the pool,
// and made sipgo bind a second socket there ("address already in use"):
// the phone got a 503. The harness starts the proxy and waits for Ready
// and nothing else; the very first INVITE must be forwarded.
func TestFirstInviteAfterReadyIsForwarded(t *testing.T) {
	h := startHarness(t, false)
	phone := newUDPClient(t)
	invite := phone.buildInvite("1001", "2002", "example.com", phoneOfferSDP(40000))
	res := phone.do(t, invite, h.publicUDP)
	if res.StatusCode != 200 {
		t.Fatalf("first INVITE after Ready: got %d %s, want 200", res.StatusCode, res.Reason)
	}
	sendAck(t, phone, invite, res, h.publicUDP)
}

// audit: P2-APP-005
// The admin call list and the active-call count describe the same set: a
// confirmed edge dialog is listed, not only counted.
func TestCallsListsWhatActiveCallsCounts(t *testing.T) {
	h := startHarness(t, false)
	h.fs.setInviteHook(auditTaggedAnswerHook(h.fs, nil, nil))
	settle()

	// Registered, so the phone is a client even though the shared harness
	// also lists 127.0.0.1 as a carrier source (a registration wins).
	phone := newUDPClient(t)
	auditRegisterPhone(t, h, phone, "1001")
	invite, res, _ := auditPhoneCall(t, h, phone)
	waitForDialog(t, h, fsip.CallID(invite))

	calls := h.srv.Calls()
	if n := h.srv.ActiveCalls(); n != 1 || len(calls) != 1 {
		t.Fatalf("ActiveCalls = %d, Calls lists %d; want 1 and 1", n, len(calls))
	}
	c := calls[0]
	if c.CallID != fsip.CallID(invite) || c.From != "edge:public" || c.To != "edge:private" || c.StartUnixNano == 0 {
		t.Errorf("call record = %+v, want the phone's Call-ID, edge:public → edge:private and a start time", c)
	}
	if r := phone.do(t, buildBye(phone, invite, res), h.publicUDP); r.StatusCode != 200 {
		t.Errorf("BYE: %d", r.StatusCode)
	}
	waitForRelease(t, h)
	if n := len(h.srv.Calls()); n != 0 {
		t.Errorf("after BYE Calls lists %d, want 0", n)
	}
}

// Run refuses to start when public.bind or the effective private IP is not
// assigned to a local interface, naming the key, before binding anything.
func TestRunFailsOnNonLocalAddress(t *testing.T) {
	for name, tc := range map[string]struct {
		public, private string
		want            string
	}{
		"public.bind": {public: "192.0.2.77", private: "192.0.2.250", want: "public.bind 192.0.2.77"},
		"private.ip":  {public: "127.0.0.1", private: "192.0.2.250", want: "private.ip 192.0.2.250"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(fmt.Sprintf(
				"public: {ip: %s}\nprivate: {ip: %s}\nedge:\n  switch: [10.77.0.10:5060]\n  listen: {udp: %d}\n",
				tc.public, tc.private, nextPort(t))))
			if err != nil {
				t.Fatal(err)
			}
			srv, err := New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			err = srv.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "not assigned to any local interface") {
				t.Fatalf("Run = %v, want a %q local-interface error", err, tc.want)
			}
		})
	}
}

// WithPrivateAddr is the test seam: it replaces the fixed private.ip:5060
// for the socket, the advertised side and the private media address, and
// Listeners reports the effective socket.
func TestWithPrivateAddrOverridesFixedSocket(t *testing.T) {
	h := startHarness(t, false)
	topo := h.srv.topo
	if got := topo.private.advIP.String() + ":" + strconv.Itoa(topo.private.advPort); got != h.privateSIP {
		t.Errorf("private side = %s, want %s", got, h.privateSIP)
	}
	if topo.privateMediaIP.String() != "127.0.0.1" {
		t.Errorf("private media IP = %v, want the override's IP", topo.privateMediaIP)
	}
	var found bool
	for _, l := range h.srv.Listeners() {
		if l == "udp://"+h.privateSIP+" (private)" {
			found = true
		}
	}
	if !found {
		t.Errorf("Listeners() = %v, want the private socket %s", h.srv.Listeners(), h.privateSIP)
	}
	// Without the option the socket is the fixed private.ip:5060.
	cfg := h.store.Current()
	plain, err := New(config.NewStore(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.shield.Close() })
	if plain.privAddr != netip.MustParseAddrPort(harnessPrivatePlaceholder+":5060") {
		t.Errorf("default private socket = %v", plain.privAddr)
	}
}

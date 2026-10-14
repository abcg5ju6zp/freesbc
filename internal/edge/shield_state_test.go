package edge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"github.com/freesbc/freesbc/internal/shield"
)

func stateGateYAML(tcpPort, mediaBase int) string {
	return fmt.Sprintf(`
public: {ip: 127.0.0.1}
private: {ip: %s}
rtp: "%d-%d"
edge:
  switch: [127.0.0.1:5999]
  listen: {tcp: %d}
`, harnessPrivatePlaceholder, mediaBase, mediaBase+398, tcpPort) + "shield:\n  rate_limit: \"5000/s per_ip\"\n  carrier_rate_limit: \"5000/s per_ip\"\n"
}

// A corrupt shield snapshot is fail-closed: the edge reports the fatal
// recovery status, opens no listener, and stays up so the status is
// queryable; after the state files are removed a fresh start binds normally.
func TestEdgeShieldCorruptStateClosesNoListener(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "shield.state")

	// Produce a valid signed snapshot with the shield package directly.
	pre, err := config.Parse([]byte(`
public: { ip: 127.0.0.1 }
private: { ip: 127.0.0.2 }
edge:
  switch: [127.0.0.1:5999]
  listen: { udp: 5060 }
`))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	preShield := shield.New(config.NewStore(pre), log, nil, shield.WithStateFile(statePath))
	preShield.Check(netip.MustParseAddr("198.51.100.77"), "sipvicious", "tcp")
	if err := preShield.Close(); err != nil {
		t.Fatal(err)
	}

	// Corrupt the file inside its signed payload.
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-260] ^= 0xff
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	priv := freeTCPPort(t)
	tcpPort := freeTCPPort(t)
	cfg, err := config.Parse([]byte(stateGateYAML(tcpPort, 28000)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Shield.StateFile = statePath
	srv, err := New(config.NewStore(cfg), log,
		WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", priv))))
	if err != nil {
		t.Fatal(err)
	}
	st := srv.ShieldState()
	if st.Phase != shield.PhaseFatal || st.FatalError == "" {
		t.Fatalf("recovery status = %+v, want fatal", st)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		err := srv.Run(ctx)
		if err != nil {
			t.Errorf("fatal-gate Run returned an error: %v", err)
		}
		close(done)
	}()

	// Nothing may bind while the gate is shut: the TCP port stays free and
	// ready never closes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ln, lerr := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
		if lerr == nil {
			_ = ln.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-srv.ready:
		t.Fatal("ready closed despite a fatal shield recovery")
	case <-time.After(300 * time.Millisecond):
	}
	if ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort)); err != nil {
		t.Fatalf("edge bound its public listener under fatal recovery: %v", err)
	} else {
		_ = ln.Close()
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fatal-gate Run did not stop on cancel")
	}

	// Repair: quarantine and key removed, a fresh start is "empty" and binds.
	if matches, _ := filepath.Glob(filepath.Join(dir, "shield.state.corrupt-*")); len(matches) != 1 {
		t.Fatalf("quarantine = %v", matches)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	cfg2, err := config.Parse([]byte(stateGateYAML(tcpPort, 28400)))
	if err != nil {
		t.Fatal(err)
	}
	cfg2.Shield.StateFile = filepath.Join(dir, "shield.state")
	srv2, err := New(config.NewStore(cfg2), log,
		WithPrivateAddr(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", priv))))
	if err != nil {
		t.Fatal(err)
	}
	if st := srv2.ShieldState(); st.Phase != shield.PhaseEmpty {
		t.Fatalf("fresh state dir = %+v, want empty", st)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		_ = srv2.Run(ctx2)
		close(done2)
	}()
	select {
	case <-srv2.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the repaired edge never became ready")
	}
	// Shut down and wait for the final snapshot write before the temp
	// directory is removed.
	cancel2()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("the repaired edge did not stop")
	}
}

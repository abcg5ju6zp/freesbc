package shield

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

const stateTestCfg = `
public: { ip: 203.0.113.7 }
private: { ip: 10.77.0.2 }
edge:
  switch: [10.77.0.10:5060]
  listen: { udp: 5060 }
shield:
  rate_limit: 2/s per_ip
  carrier_rate_limit: 3/s per_ip
  ban: 1h
  register_ban: 2/10m
  admission_ban: 2/1m
`

func stateCfgStore(t *testing.T, yaml string) *config.Store {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return config.NewStore(cfg)
}

// newStateShield builds a persistence-enabled shield over a shared clock.
func newStateShield(t *testing.T, path, yaml string, now func() time.Time, isCarrier func(netip.Addr) bool) *Shield {
	t.Helper()
	s := New(stateCfgStore(t, yaml), discard(), isCarrier, WithStateFile(path), WithClock(now))
	t.Cleanup(func() { s.Close() })
	return s
}

func activeGen(s *Shield) string { return string(s.generation()) }

// With no state file configured, nothing touches the disk and the status
// is disabled.
func TestStateDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	s := newStateShield(t, "", stateTestCfg, time.Now, nil)
	st := s.State()
	if st.Enabled || st.Phase != PhaseDisabled || st.RecoveryResult != ResultDisabled {
		t.Fatalf("status = %+v, want disabled", st)
	}
	if st.ActiveGeneration == "" {
		t.Fatal("disabled status still carries the active generation")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("disabled persistence created files: %v", entries)
	}
}

// First start with no snapshot is "empty" and creates the HMAC key; a save
// writes one signed file.
func TestStateEmptyBootstrapAndKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "shield.state")
	now := time.Unix(1_800_000_000, 0)
	s := newStateShield(t, path, stateTestCfg, func() time.Time { return now }, nil)
	st := s.State()
	if st.Phase != PhaseEmpty || st.RecoveryResult != ResultEmpty || !st.Enabled {
		t.Fatalf("status = %+v, want empty", st)
	}
	key, err := os.ReadFile(path + ".key")
	if err != nil || len(key) != keySize {
		t.Fatalf("key file: %v len=%d", err, len(key))
	}
	info, err := os.Stat(path)
	if !os.IsNotExist(err) {
		t.Fatalf("state file exists before any save: %v %v", info, err)
	}
	s.Check(netip.MustParseAddr("198.51.100.5"), "sipvicious", "tcp")
	s.saveSnapshot(false)
	st = s.State()
	if st.SavesOK != 1 || st.LastSaveError != "" {
		t.Fatalf("save status = %+v", st)
	}
	if raw, err := os.ReadFile(path); err != nil || !strings.Contains(string(raw), stateFormat) {
		t.Fatalf("state file not written: %v (%d bytes)", err, len(raw))
	}
}

// Build live state of every kind under gen g1, close it, and reopen with the
// same config: the same-generation snapshot restores everything, with the
// original deadlines.
func TestStateRoundTripSameGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.state")
	now := time.Unix(1_800_000_000, 0)
	clk := func() time.Time { return now }

	tcpIP := netip.MustParseAddr("198.51.100.10")
	sock := netip.MustParseAddrPort("198.51.100.11:5060")
	udpIP := netip.MustParseAddr("198.51.100.12")
	regIP := netip.MustParseAddr("198.51.100.13")
	drained := netip.MustParseAddr("198.51.100.14")

	s1 := newStateShield(t, path, stateTestCfg, clk, nil)
	g1 := activeGen(s1)
	s1.Check(tcpIP, "sipvicious", "tcp")    // ip ban
	s1.CheckFrom(sock, "sipvicious", "udp") // udp_socket ban
	for i := 0; i < 3; i++ {                // 2/1m: third strike bans udp_ip
		s1.StrikeOn(udpIP, StrikeAdmission, "udp")
	}
	s1.Strike(regIP, StrikeRegister)
	s1.Strike(regIP, StrikeRegister)
	// Drain one public rate bucket: 2/s, three checks, the third drops.
	for i := 0; i < 3; i++ {
		s1.AllowRate(drained)
	}
	if s1.AllowRate(drained) {
		t.Fatal("drained bucket should refuse at t0")
	}
	s1.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.ActiveGeneration != g1 {
		t.Fatalf("file generation %q != %q", env.ActiveGeneration, g1)
	}

	s2 := newStateShield(t, path, stateTestCfg, clk, nil)
	st := s2.State()
	if st.Phase != PhaseRestored || st.RecoveryResult != ResultSameGeneration || st.SnapshotGeneration != g1 {
		t.Fatalf("status = %+v", st)
	}
	if st.Restored.IPBans != 1 || st.Restored.UDPIPBans != 1 || st.Restored.UDPSocketBans != 1 ||
		st.Restored.Offenders != 2 || st.Restored.Buckets < 1 || st.ExpiredSkipped != 0 {
		t.Fatalf("restored counts = %+v", st.Restored)
	}
	if !s2.BannedFrom(netip.AddrPortFrom(tcpIP, 9999), "tcp") {
		t.Error("ip ban did not survive restart")
	}
	if !s2.BannedFrom(sock, "udp") {
		t.Error("udp socket ban did not survive restart")
	}
	if s2.BannedFrom(netip.AddrPortFrom(udpIP, 1), "tcp") || !s2.BannedFrom(netip.AddrPortFrom(udpIP, 1), "udp") {
		t.Error("udp_ip ban scope did not survive restart")
	}
	// The restored strike window keeps counting: two strikes restored, the
	// third (threshold 2) bans under the same rules.
	if !s2.Strike(regIP, StrikeRegister) || !s2.Banned(regIP) {
		t.Fatal("restored offender window did not continue under its rules")
	}
	page, _ := s2.Bans(100, 0)
	for _, b := range page {
		if b.Generation != g1 {
			t.Errorf("restored ban %s has generation %q, want %q", b.Source, b.Generation, g1)
		}
		if b.Kind == BanKindIP && b.Source == tcpIP.String() && b.Until.Sub(b.Since) != time.Hour {
			t.Errorf("ban deadline changed across restart: %s", b.Until.Sub(b.Since))
		}
	}
	if top, total := s2.Offenders(100); total < 1 {
		t.Errorf("offenders not restored: %d", total)
	} else {
		for _, o := range top {
			if o.Generation != g1 {
				t.Errorf("offender generation %q", o.Generation)
			}
		}
	}
	// The drained bucket is still empty at the same wall time.
	if s2.AllowRate(drained) {
		t.Error("a drained rate bucket restarted full")
	}
	now = now.Add(time.Second)
	if !s2.AllowRate(drained) {
		t.Error("the bucket did not resume refilling after the restart")
	}
}

// Records past their deadline at recovery are dropped (counted), never loaded.
func TestStateExpiredRecordsSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.state")
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	clk := func() time.Time { return now }
	s1 := newStateShield(t, path, stateTestCfg, clk, nil)
	live := netip.MustParseAddr("198.51.100.20")
	dead := netip.MustParseAddr("198.51.100.21")
	s1.bans.ban(live, time.Hour, BanReasonScanner, activeGen(s1))
	s1.bans.ban(dead, time.Minute, BanReasonScanner, activeGen(s1))
	s1.Close()

	now = t0.Add(2 * time.Minute) // dead lapsed, live still in force
	s2 := newStateShield(t, path, stateTestCfg, clk, nil)
	st := s2.State()
	if st.Restored.IPBans != 1 || st.ExpiredSkipped != 1 {
		t.Fatalf("counts = %+v expired=%d", st.Restored, st.ExpiredSkipped)
	}
	if s2.Banned(dead) || !s2.Banned(live) {
		t.Fatal("expiry by the original deadline was not respected")
	}
}

// Rules changed while the process was down: the snapshot's generation is
// older. Old state restores and stays in force; new state starts under the
// new generation.
func TestStateStaleGenerationAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.state")
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	clk := func() time.Time { return now }

	s1 := newStateShield(t, path, stateTestCfg, clk, nil)
	g1 := activeGen(s1)
	old := netip.MustParseAddr("198.51.100.30")
	s1.Check(old, "sipvicious", "tcp") // banned for 1h under g1
	s1.Close()

	cfg2 := strings.Replace(stateTestCfg, "ban: 1h", "ban: 1m", 1)
	s2 := newStateShield(t, path, cfg2, clk, nil)
	g2 := activeGen(s2)
	if g1 == g2 {
		t.Fatal("changing ban duration did not change the generation")
	}
	st := s2.State()
	if st.RecoveryResult != ResultStaleGeneration || len(st.StaleGenerations) != 1 || st.StaleGenerations[0] != g1 {
		t.Fatalf("status = %+v", st)
	}
	page, _ := s2.Bans(100, 0)
	if len(page) != 1 || page[0].Generation != g1 || page[0].Until.Sub(page[0].Since) != time.Hour {
		t.Fatalf("old ban = %+v, want the 1h g1 entry", page)
	}
	// The old entry still protects, and a new ban runs under g2 for 1m.
	if !s2.Banned(old) {
		t.Fatal("the stale-generation ban stopped protecting")
	}
	newSrc := netip.MustParseAddr("198.51.100.31")
	s2.Check(newSrc, "sipvicious", "tcp")
	page, _ = s2.Bans(100, 0)
	var foundOld, foundNew bool
	for _, b := range page {
		if b.Source == old.String() && b.Generation == g1 && b.Until.Sub(b.Since) == time.Hour {
			foundOld = true
		}
		if b.Source == newSrc.String() && b.Generation == g2 && b.Until.Sub(b.Since) == time.Minute {
			foundNew = true
		}
	}
	if !foundOld || !foundNew {
		t.Fatalf("generations not kept apart: %+v", page)
	}
}

// A hot threshold change freezes the old window on its own rules while new
// strikes open a new-generation window.
func TestStateHotReloadKeepsOldWindowRules(t *testing.T) {
	s := testShield(t, stateTestCfg)
	store := s.store
	src := netip.MustParseAddr("198.51.100.40")
	g1 := activeGen(s)
	s.Strike(src, StrikeRegister)
	s.Strike(src, StrikeRegister) // window at the threshold, not over
	if s.Banned(src) {
		t.Fatal("at the threshold must not ban")
	}

	next := *store.Current()
	next.Shield.RegisterBan = "100/10m"
	store.Replace(&next)
	g2 := activeGen(s)
	if g1 == g2 {
		t.Fatal("reload did not advance the generation")
	}
	s.Strike(src, StrikeRegister) // g2 window: count 1 of 100
	if s.Banned(src) {
		t.Fatal("a strike under the relaxed new rules must not use the old window")
	}
	top, total := s.Offenders(100)
	if total != 2 {
		t.Fatalf("want one window per generation (2), got %d: %+v", total, top)
	}

	// Tightening the rules only affects the new generation: a source with a
	// relaxed g2 count is not retroactively banned, but strikes under the
	// new 1/10m threshold open a fresh window and ban on the second one.
	next = *store.Current()
	next.Shield.RegisterBan = "1/10m"
	store.Replace(&next)
	g3 := activeGen(s)
	if g3 == g2 {
		t.Fatal("tightening the threshold did not advance the generation")
	}
	if s.Strike(src, StrikeRegister) {
		t.Fatal("the first g3 strike is count 1 of 1, not over")
	}
	if !s.Strike(src, StrikeRegister) || !s.Banned(src) {
		t.Fatal("the tightened new-generation threshold did not ban")
	}
	// g1 window still reads 2 (never re-interpreted under g2/g3 rules).
	for _, o := range s.OffendersAll() {
		if o.key.gen == g1 && o.count != 2 {
			t.Errorf("old window count changed to %d", o.count)
		}
		if o.key.gen == g1 && o.n != 2 {
			t.Errorf("old window threshold changed to %d", o.n)
		}
	}
}

// OffendersAll returns every window (test helper).
func (s *Shield) OffendersAll() []offender { return s.offenders.live() }

// A ban-duration change never moves an existing ban's deadline.
func TestStateBanDurationChangeKeepsDeadline(t *testing.T) {
	s := testShield(t, stateTestCfg)
	src := netip.MustParseAddr("198.51.100.41")
	g1 := activeGen(s)
	s.Check(src, "sipvicious", "tcp")
	next := *s.store.Current()
	next.Shield.Ban = config.Duration(time.Minute)
	s.store.Replace(&next)
	g2 := activeGen(s)
	page, _ := s.Bans(10, 0)
	if len(page) != 1 || page[0].Generation != g1 || page[0].Until.Sub(page[0].Since) != time.Hour {
		t.Fatalf("old ban moved: %+v", page)
	}
	// A fresh ban on another source uses g2 and the new duration.
	src2 := netip.MustParseAddr("198.51.100.42")
	s.Check(src2, "sipvicious", "tcp")
	page, _ = s.Bans(10, 0)
	byGen := map[string]BanInfo{}
	for _, b := range page {
		byGen[b.Generation] = b
	}
	if byGen[g1].Until.Sub(byGen[g1].Since) != time.Hour || byGen[g2].Until.Sub(byGen[g2].Since) != time.Minute {
		t.Fatalf("deadlines = %v / %v", byGen[g1].Until.Sub(byGen[g1].Since), byGen[g2].Until.Sub(byGen[g2].Since))
	}
}

// Explicit unbans act only on the named generation.
func TestUnbanMatchesGeneration(t *testing.T) {
	s := testShield(t, stateTestCfg)
	a, b := netip.MustParseAddr("198.51.100.50"), netip.MustParseAddr("198.51.100.51")
	g1 := activeGen(s)
	s.bans.ban(a, time.Hour, BanReasonScanner, g1)
	s.bans.ban(b, time.Hour, BanReasonScanner, g1)
	next := *s.store.Current()
	next.Shield.Ban = config.Duration(2 * time.Hour)
	s.store.Replace(&next)
	g2 := activeGen(s)
	// Same source under both generations.
	s.bans.ban(a, 2*time.Hour, BanReasonScanner, g2)

	if ok, err := s.Unban(BanKindIP, a.String(), g2); err != nil || !ok {
		t.Fatalf("unban g2: %v %v", ok, err)
	}
	if !s.Banned(a) {
		t.Fatal("unbanning the new generation must not release the old-generation ban")
	}
	if ok, _ := s.Unban(BanKindIP, a.String(), g1); !ok || s.Banned(a) {
		t.Fatal("matching-generation unban did not release the old ban")
	}
	// Missing generation is a clean miss.
	if ok, err := s.Unban(BanKindIP, b.String(), g2); err != nil || ok {
		t.Fatalf("unban of a generation with no entry = %v %v, want false, nil", ok, err)
	}
	if ok, _ := s.Unban(BanKindIP, b.String(), g1); !ok {
		t.Fatal("exact generation unban failed")
	}
	for _, bad := range []struct {
		kind, source, gen string
	}{
		{"nope", b.String(), g1},
		{BanKindIP, "not-an-ip", g1},
		{BanKindUDPSocket, "1.2.3.4", g1}, // not host:port
		{BanKindIP, b.String(), ""},
	} {
		if _, err := s.Unban(bad.kind, bad.source, bad.gen); err == nil {
			t.Errorf("Unban(%v) returned no error", bad)
		}
	}
}

// Public and carrier rate buckets are physically separate, and a carrier
// bucket drained before a restart stays drained after it.
func TestStateCarrierAndPublicBucketsSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.state")
	now := time.Unix(1_800_000_000, 0)
	clk := func() time.Time { return now }
	carrier := netip.MustParseAddr("192.0.2.66")
	isCarrier := func(ip netip.Addr) bool { return ip == carrier }

	s1 := newStateShield(t, path, stateTestCfg, clk, isCarrier)
	// carrier limit is 3/s: three allowed, fourth dropped.
	for i := 0; i < 3; i++ {
		if !s1.AllowRate(carrier) {
			t.Fatalf("carrier token %d refused", i)
		}
	}
	if s1.AllowRate(carrier) {
		t.Fatal("carrier bucket did not drain")
	}
	// No public source is charged at all: the two limiters never share a
	// bucket, so nothing public must cross the restart either.
	s1.Close()

	s2 := newStateShield(t, path, stateTestCfg, clk, isCarrier)
	if s2.AllowRate(carrier) {
		t.Fatal("carrier bucket restarted full")
	}
	foundCarrier := false
	for _, b := range s2.limCarrier.drained() {
		if b.Src == bucketKeyFor(carrier) {
			foundCarrier = true
		}
	}
	if !foundCarrier {
		t.Error("carrier bucket was not restored into the carrier limiter")
	}
	if len(s2.limPublic.drained()) != 0 {
		t.Error("carrier state leaked into the public limiter")
	}
	// A public source keeps the independent 2/s public budget.
	pub := netip.MustParseAddr("198.51.100.66")
	if !s2.AllowRate(pub) {
		t.Fatal("public/carrier budget leaked across scopes")
	}
}

// A byte-flip of the file fails HMAC: the snapshot is quarantined, nothing
// loads, and the status is the fatal fail-closed result.
func TestStateCorruptFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shield.state")
	t0 := time.Unix(1_800_000_000, 0)
	now := t0
	clk := func() time.Time { return now }
	s1 := newStateShield(t, path, stateTestCfg, clk, nil)
	ip := netip.MustParseAddr("198.51.100.70")
	s1.Check(ip, "sipvicious", "tcp")
	s1.Close()

	raw, _ := os.ReadFile(path)
	raw[len(raw)-260] ^= 0xff // inside the base64 payload
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newStateShield(t, path, stateTestCfg, clk, nil)
	st := s2.State()
	if st.Phase != PhaseFatal || st.RecoveryResult != ResultFatal || st.FatalError == "" {
		t.Fatalf("status = %+v, want fatal", st)
	}
	if s2.Banned(ip) {
		t.Fatal("a corrupt snapshot must not load any state")
	}
	if st.Restored != (RestoredCounts{}) {
		t.Fatalf("nothing should be restored, got %+v", st.Restored)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "shield.state.corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("quarantine file missing: %v", matches)
	}
	// Writes are disarmed after a fatal recovery.
	s2.markDirty()
	s2.saveSnapshot(false)
	if st := s2.State(); st.SavesFailed != 0 || st.SavesOK != 0 {
		t.Fatalf("a fatal plane must not rewrite state: %+v", st)
	}
}

// A validly signed but semantically invalid record (bad IP) is corruption.
func TestStateSignedButInvalidRecordIsFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shield.state")
	t0 := time.Unix(1_800_000_000, 0)
	clk := func() time.Time { return t0 }
	s1 := newStateShield(t, path, stateTestCfg, clk, nil)
	g1 := activeGen(s1)
	s1.bans.ban(netip.MustParseAddr("198.51.100.71"), time.Hour, BanReasonScanner, g1)
	s1.Close()

	// Re-sign a payload with a syntactically invalid address.
	key, err := os.ReadFile(path + ".key")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	var data snapshotData
	if err := json.Unmarshal(payload, &data); err != nil {
		t.Fatal(err)
	}
	data.IPBans[0].Key = "not-an-ip"
	payload, _ = json.Marshal(&data)
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	env.Sig = hex.EncodeToString(mac.Sum(nil))
	signed, _ := json.MarshalIndent(&env, "", "  ")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newStateShield(t, path, stateTestCfg, clk, nil)
	if st := s2.State(); st.Phase != PhaseFatal || !strings.Contains(st.FatalError, "ban record") {
		t.Fatalf("status = %+v, want a fatal record-validation error", st)
	}
}

// A missing key file with a state file present is unverifiable and fatal.
func TestStateMissingKeyIsFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.state")
	now := time.Unix(1_800_000_000, 0)
	s1 := newStateShield(t, path, stateTestCfg, func() time.Time { return now }, nil)
	s1.Check(netip.MustParseAddr("198.51.100.72"), "sipvicious", "tcp")
	s1.Close()
	if err := os.Remove(path + ".key"); err != nil {
		t.Fatal(err)
	}
	s2 := newStateShield(t, path, stateTestCfg, func() time.Time { return now }, nil)
	if st := s2.State(); st.Phase != PhaseFatal || !strings.Contains(st.FatalError, "key") {
		t.Fatalf("status = %+v, want a fatal key error", st)
	}
}

// A write failure after a successful start is queryable, non-fatal, and the
// next attempt retries successfully.
func TestStateWriteFailureRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shield.state")
	now := time.Unix(1_800_000_000, 0)
	clk := func() time.Time { return now }
	s := newStateShield(t, path, stateTestCfg, clk, nil)
	if st := s.State(); st.Phase != PhaseEmpty {
		t.Fatalf("phase = %s", st.Phase)
	}
	// Turn the snapshot path itself into a directory: the atomic rename
	// then fails, independent of the caller's uid.
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	s.markDirty()
	s.saveSnapshot(false)
	st := s.State()
	if st.SavesFailed != 1 || st.LastSaveError == "" || st.LastSaveErrorAt.IsZero() {
		t.Fatalf("expected a recorded write failure, got %+v", st)
	}
	// The plane keeps working in memory.
	ip := netip.MustParseAddr("198.51.100.73")
	s.Check(ip, "sipvicious", "tcp")
	if !s.Banned(ip) {
		t.Fatal("write failure must not disable the in-memory plane")
	}
	// Clear the obstruction: the retry succeeds and clears the error.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	s.markDirty()
	s.saveSnapshot(false)
	st = s.State()
	if st.SavesOK != 1 || st.SavesFailed != 1 || st.LastSaveError != "" {
		t.Fatalf("retry did not recover: %+v", st)
	}
	// A third instance restores from the recovered file.
	s.Close()
	s2 := newStateShield(t, path, stateTestCfg, clk, nil)
	if st := s2.State(); st.Phase != PhaseRestored || st.Restored.IPBans != 1 {
		t.Fatalf("restart after recovery = %+v", st)
	}
}

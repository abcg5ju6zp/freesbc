package shield

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Snapshot file format and integrity. The file is one JSON envelope whose
// payload is base64-encoded canonical JSON authenticated with an
// HMAC-SHA256 key held in the 0600 sidecar "<state_file>.key". Signing the
// exact payload bytes (rather than a re-marshal) makes verification
// independent of field ordering rules.
const (
	stateFormat  = "freesbc-shield-state/v1"
	stateVersion = 1
	keySize      = 32

	// maxPersistedBan bounds the age a restored record may claim loosely:
	// corruption protection is the HMAC, strict decoding and closed value
	// sets, not a duration cap that could reject a ban a long-duration
	// config legitimately wrote. The substantive bounds (window and interval
	// shapes, threshold range, table caps) are the parsers' own.
	maxPersistedBan  = 100 * 365 * 24 * time.Hour
	maxFutureClock   = time.Hour
	maxPersistedRate = 2_000_000_000
)

// Recovery phases: what the constructor did with the state file.
const (
	// PhaseDisabled: no state file configured (state lives in memory).
	PhaseDisabled = "disabled"
	// PhaseEmpty: persistence enabled, no snapshot existed yet.
	PhaseEmpty = "empty"
	// PhaseRestored: a snapshot was verified and loaded (RecoveryResult
	// says whether its generation matched the running rules).
	PhaseRestored = "restored"
	// PhaseFatal: the snapshot could not be verified; it was quarantined,
	// no state was loaded and the edge must not open public listeners.
	PhaseFatal = "fatal"
)

// RecoveryResult labels the startup outcome, one per status plus the two
// restored cases.
const (
	ResultDisabled        = "disabled"
	ResultEmpty           = "empty"
	ResultSameGeneration  = "same_generation"
	ResultStaleGeneration = "stale_generation"
	ResultFatal           = "fatal"
)

// Bucket scopes: the two physically separate rate limiters.
const (
	scopePublic  = "public"
	scopeCarrier = "carrier"
)

// RestoredCounts is how many of each kind of record the last recovery
// loaded.
type RestoredCounts struct {
	IPBans        int `json:"ip_bans"`
	UDPIPBans     int `json:"udp_ip_bans"`
	UDPSocketBans int `json:"udp_socket_bans"`
	Offenders     int `json:"offenders"`
	Buckets       int `json:"buckets"`
}

// Status is the queryable state of shield persistence and recovery.
type Status struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path,omitempty"`
	Phase   string `json:"phase"`
	// RecoveryResult is disabled|empty|same_generation|stale_generation|fatal.
	RecoveryResult string `json:"recovery_result"`
	// ActiveGeneration is the generation of the running shield rules.
	ActiveGeneration string `json:"active_generation"`
	// SnapshotGeneration is the active generation the file was written under.
	SnapshotGeneration string `json:"snapshot_generation,omitempty"`
	RestoredAt         time.Time
	Restored           RestoredCounts
	// ExpiredSkipped counts records past their own deadline at recovery
	// (dropped, not loaded).
	ExpiredSkipped int
	// StaleGenerations are the non-active generations still carrying live
	// restored state; they complete under their own rules.
	StaleGenerations []string

	LastSaveAt      time.Time
	LastSaveError   string
	LastSaveErrorAt time.Time
	SavesOK         int64
	SavesFailed     int64

	// FatalError is why recovery refused the snapshot.
	FatalError string
}

// State returns a copy of the persistence status. With no state file it is
// the disabled status carrying the active generation.
func (s *Shield) State() Status {
	active := string(s.generation())
	if s.persist == nil {
		return Status{Enabled: false, Phase: PhaseDisabled, RecoveryResult: ResultDisabled,
			ActiveGeneration: active, StaleGenerations: []string{}}
	}
	st := s.persist.status()
	st.ActiveGeneration = active
	// Report the old generations still carrying live state, so the stale
	// condition clears by itself once they finish; the startup result label
	// stays in RecoveryResult.
	st.StaleGenerations = s.liveStaleGenerations(active)
	return st
}

// liveStaleGenerations lists the non-active generations that still hold live
// bans, open windows or drained buckets.
func (s *Shield) liveStaleGenerations(active string) []string {
	stale := map[string]bool{}
	add := func(g string) {
		if g != "" && g != active {
			stale[g] = true
		}
	}
	for _, e := range s.bans.live() {
		add(e.gen)
	}
	for _, e := range s.udpBans.live() {
		add(e.gen)
	}
	for _, e := range s.socketBans.live() {
		add(e.gen)
	}
	for _, o := range s.offenders.live() {
		add(o.key.gen)
	}
	for _, b := range s.limPublic.drained() {
		add(b.Generation)
	}
	for _, b := range s.limCarrier.drained() {
		add(b.Generation)
	}
	gens := make([]string, 0, len(stale))
	for g := range stale {
		gens = append(gens, g)
	}
	slices.Sort(gens)
	return gens
}

// stateStore owns the snapshot file, its HMAC key and the recovery/save
// status. One Shield has at most one; saves are serialized.
type stateStore struct {
	s       *Shield
	path    string
	keyPath string
	key     []byte
	armed   bool // false while disabled or after a fatal recovery

	mu sync.Mutex
	st Status
}

func newStateStore(s *Shield) *stateStore {
	return &stateStore{s: s, path: s.statePath, keyPath: s.statePath + ".key"}
}

// fatalf records a fail-closed recovery, quarantines the file and disarms
// writes. The caller has loaded nothing.
func (st *stateStore) fatalf(format string, args ...any) {
	err := fmt.Errorf(format, args...)
	st.mu.Lock()
	st.st.Phase = PhaseFatal
	st.st.RecoveryResult = ResultFatal
	st.st.FatalError = err.Error()
	st.st.Restored = RestoredCounts{}
	st.armed = false
	st.mu.Unlock()
	if renameErr := os.Rename(st.path, fmt.Sprintf("%s.corrupt-%d", st.path, st.s.now().UnixNano())); renameErr != nil && !errors.Is(renameErr, os.ErrNotExist) {
		st.s.log.Error("shield state quarantined, but the corrupt file could not be renamed", "path", st.path, "err", renameErr, "reason", err)
		return
	}
	st.s.log.Error("shield state snapshot failed verification; public listeners stay closed and the file was quarantined",
		"path", st.path, "err", err)
}

// bootstrap creates or loads the HMAC key, then verifies and restores the
// snapshot. It runs once, synchronously in New (before any listener opens).
func (st *stateStore) bootstrap() {
	active := string(st.s.generation())
	st.mu.Lock()
	st.st = Status{Enabled: true, Path: st.path, ActiveGeneration: active, StaleGenerations: []string{}}
	st.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
		st.fatalf("create state directory: %v", err)
		return
	}
	raw, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		// First start: create the key and wait for the first save.
		key, err := st.loadOrCreateKey()
		if err != nil {
			st.fatalf("state key: %v", err)
			return
		}
		st.key = key
		st.mu.Lock()
		st.armed = true
		st.st.Phase = PhaseEmpty
		st.st.RecoveryResult = ResultEmpty
		st.mu.Unlock()
		st.s.log.Info("shield state persistence enabled with no snapshot yet", "path", st.path)
		return
	}
	if err != nil {
		st.fatalf("read state file: %v", err)
		return
	}
	// A snapshot exists: its key must already exist. Silently making a new
	// key would turn every HMAC mismatch into an unrecoverable lockout, and
	// a missing key means the state cannot be authenticated.
	key, err := os.ReadFile(st.keyPath)
	if errors.Is(err, os.ErrNotExist) {
		st.fatalf("state file %s exists but its HMAC key %s is missing", filepath.Base(st.path), filepath.Base(st.keyPath))
		return
	}
	if err != nil {
		st.fatalf("read state key: %v", err)
		return
	}
	if len(key) != keySize {
		st.fatalf("state key %s is %d bytes, want %d", filepath.Base(st.keyPath), len(key), keySize)
		return
	}
	st.key = key

	data, env, err := st.verify(raw)
	if err != nil {
		st.fatalf("%v", err)
		return
	}
	if err := st.load(data, active, env.ActiveGeneration); err != nil {
		st.fatalf("%v", err)
		return
	}
}

func (st *stateStore) loadOrCreateKey() ([]byte, error) {
	if b, err := os.ReadFile(st.keyPath); err == nil {
		if len(b) != keySize {
			return nil, fmt.Errorf("%s is %d bytes, want %d", filepath.Base(st.keyPath), len(b), keySize)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(st.keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	st.s.log.Info("created shield state HMAC key", "path", st.keyPath)
	return key, nil
}

// envelope is the on-disk outer JSON.
type envelope struct {
	Format           string    `json:"format"`
	Version          int       `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	ActiveGeneration string    `json:"active_generation"`
	Payload          string    `json:"payload"`
	Sig              string    `json:"sig"`
}

// verify checks the envelope, the HMAC over the exact payload bytes, and
// decodes the payload strictly (unknown fields rejected).
func (st *stateStore) verify(raw []byte) (*snapshotData, *envelope, error) {
	var env envelope
	if err := strictJSON(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("state file is not valid JSON: %w", err)
	}
	if env.Format != stateFormat {
		return nil, nil, fmt.Errorf("unknown state format %q", env.Format)
	}
	if env.Version != stateVersion {
		return nil, nil, fmt.Errorf("unsupported state version %d (want %d)", env.Version, stateVersion)
	}
	if !validGeneration(env.ActiveGeneration) {
		return nil, nil, errors.New("envelope carries no valid active generation")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("payload is not valid base64: %w", err)
	}
	sig, err := hex.DecodeString(env.Sig)
	if err != nil || len(sig) != sha256.Size {
		return nil, nil, errors.New("signature is not valid hex HMAC-SHA-256")
	}
	mac := hmac.New(sha256.New, st.key)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, nil, errors.New("HMAC mismatch: state file corrupted or tampered with")
	}
	var data snapshotData
	if err := strictJSON(payload, &data); err != nil {
		return nil, nil, fmt.Errorf("payload is not valid JSON: %w", err)
	}
	return &data, &env, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}

// On-disk record shapes. Absolute times carry the original deadlines
// across the restart; the generation binds each record to its rules.
type banRecord struct {
	Key        string    `json:"key"`
	Since      time.Time `json:"since"`
	Until      time.Time `json:"until"`
	Reason     string    `json:"reason"`
	Generation string    `json:"generation"`
}

type offenderRecord struct {
	Source     string    `json:"source"`
	Reason     string    `json:"reason"`
	Start      time.Time `json:"start"`
	WindowNS   int64     `json:"window_ns"`
	N          int       `json:"n"`
	Count      int       `json:"count"`
	Over       bool      `json:"over"`
	BanNS      int64     `json:"ban_ns"`
	Generation string    `json:"generation"`
}

type bucketRecord struct {
	Scope      string    `json:"scope"`
	Key        string    `json:"key"` // empty: the (per-scope) global bucket
	Tokens     float64   `json:"tokens"`
	Last       time.Time `json:"last"`
	IntervalNS int64     `json:"interval_ns"`
	Rate       int       `json:"rate"`
	Generation string    `json:"generation"`
}

type snapshotData struct {
	IPBans        []banRecord      `json:"ip_bans"`
	UDPIPBans     []banRecord      `json:"udp_ip_bans"`
	UDPSocketBans []banRecord      `json:"udp_socket_bans"`
	Offenders     []offenderRecord `json:"offenders"`
	Buckets       []bucketRecord   `json:"buckets"`
}

var (
	banReasons    = map[string]bool{BanReasonScanner: true, BanReasonRegister: true, BanReasonAdmission: true}
	strikeReasons = map[string]bool{StrikeRegister: true, StrikeAdmission: true, StrikeAdmissionUDP: true}
)

func validGeneration(g string) bool {
	if len(g) != 64 {
		return false
	}
	_, err := hex.DecodeString(g)
	return err == nil
}

func plausibleTime(t, now time.Time) bool {
	return !t.IsZero() && !t.Before(now.Add(-maxPersistedBan)) && !t.After(now.Add(maxFutureClock))
}

// load validates every record (a single bad record fails the whole file:
// we only ever write valid ones, so any deviation is corruption), drops the
// expired, and installs the rest into the live tables.
func (st *stateStore) load(d *snapshotData, active, fileGeneration string) error {
	now := st.s.now()
	if len(d.IPBans) > banCap || len(d.UDPIPBans) > banCap || len(d.UDPSocketBans) > banCap {
		return fmt.Errorf("ban record count exceeds the hard cap %d", banCap)
	}
	if len(d.Offenders) > offenderCap {
		return fmt.Errorf("offender record count exceeds the hard cap %d", offenderCap)
	}
	if len(d.Buckets) > 2*bucketCap {
		return fmt.Errorf("bucket record count exceeds the hard cap %d", 2*bucketCap)
	}
	var counts RestoredCounts
	expired := 0
	stale := map[string]bool{}
	addStale := func(g string) {
		if g != active {
			stale[g] = true
		}
	}

	convertBans := func(recs []banRecord, socket bool) ([]storedBan[netip.Addr], []storedBan[netip.AddrPort], error) {
		ips := make([]storedBan[netip.Addr], 0, len(recs))
		socks := make([]storedBan[netip.AddrPort], 0, len(recs))
		for i, r := range recs {
			if !banReasons[r.Reason] || !validGeneration(r.Generation) {
				return nil, nil, fmt.Errorf("ban record %d has an unknown reason or generation", i)
			}
			if r.Until.Before(r.Since) || r.Until.Sub(r.Since) > maxPersistedBan || r.Until.Sub(r.Since) <= 0 ||
				!plausibleTime(r.Since, now) || r.Until.After(now.Add(maxPersistedBan+maxFutureClock)) {
				return nil, nil, fmt.Errorf("ban record %d has implausible times", i)
			}
			addStale(r.Generation)
			if socket {
				ap, err := netip.ParseAddrPort(r.Key)
				if err != nil {
					return nil, nil, fmt.Errorf("ban record %d: %w", i, err)
				}
				socks = append(socks, storedBan[netip.AddrPort]{Key: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()),
					Generation: r.Generation, Reason: r.Reason, Since: r.Since, Until: r.Until})
			} else {
				ip, err := netip.ParseAddr(r.Key)
				if err != nil {
					return nil, nil, fmt.Errorf("ban record %d: %w", i, err)
				}
				ips = append(ips, storedBan[netip.Addr]{Key: ip.Unmap(),
					Generation: r.Generation, Reason: r.Reason, Since: r.Since, Until: r.Until})
			}
		}
		return ips, socks, nil
	}

	ipRecs, _, err := convertBans(d.IPBans, false)
	if err != nil {
		return err
	}
	udpRecs, _, err := convertBans(d.UDPIPBans, false)
	if err != nil {
		return err
	}
	_, sockRecs, err := convertBans(d.UDPSocketBans, true)
	if err != nil {
		return err
	}

	offRecs := make([]storedOffender, 0, len(d.Offenders))
	for i, r := range d.Offenders {
		if !strikeReasons[r.Reason] || !validGeneration(r.Generation) {
			return fmt.Errorf("offender record %d has an unknown reason or generation", i)
		}
		w := time.Duration(r.WindowNS)
		ban := time.Duration(r.BanNS)
		if w < time.Second || w > 24*time.Hour || r.N < 1 || r.N > 100000 ||
			r.Count < 1 || r.Count > maxPersistedRate || ban <= 0 || ban > maxPersistedBan ||
			!plausibleTime(r.Start, now) || (r.Over != (r.Count > r.N)) {
			return fmt.Errorf("offender record %d has out-of-range or inconsistent fields", i)
		}
		src, err := netip.ParseAddr(r.Source)
		if err != nil {
			return fmt.Errorf("offender record %d: %w", i, err)
		}
		addStale(r.Generation)
		offRecs = append(offRecs, storedOffender{Src: src.Unmap(), Reason: r.Reason, Generation: r.Generation,
			Start: r.Start, Window: w, BanDur: ban, N: r.N, Count: r.Count, Over: r.Over})
	}

	pub := make([]storedBucket, 0, len(d.Buckets))
	car := make([]storedBucket, 0, len(d.Buckets))
	for i, r := range d.Buckets {
		if !validGeneration(r.Generation) || r.Rate < 1 || r.Rate > maxPersistedRate ||
			r.Tokens < 0 || r.Tokens > float64(r.Rate) || !plausibleTime(r.Last, now) {
			return fmt.Errorf("bucket record %d has out-of-range fields", i)
		}
		interval := time.Duration(r.IntervalNS)
		if interval != time.Second && interval != time.Minute && interval != time.Hour {
			return fmt.Errorf("bucket record %d has an interval the parser cannot produce", i)
		}
		var src netip.Addr
		if r.Key != "" {
			ip, err := netip.ParseAddr(r.Key)
			if err != nil {
				return fmt.Errorf("bucket record %d: %w", i, err)
			}
			src = ip.Unmap()
		}
		addStale(r.Generation)
		b := storedBucket{Src: src, Generation: r.Generation, Tokens: r.Tokens, Last: r.Last, Interval: interval, Rate: r.Rate}
		switch r.Scope {
		case scopePublic:
			pub = append(pub, b)
		case scopeCarrier:
			car = append(car, b)
		default:
			return fmt.Errorf("bucket record %d has unknown scope %q", i, r.Scope)
		}
	}

	// All records validated: install them. The restore calls skip expired
	// records by their own deadlines and report the counts.
	n, ex := st.s.bans.restore(ipRecs)
	counts.IPBans += n
	expired += ex
	n, ex = st.s.udpBans.restore(udpRecs)
	counts.UDPIPBans += n
	expired += ex
	n, ex = st.s.socketBans.restore(sockRecs)
	counts.UDPSocketBans += n
	expired += ex
	on, ex := st.s.offenders.restore(offRecs)
	counts.Offenders += on
	expired += ex
	counts.Buckets += st.s.limPublic.restore(pub)
	counts.Buckets += st.s.limCarrier.restore(car)

	gens := make([]string, 0, len(stale))
	for g := range stale {
		gens = append(gens, g)
	}
	slices.Sort(gens)
	result := ResultSameGeneration
	if fileGeneration != active || len(gens) > 0 {
		result = ResultStaleGeneration
	}
	st.mu.Lock()
	st.armed = true
	st.st.Phase = PhaseRestored
	st.st.RecoveryResult = result
	st.st.SnapshotGeneration = fileGeneration
	st.st.RestoredAt = now
	st.st.Restored = counts
	st.st.ExpiredSkipped = expired
	st.st.StaleGenerations = gens
	st.mu.Unlock()
	st.s.log.Info("shield state restored",
		"ip_bans", counts.IPBans, "udp_ip_bans", counts.UDPIPBans, "udp_socket_bans", counts.UDPSocketBans,
		"offenders", counts.Offenders, "buckets", counts.Buckets, "expired_skipped", expired,
		"recovery_result", result, "active_generation", Generation(active).Short())
	return nil
}

// save writes one snapshot atomically when persistence is armed.
func (st *stateStore) save() error {
	st.mu.Lock()
	if !st.armed {
		st.mu.Unlock()
		return nil
	}
	active := string(st.s.generation())
	st.st.ActiveGeneration = active
	st.mu.Unlock()

	data := st.collect(active)
	payload, err := json.Marshal(data)
	if err != nil {
		st.noteSaveError(err)
		return err
	}
	mac := hmac.New(sha256.New, st.key)
	mac.Write(payload)
	env := envelope{
		Format:           stateFormat,
		Version:          stateVersion,
		CreatedAt:        st.s.now().UTC(),
		ActiveGeneration: active,
		Payload:          base64.StdEncoding.EncodeToString(payload),
		Sig:              hex.EncodeToString(mac.Sum(nil)),
	}
	raw, err := json.MarshalIndent(&env, "", "  ")
	if err != nil {
		st.noteSaveError(err)
		return err
	}
	if err := st.writeAtomic(raw); err != nil {
		st.noteSaveError(err)
		return err
	}
	st.mu.Lock()
	st.st.LastSaveAt = st.s.now()
	st.st.LastSaveError = ""
	st.st.LastSaveErrorAt = time.Time{}
	st.st.SavesOK++
	st.mu.Unlock()
	return nil
}

// collect dumps the live tables into the wire shape. Slices are always
// non-nil so an empty file is "[]" and round-trips byte-stably.
func (st *stateStore) collect(active string) snapshotData {
	toBanRecs := func(in []storedBan[netip.Addr]) []banRecord {
		out := make([]banRecord, 0, len(in))
		for _, e := range in {
			out = append(out, banRecord{Key: e.Key.String(), Since: e.Since.UTC(), Until: e.Until.UTC(),
				Reason: e.Reason, Generation: e.Generation})
		}
		return out
	}
	d := snapshotData{
		IPBans:        toBanRecs(st.s.bans.dump()),
		UDPIPBans:     toBanRecs(st.s.udpBans.dump()),
		UDPSocketBans: []banRecord{},
		Offenders:     []offenderRecord{},
		Buckets:       []bucketRecord{},
	}
	for _, e := range st.s.socketBans.dump() {
		d.UDPSocketBans = append(d.UDPSocketBans, banRecord{Key: e.Key.String(), Since: e.Since.UTC(),
			Until: e.Until.UTC(), Reason: e.Reason, Generation: e.Generation})
	}
	for _, e := range st.s.offenders.dump() {
		d.Offenders = append(d.Offenders, offenderRecord{
			Source: e.Src.String(), Reason: e.Reason, Start: e.Start.UTC(), WindowNS: int64(e.Window),
			N: e.N, Count: e.Count, Over: e.Over, BanNS: int64(e.BanDur), Generation: e.Generation})
	}
	toBuckets := func(scope string, in []storedBucket) {
		for _, e := range in {
			d.Buckets = append(d.Buckets, bucketRecord{Scope: scope, Key: e.Src.String(),
				Tokens: e.Tokens, Last: e.Last.UTC(), IntervalNS: int64(e.Interval),
				Rate: e.Rate, Generation: e.Generation})
		}
	}
	toBuckets(scopePublic, st.s.limPublic.drained())
	toBuckets(scopeCarrier, st.s.limCarrier.drained())
	return d
}

// writeAtomic writes to a same-directory 0600 temp file, syncs it, and
// renames it over the snapshot.
func (st *stateStore) writeAtomic(raw []byte) error {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%x", st.path, suffix)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, st.path)
}

func (st *stateStore) noteSaveError(err error) {
	st.mu.Lock()
	st.st.SavesFailed++
	st.st.LastSaveError = err.Error()
	st.st.LastSaveErrorAt = st.s.now()
	st.mu.Unlock()
	st.s.log.Error("shield state snapshot write failed; serving from memory and will retry", "path", st.path, "err", err)
}

func (st *stateStore) status() Status {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.st
	out.StaleGenerations = slices.Clone(st.st.StaleGenerations)
	if out.StaleGenerations == nil {
		out.StaleGenerations = []string{}
	}
	return out
}

// saveSnapshot is the prune-loop/Close hook. Periodic writes happen only
// while dirty; Close always tries once more.
func (s *Shield) saveSnapshot(final bool) {
	if s.persist == nil {
		return
	}
	if !final {
		if !s.dirty.CompareAndSwap(true, false) {
			return
		}
	}
	if !s.persist.armedState() {
		return
	}
	_ = s.persist.save()
}

// armedState reports whether writes are allowed (disabled after a fatal
// recovery).
func (st *stateStore) armedState() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.armed
}

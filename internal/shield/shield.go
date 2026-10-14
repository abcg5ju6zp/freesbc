package shield

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// Verdict is Shield.Check's decision.
type Verdict int

const (
	Allow Verdict = iota
	Drop
)

// Option customises New.
type Option func(*Shield)

// WithClock overrides the wall clock. Tests only.
func WithClock(now func() time.Time) Option {
	return func(s *Shield) {
		s.clock = now
		s.customClock = true
	}
}

// WithStateFile enables snapshot persistence at path (an absolute file
// path; the HMAC key is kept at path+".key"). The snapshot is restored
// before New returns.
func WithStateFile(path string) Option {
	return func(s *Shield) { s.statePath = path }
}

// Shield is FreeSBC's front-door security plane. It is consulted on every
// inbound request on the public edge listeners; every denial is a silent
// Drop. Params (rate limits, ban) hot-reload from the config store per
// call, and every piece of live state carries the Generation of the rules
// that created it. When a state file is configured, live state is
// snapshotted to disk and restored at construction, before any listener
// opens; otherwise it lives in process memory only.
type Shield struct {
	store       *config.Store
	log         *slog.Logger
	isCarrier   func(netip.Addr) bool    // carrier-source predicate; never nil
	limPublic   *rateLimiter             // per-source limit for public sources (shield.rate_limit)
	limCarrier  *rateLimiter             // per-source limit for carrier sources (carrier_rate_limit)
	bans        *banList[netip.Addr]     // source IPs (connection-oriented verdicts)
	socketBans  *banList[netip.AddrPort] // UDP source sockets (see CheckFrom)
	udpBans     *banList[netip.Addr]     // source IPs banned on UDP only (see StrikeOn)
	offenders   *offenderTable           // per-source strike counters (Strike)
	clock       func() time.Time         // wall clock; time.Now unless WithClock
	customClock bool
	statePath   string      // "" keeps state in memory only
	persist     *stateStore // snapshot persistence; nil with no state file

	// Cumulative drop counters by reason, for the admin API's metrics
	// snapshot (Stats). Incremented in Check at each of its three drop
	// points; read via Stats' atomic Load.
	dropsBanned  atomic.Int64
	dropsScanner atomic.Int64
	dropsRate    atomic.Int64

	// dirty is set by every state mutation and cleared after a snapshot
	// write, so the periodic writer is a no-op while nothing changed.
	dirty atomic.Bool

	// cached parses of the rate limit strings (re-parsed only when they change).
	rlMu    sync.Mutex
	rlStr   string
	rlOpts  config.RateLimit
	carStr  string
	carOpts config.RateLimit
	// strike thresholds by reason (strikeLimit), under rlMu.
	strikeStr  map[string]string
	strikeOpts map[string]config.StrikeLimit
	// cached rule generation. Snapshots are normally fresh pointers, but a
	// caller can Replace a copy at the same address, so the cache key is the
	// rule content (cheap string compares), not the pointer. Under rlMu.
	genCfg              *config.Config
	genBan              config.Duration
	genRate, genCarRate string
	genReg, genAdm      string
	gen                 Generation

	stop context.CancelFunc
	done chan struct{}
}

// New builds the Shield over store and starts a background prune loop.
// isCarrier reports whether an address is a carrier source: such sources
// are limited by shield.carrier_rate_limit instead of shield.rate_limit
// and are exempt from the scanner ban. nil means no carriers. (The edge's
// trusted private plane bypasses the shield before calling it.)
//
// With a WithStateFile option, the snapshot is read, verified and restored
// before New returns; see Status for the outcome (including a fatal,
// fail-closed verification failure).
func New(store *config.Store, log *slog.Logger, isCarrier func(netip.Addr) bool, opts ...Option) *Shield {
	if isCarrier == nil {
		isCarrier = func(netip.Addr) bool { return false }
	}
	now := time.Now
	ctx, cancel := context.WithCancel(context.Background())
	s := &Shield{
		store:      store,
		log:        log,
		isCarrier:  isCarrier,
		limPublic:  newRateLimiter(),
		limCarrier: newRateLimiter(),
		bans:       newBanList(),
		socketBans: newBanTable[netip.AddrPort](),
		udpBans:    newBanList(),
		offenders:  newOffenderTable(),
		clock:      now,
		stop:       cancel,
		done:       make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.customClock {
		// Thread the test clock through every table.
		s.limPublic.now, s.limCarrier.now = s.clock, s.clock
		s.bans.now, s.socketBans.now, s.udpBans.now = s.clock, s.clock, s.clock
		s.offenders.now = s.clock
	}
	if s.statePath != "" {
		s.persist = newStateStore(s)
		s.persist.bootstrap()
	}
	go s.pruneLoop(ctx)
	return s
}

// generation returns the rule generation of the current config snapshot,
// cached until one of the rule values changes.
func (s *Shield) generation() Generation {
	cfg := s.store.Current()
	sh := &cfg.Shield
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	if s.genCfg == nil ||
		s.genBan != sh.Ban ||
		s.genRate != sh.RateLimit ||
		s.genCarRate != sh.CarrierRateLimit ||
		s.genReg != sh.RegisterBan ||
		s.genAdm != sh.AdmissionBan {
		s.genCfg = cfg
		s.genBan, s.genRate, s.genCarRate = sh.Ban, sh.RateLimit, sh.CarrierRateLimit
		s.genReg, s.genAdm = sh.RegisterBan, sh.AdmissionBan
		s.gen = GenerationOf(cfg)
	}
	return s.gen
}

func (s *Shield) now() time.Time { return s.clock() }

// markDirty notes a state mutation for the next snapshot write.
func (s *Shield) markDirty() { s.dirty.Store(true) }

// Check is the per-request gate (spec §3): a banned source and a
// rate-limit violation Drop; otherwise a scanner UA is dropped, and instantly
// banned when it arrived over a connection-oriented transport (see
// bannableTransport) — but only AFTER the rate limiter has had its say (the
// UA is a client-controlled "ban me" signal, so it must first burn through
// the source's rate budget like any other traffic, never skip the limiter).
// transport is the request transport ("udp"/"tcp"/"tls"/"ws"/"wss"/"";
// case-insensitive).
//
// Check knows only the source IP, so a scanner datagram is dropped without
// any ban; CheckFrom, which also knows the source port, bans the socket.
func (s *Shield) Check(src netip.Addr, userAgent string, transport string) Verdict {
	return s.CheckFrom(netip.AddrPortFrom(src, 0), userAgent, transport)
}

// socketBanMax caps how long a UDP scanner verdict bans its source socket.
// The verdict rests on one forgeable datagram, so the ban is kept short: a
// real scanner that keeps sending from the socket re-arms it, while a
// forged datagram naming a victim's socket silences that socket briefly
// and never the rest of its IP.
const socketBanMax = time.Minute

// CheckFrom is Check with the source port. A scanner verdict on UDP bans
// only the exact source socket (IP and port), for at most socketBanMax, in
// a table separate from the IP bans; a port of 0 means unknown and bans
// nothing.
func (s *Shield) CheckFrom(srcAP netip.AddrPort, userAgent string, transport string) Verdict {
	srcAP = netip.AddrPortFrom(srcAP.Addr().Unmap(), srcAP.Port())
	if s.BannedFrom(srcAP, transport) {
		s.dropsBanned.Add(1)
		return Drop
	}
	if !s.AllowRate(srcAP.Addr()) {
		return Drop
	}
	return s.CheckScanner(srcAP, userAgent, transport)
}

// AllowRate charges one token of src's rate-limit bucket (shield.rate_limit,
// or shield.carrier_rate_limit for a carrier source) and reports whether it
// was available. A refusal is counted as a "rate" drop. It needs no parsed
// message, so the edge read filter calls it once per datagram or frame,
// before the parser; a parsable request is then charged exactly once, there,
// and its guard calls CheckScanner instead of CheckFrom.
//
// Public and carrier sources never share a bucket.
func (s *Shield) AllowRate(src netip.Addr) bool {
	src = src.Unmap()
	carrier := s.isCarrier(src)
	cfg := s.store.Current()
	rl := s.rateLimit(cfg, carrier)
	lim := s.limPublic
	if carrier {
		lim = s.limCarrier
	}
	if !lim.allow(src, rl.Rate, rl.Interval, rl.PerIP, string(s.generation())) {
		s.log.Debug("shield rate-limited", "source", src, "carrier", carrier)
		s.dropsRate.Add(1)
		return false
	}
	return true
}

// CheckScanner is CheckFrom without the rate token: the ban re-check and the
// scanner (User-Agent) verdict, which need a parsed message. The caller must
// already have charged the source through AllowRate (the UA is a
// client-controlled "ban me" signal, so it must first burn through the
// source's rate budget like any other traffic, never skip the limiter).
func (s *Shield) CheckScanner(srcAP netip.AddrPort, userAgent string, transport string) Verdict {
	srcAP = netip.AddrPortFrom(srcAP.Addr().Unmap(), srcAP.Port())
	src := srcAP.Addr()
	cfg := s.store.Current()
	if s.BannedFrom(srcAP, transport) {
		s.dropsBanned.Add(1)
		return Drop
	}
	carrier := s.isCarrier(src)
	if !carrier && isScanner(userAgent) {
		s.dropsScanner.Add(1)
		gen := string(s.generation())
		if !bannableTransport(transport) {
			// A datagram's source address is forgeable: an IP ban would let
			// one spoofed packet lock a third party out, and a spoofed flood
			// fill the IP table. Ban the socket instead, briefly.
			if isUDP(transport) && srcAP.Port() != 0 {
				s.socketBans.ban(srcAP, min(cfg.Shield.Ban.Std(), socketBanMax), BanReasonScanner, gen)
				s.markDirty()
			}
			s.log.Debug("shield dropped scanner datagram", "source", srcAP, "ua", userAgent)
			return Drop
		}
		if !s.bans.ban(src, cfg.Shield.Ban.Std(), BanReasonScanner, gen) {
			s.log.Debug("shield ban table at hard cap; scanner ban refused", "source", src, "ua", userAgent)
		} else {
			s.markDirty()
			s.log.Warn("shield banned scanner", "source", src, "ua", userAgent, "generation", s.gen.Short())
		}
		return Drop
	}
	return Allow
}

// bannableTransport reports whether a scanner verdict on this transport may
// ban its source. Only connection-oriented transports qualify: their source
// address survived a handshake, so it is not forged. UDP, and an unknown or
// empty transport, get a drop without a ban.
func bannableTransport(transport string) bool {
	switch strings.ToLower(transport) {
	case "tcp", "tls", "ws", "wss":
		return true
	}
	return false
}

func isUDP(transport string) bool { return strings.EqualFold(transport, "udp") }

// BannedFrom reports whether the source is banned: its IP, or on UDP its
// exact socket. A ban counts under ANY rule generation, so a ban made under
// old rules stays in force until its own deadline. Like Banned it counts
// nothing, so a read filter can call it.
func (s *Shield) BannedFrom(src netip.AddrPort, transport string) bool {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	if s.bans.banned(src.Addr()) {
		return true
	}
	if !isUDP(transport) {
		return false
	}
	return s.udpBans.banned(src.Addr()) || (src.Port() != 0 && s.socketBans.banned(src))
}

// ErrUnknownBanKind and ErrBanNotFound describe an Unban miss.
var (
	ErrUnknownBanKind = errors.New("unknown ban kind")
	ErrBadBanSource   = errors.New("invalid ban source")
	ErrBanNotFound    = errors.New("ban not found for this generation")
)

// Unban removes exactly one live ban: kind is BanKindIP, BanKindUDPIP or
// BanKindUDPSocket, source the IP (or IP:port for a socket ban) as Bans
// lists it, and generation the rule generation the ban was created under
// (required: an unban never reaches a ban made under different rules). It
// reports whether one was removed; ErrUnknownBanKind/ErrBadBanSource make
// the request a 400, a clean miss (false) a 404.
func (s *Shield) Unban(kind, source, generation string) (bool, error) {
	if generation == "" {
		return false, ErrBanNotFound
	}
	var removed bool
	switch kind {
	case BanKindIP:
		ip, err := netip.ParseAddr(source)
		if err != nil {
			return false, ErrBadBanSource
		}
		removed = s.bans.unban(ip.Unmap(), generation)
	case BanKindUDPIP:
		ip, err := netip.ParseAddr(source)
		if err != nil {
			return false, ErrBadBanSource
		}
		removed = s.udpBans.unban(ip.Unmap(), generation)
	case BanKindUDPSocket:
		ap, err := netip.ParseAddrPort(source)
		if err != nil {
			return false, ErrBadBanSource
		}
		removed = s.socketBans.unban(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), generation)
	default:
		return false, ErrUnknownBanKind
	}
	if removed {
		s.markDirty()
	}
	return removed, nil
}

// Stats is a snapshot of shield activity for metrics.
type Stats struct {
	BannedCurrent int
	// BanAddsRejected counts ban additions refused at the ban table's hard
	// cap — an indicator that a source flood is exhausting the table.
	BanAddsRejected int64
	DropsByReason   map[string]int64
}

// Stats returns a snapshot of current bans and cumulative drops by reason.
func (s *Shield) Stats() Stats {
	return Stats{
		BannedCurrent:   s.bans.size() + s.socketBans.size() + s.udpBans.size(),
		BanAddsRejected: s.bans.overflowed() + s.socketBans.overflowed() + s.udpBans.overflowed(),
		DropsByReason: map[string]int64{
			"banned":  s.dropsBanned.Load(),
			"scanner": s.dropsScanner.Load(),
			"rate":    s.dropsRate.Load(),
		},
	}
}

// Close stops the prune loop, writing one final best-effort snapshot when
// persistence is enabled.
func (s *Shield) Close() error {
	s.stop()
	<-s.done
	return nil
}

func (s *Shield) rateLimit(cfg *config.Config, carrier bool) config.RateLimit {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	str, cached, opts := cfg.Shield.RateLimit, &s.rlStr, &s.rlOpts
	if carrier {
		str, cached, opts = cfg.Shield.CarrierRateLimit, &s.carStr, &s.carOpts
	}
	if str != *cached {
		if rl, err := config.ParseRateLimit(str); err == nil {
			*opts = rl
			*cached = str
		}
	}
	return *opts
}

func (s *Shield) pruneLoop(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.saveSnapshot(true)
			return
		case <-t.C:
			s.limPublic.prune()
			s.limCarrier.prune()
			s.bans.prune()
			s.socketBans.prune()
			s.udpBans.prune()
			s.offenders.prune()
			s.saveSnapshot(false)
		}
	}
}

// BanInfo is one live ban, copied out of a ban table.
type BanInfo struct {
	// Source is the banned IP, or IP:port for a UDP socket ban.
	Source string
	// Kind is BanKindIP (every transport), BanKindUDPIP (the IP, UDP only)
	// or BanKindUDPSocket.
	Kind string
	// Reason is why the ban was recorded (BanReasonScanner,
	// BanReasonRegister).
	Reason string
	// Generation is the shield rule generation the ban was created under.
	Generation string
	// Since is when the ban was first recorded; Until when it lapses.
	Since, Until time.Time
}

// maxBanPage bounds one Bans page.
const maxBanPage = 1000

// Bans returns one page of the live (unexpired) bans of both tables, newest
// first then by source, and the total number of live bans. limit is clamped
// to 1..maxBanPage and a negative offset is 0. The tables are copied under
// their own locks; sorting and slicing happen outside them. The page is a
// non-nil slice.
func (s *Shield) Bans(limit, offset int) (page []BanInfo, total int) {
	limit = min(max(limit, 1), maxBanPage)
	offset = max(offset, 0)
	ips, socks, udps := s.bans.live(), s.socketBans.live(), s.udpBans.live()
	all := make([]BanInfo, 0, len(ips)+len(socks)+len(udps))
	for _, e := range udps {
		all = append(all, BanInfo{Source: e.key.String(), Kind: BanKindUDPIP, Reason: e.reason, Generation: e.gen, Since: e.since, Until: e.until})
	}
	for _, e := range ips {
		all = append(all, BanInfo{Source: e.key.String(), Kind: BanKindIP, Reason: e.reason, Generation: e.gen, Since: e.since, Until: e.until})
	}
	for _, e := range socks {
		all = append(all, BanInfo{Source: e.key.String(), Kind: BanKindUDPSocket, Reason: e.reason, Generation: e.gen, Since: e.since, Until: e.until})
	}
	sortBans(all)
	total = len(all)
	if offset >= total {
		return []BanInfo{}, total
	}
	end := min(offset+limit, total)
	return append([]BanInfo{}, all[offset:end]...), total
}

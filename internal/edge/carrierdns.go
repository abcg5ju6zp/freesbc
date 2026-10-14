package edge

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// This file is the carrier directory: what edge.carriers resolves to, and
// with it the set of public source addresses an out-of-dialog INVITE is
// admitted from as a carrier's.
//
// A literal-IP entry is static: it owns one permanent generation. A
// DNS-name entry resolves on the PUBLIC side only (the switch is never
// asked, and the private leg does no DNS): without a port through SRV
// (_sip._udp, _sip._tcp or _sips._tcp.<host> by the carrier's transport)
// ordered by priority and weight (RFC 2782) and then A/AAAA per target;
// with an explicit port through A/AAAA only (RFC 3263 §4.2). With no SRV
// record the port is the transport's default (5060, 5061 for tls). There
// is no NAPTR and no failover across SRV targets. Go exposes no record
// TTL, so a good answer is cached for the carrierDNSTTL constant and a
// failed one for the much shorter carrierDNSNegTTL.
//
// Each successful resolution that changes the address set opens a new
// address generation (carriergen.go). New requests take only the current
// generation, while a superseded one stays live — with its source
// qualification and its stream connections — for as long as a
// connection, a REGISTER binding or a dialog is still pinned to it, and
// retires the moment the last pin goes. A failed refresh keeps the last
// good set: the current generation stays current, and a resolver outage
// must never turn a carrier's source address into "unknown". A DNS
// failure at startup is not fatal either; the carrier is simply
// unresolved (and its calls dropped by admission) until a lookup
// succeeds.
//
// A background goroutine (Run) refreshes entries as they expire and
// publishes an immutable snapshot through an atomic pointer, so the
// shield and the admission check read it without locking.

const (
	// carrierDNSTTL is how long a resolved carrier is cached.
	carrierDNSTTL = 300 * time.Second
	// carrierDNSNegTTL is how long a FAILED or EMPTY lookup is cached before
	// it is retried, so a transient fault is not pinned for the whole TTL.
	carrierDNSNegTTL = 10 * time.Second
	// carrierLookupTimeout bounds one DNS query.
	carrierLookupTimeout = 3 * time.Second
	// carrierUnknown is the name stamped on a request from a carrier source
	// that matches no edge.carriers entry by address.
	carrierUnknown = "unknown"
)

// carrierSnapshot is one immutable published view of the directory.
type carrierSnapshot struct {
	names []string // edge.carriers names, sorted
	// addrs is each carrier's CURRENT generation's destinations in
	// preference order (nil for an unresolved carrier). New requests use
	// this alone.
	addrs map[string][]netip.AddrPort
	// live is every live generation per carrier, current first and then
	// the retained ones oldest first. It is what still recognises the
	// connections, registrations and dialogs pinned to an old address set.
	live map[string][]*carrierGen
	nets []netip.Prefix // carrier source prefixes (current and retained), sorted and deduplicated
	// extra is edge.carrier_sources alone: prefixes that match on any
	// public transport. nets also holds the carriers' own addresses, which
	// match by IP for the shield but are admitted only on their carrier's
	// transport (sourceGen).
	extra []netip.Prefix
	// transports is each carrier's transport by name.
	transports map[string]string
}

// isSource reports whether ip is inside a carrier-source prefix,
// including a retained generation still carrying existing traffic.
func (c *carrierSnapshot) isSource(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range c.nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// carrierFor names the carrier a public source belongs to, for a request
// that arrived over network (udp, tcp, tls...). See sourceGen.
func (c *carrierSnapshot) carrierFor(src netip.AddrPort, network string) (name string, ok bool) {
	name, _, ok = c.sourceGen(src, network)
	return name, ok
}

// sourceGen names the carrier and generation a public source belongs to,
// for a request that arrived over network (udp, tcp, tls...). A
// generation's resolved address counts only on that carrier's own
// transport: a tls carrier's IP over UDP is no carrier. The current
// generation precedes retained ones, an exact IP:port match wins; failing
// that the first entry (by sorted name, current first within it) with
// that IP; a source inside edge.carrier_sources (any transport) that
// matches no generation is carrierUnknown with no generation. ok is
// false for a source that is no carrier source at all.
func (c *carrierSnapshot) sourceGen(src netip.AddrPort, network string) (name string, g *carrierGen, ok bool) {
	ip := src.Addr().Unmap().WithZone("")
	src = netip.AddrPortFrom(ip, src.Port())
	byIPName := ""
	var byIPGen *carrierGen
	for _, n := range c.names {
		if c.transports[n] != network {
			continue
		}
		for _, lg := range c.live[n] {
			for _, a := range lg.addrs {
				if a == src {
					return n, lg, true
				}
				if byIPName == "" && a.Addr() == ip {
					byIPName, byIPGen = n, lg
				}
			}
		}
	}
	if byIPName != "" {
		return byIPName, byIPGen, true
	}
	for _, p := range c.extra {
		if p.Contains(ip) {
			return carrierUnknown, nil, true
		}
	}
	return "", nil, false
}

// sourcesString renders the source set for the startup log.
func (c *carrierSnapshot) sourcesString() string {
	parts := make([]string, len(c.nets))
	for i, p := range c.nets {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// carrierEntry is the cached resolution state of one DNS-name carrier.
type carrierEntry struct {
	// cur is the current generation, nil until a lookup first succeeds;
	// retained are superseded generations still pinned, oldest first;
	// history keeps the retired and closed ones (bounded) so the handoff
	// stays queryable.
	cur      *carrierGen
	retained []*carrierGen
	history  []*carrierGen

	seq    uint64 // generation ids handed out for this carrier
	expiry time.Time
	// failing is true while the latest lookup failed (cur, if any, is the
	// last good generation). lastErr is its text, cleared on success.
	failing bool
	lastErr string
}

// Carrier resolution modes.
const (
	carrierModeLiteral = "literal"
	carrierModeSRV     = "srv"
	carrierModeA       = "a"
)

// carrierDirectory resolves edge.carriers and publishes the result.
type carrierDirectory struct {
	log      *slog.Logger
	carriers []config.Carrier // sorted by name
	static   []netip.Prefix   // carrier_sources plus literal-IP carriers
	extra    []netip.Prefix   // carrier_sources alone

	// lookupSRV and lookupIP are the DNS seams; tests replace them.
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	lookupIP  func(ctx context.Context, host string) ([]netip.Addr, error)
	now       func() time.Time

	mu      sync.Mutex // serialises refresh and references; guards entries, statics and rnd
	entries map[string]*carrierEntry
	statics map[string]*carrierGen // the one permanent generation of each literal carrier
	closed  bool                   // shutdown ran
	rnd     *rand.Rand

	// closeConn closes a pooled stream connection, called outside mu when
	// a generation retires. Wired by the Server; nil in standalone tests.
	closeConn func(network, addr string)

	snap atomic.Pointer[carrierSnapshot]
}

func newCarrierDirectory(cfg *config.Config, log *slog.Logger) *carrierDirectory {
	d := &carrierDirectory{
		log:      log,
		carriers: cfg.CarrierList(),
		static:   cfg.CarrierNets(),
		extra:    cfg.CarrierSourceNets(),
		lookupSRV: func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
			return net.DefaultResolver.LookupSRV(ctx, service, proto, name)
		},
		lookupIP: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		now:     time.Now,
		entries: map[string]*carrierEntry{},
		statics: map[string]*carrierGen{},
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	d.buildStatics()
	d.publish()
	return d
}

// buildStatics creates the one permanent generation of each literal-IP
// carrier. Called by the constructor; standalone test directories use it
// too.
func (d *carrierDirectory) buildStatics() {
	for _, c := range d.carriers {
		if !c.Literal() {
			continue
		}
		addr := netip.AddrPortFrom(c.Addr, uint16(c.DialPort()))
		d.statics[c.Name] = &carrierGen{
			id: 1, carrier: c.Name,
			transport: carrierTransport(c), addrs: []netip.AddrPort{addr},
			static: true, state: genCurrent, mode: carrierModeLiteral, born: genBirthLiteral,
		}
	}
}

// carrierTransport is the carrier's transport, udp when the entry leaves
// it unset.
func carrierTransport(c config.Carrier) string {
	if c.Transport != "" {
		return c.Transport
	}
	return config.CarrierUDP
}

// snapshot is the current published view.
func (d *carrierDirectory) snapshot() *carrierSnapshot { return d.snap.Load() }

// publish builds and stores a snapshot from the literal carriers, the
// static prefixes and every live generation. The caller holds mu (or is
// the constructor).
func (d *carrierDirectory) publish() {
	snap := &carrierSnapshot{
		addrs:      map[string][]netip.AddrPort{},
		live:       map[string][]*carrierGen{},
		transports: map[string]string{},
		extra:      d.extra,
	}
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if !seen[p] {
			seen[p] = true
			snap.nets = append(snap.nets, p)
		}
	}
	addGen := func(g *carrierGen) {
		snap.live[g.carrier] = append(snap.live[g.carrier], g)
		for _, a := range g.addrs {
			add(netip.PrefixFrom(a.Addr(), a.Addr().BitLen()))
		}
	}
	for _, p := range d.static {
		add(p)
	}
	for _, c := range d.carriers {
		snap.names = append(snap.names, c.Name)
		snap.transports[c.Name] = carrierTransport(c)
		if c.Literal() {
			if g := d.statics[c.Name]; g != nil {
				snap.addrs[c.Name] = g.addrs
				addGen(g)
			}
			continue
		}
		if e := d.entries[c.Name]; e != nil {
			if e.cur != nil {
				snap.addrs[c.Name] = e.cur.addrs
				addGen(e.cur)
			}
			for _, g := range e.retained {
				addGen(g)
			}
		}
	}
	sort.Strings(snap.names)
	sort.Slice(snap.nets, func(i, j int) bool {
		if c := snap.nets[i].Addr().Compare(snap.nets[j].Addr()); c != 0 {
			return c < 0
		}
		return snap.nets[i].Bits() < snap.nets[j].Bits()
	})
	d.snap.Store(snap)
}

// liveAddrsLocked is the transport/address pairs every live generation
// (current or retained) still names. The caller holds mu.
func (d *carrierDirectory) liveAddrsLocked() map[genAddr]bool {
	out := map[genAddr]bool{}
	keep := func(g *carrierGen) {
		for _, a := range g.addrs {
			out[genAddr{transport: g.transport, addr: a}] = true
		}
	}
	for _, g := range d.statics {
		keep(g)
	}
	for _, e := range d.entries {
		if e.cur != nil {
			keep(e.cur)
		}
		for _, g := range e.retained {
			keep(g)
		}
	}
	return out
}

// buryLocked moves a retained generation into the carrier's bounded
// history. The caller holds mu and has already taken it out of the live
// lists.
func (d *carrierDirectory) buryLocked(g *carrierGen) {
	if g.static {
		return
	}
	e := d.entries[g.carrier]
	if e == nil {
		return
	}
	for i, r := range e.retained {
		if r == g {
			e.retained = append(e.retained[:i], e.retained[i+1:]...)
			break
		}
	}
	e.history = append(e.history, g)
	if len(e.history) > carrierGenHistory {
		e.history = e.history[len(e.history)-carrierGenHistory:]
	}
}

// refresh resolves every DNS-name carrier whose cache entry is missing or
// expired, then publishes a new snapshot.
//
// mu is held only to read and to apply an outcome, never across a lookup, so
// the operator views (snapshotInfo, and the health conditions built on it)
// never wait on a slow resolver. refresh itself is called from one goroutine.
func (d *carrierDirectory) refresh(ctx context.Context) {
	var closeConns []connToClose
	changed := false
	for _, c := range d.carriers {
		if c.Literal() {
			continue
		}
		d.mu.Lock()
		now := d.now()
		e := d.entries[c.Name]
		fresh := e != nil && now.Before(e.expiry)
		d.mu.Unlock()
		if fresh {
			continue
		}
		addrs, mode, err := d.resolve(ctx, c)
		pairs, did := d.apply(c, now, addrs, mode, err)
		if did {
			changed = true
		}
		closeConns = append(closeConns, pairs...)
	}
	if changed {
		d.mu.Lock()
		d.publish()
		d.mu.Unlock()
	}
	for _, p := range closeConns {
		if d.closeConn != nil {
			d.closeConn(p.network, p.addr)
		}
	}
}

// connToClose is a stream connection a retiring generation owned
// exclusively.
type connToClose struct {
	network string
	addr    string
}

// apply records one lookup outcome and reports the connections of
// generations it immediately retired, and whether the live set changed
// (a successful resolution). It takes mu only around the state change.
func (d *carrierDirectory) apply(c config.Carrier, now time.Time, addrs []netip.AddrPort, mode string, err error) ([]connToClose, bool) {
	d.mu.Lock()
	e := d.entries[c.Name]
	if e == nil {
		e = &carrierEntry{}
		d.entries[c.Name] = e
	}
	if err != nil || len(addrs) == 0 {
		if err == nil {
			err = errors.New("no addresses")
		}
		// Keep the current (last good) generation; retry soon.
		e.expiry = now.Add(carrierDNSNegTTL)
		if !e.failing {
			d.log.Warn("carrier DNS lookup failed; keeping the last good addresses",
				"carrier", c.Name, "host", c.Host, "err", err, "have", genAddrCount(e.cur))
		} else {
			d.log.Debug("carrier DNS lookup still failing", "carrier", c.Name, "err", err)
		}
		e.failing = true
		e.lastErr = err.Error()
		d.mu.Unlock()
		return nil, false
	}

	old := e.cur
	var retired []retirePair
	readopted := d.findRetainedLocked(c.Name, addrs)
	switch {
	case old != nil && sameAddrSet(old.addrs, addrs):
		// Same generation, re-resolved: extend its cache window. (The
		// weighted order SRV draws can change without the set changing.)
		old.resolvedAt, old.expiresAt, old.mode = now, now.Add(carrierDNSTTL), mode
		e.expiry = now.Add(carrierDNSTTL)
		if e.failing {
			d.log.Info("carrier DNS recovered", "carrier", c.Name, "host", c.Host,
				"generation", old.id, "addrs", sprintAddrs(old.addrs))
		}
		e.failing, e.lastErr = false, ""
		d.mu.Unlock()
		return nil, false

	case readopted != nil:
		// Switchback: the new answer is the set of a generation still
		// retained for existing traffic. Readopt it as current rather
		// than open a parallel generation to the same addresses.
		retired = d.supersedeLocked(e, readopted, now, true)
		readopted.born = genBirthSwitchback
		readopted.promotedAt = now
		readopted.resolvedAt, readopted.expiresAt, readopted.mode = now, now.Add(carrierDNSTTL), mode
		readopted.recordHandoff(now, "readopted", oldID(old), "")
		e.expiry = now.Add(carrierDNSTTL)
		e.failing, e.lastErr = false, ""
		d.log.Info("carrier address generation readopted on switchback",
			"carrier", c.Name, "generation", readopted.id, "addrs", sprintAddrs(addrs),
			"superseded", oldID(old))

	default:
		born := genBirthStartup
		if old != nil {
			born = genBirthRefresh
		}
		e.seq++
		ng := &carrierGen{
			id: e.seq, carrier: c.Name, transport: carrierTransport(c), addrs: addrs,
			state: genCurrent, mode: mode, born: born,
			resolvedAt: now, expiresAt: now.Add(carrierDNSTTL),
		}
		if old != nil {
			retired = d.supersedeLocked(e, ng, now, false)
			d.log.Info("carrier address generation changed",
				"carrier", c.Name, "host", c.Host, "generation", ng.id,
				"addrs", sprintAddrs(addrs), "superseded", old.id,
				"retained_pins", old.totalRefs())
		} else {
			e.cur = ng
			d.log.Info("carrier resolved", "carrier", c.Name, "host", c.Host,
				"generation", ng.id, "addrs", sprintAddrs(addrs))
		}
		e.expiry = now.Add(carrierDNSTTL)
		e.failing, e.lastErr = false, ""
	}

	d.publish()
	d.mu.Unlock()

	var closeConns []connToClose
	for _, p := range retired {
		for _, dest := range d.exclusiveOf(p.g, p.addrs) {
			closeConns = append(closeConns, connToClose{network: p.g.transport, addr: dest.String()})
		}
	}
	return closeConns, true
}

// retirePair is a generation retired at a handoff together with the
// address snapshot it had then.
type retirePair struct {
	g     *carrierGen
	addrs []netip.AddrPort
}

// supersedeLocked makes ng the current generation of e and retires or
// retains its previous current. When readopt is true ng is a retained
// generation being promoted (it is removed from the retained list). It
// returns the generations it retired immediately (no references) with
// the connections the new live set no longer shares. The caller holds
// mu and publishes afterwards.
func (d *carrierDirectory) supersedeLocked(e *carrierEntry, ng *carrierGen, now time.Time, readopt bool) []retirePair {
	old := e.cur
	ng.state = genCurrent
	if readopt {
		for i, r := range e.retained {
			if r == ng {
				e.retained = append(e.retained[:i], e.retained[i+1:]...)
				break
			}
		}
	}
	var retired []retirePair
	if old != nil {
		old.supersededAt, old.supersededBy = now, ng.id
		old.recordHandoff(now, genRetained.String(), ng.id, "")
		// Only a live registration, dialog or exchange keeps the old
		// generation; an idle pooled connection alone does not (it is
		// the route, not the work).
		if old.livePins() == 0 {
			old.state = genRetired
			old.retiredAt, old.retiredWhy = now, genRetireReplaced
			old.recordHandoff(now, genRetired.String(), ng.id, "superseded with no pinned traffic")
			addrs := d.exclusiveConnsLocked(old)
			d.buryLocked(old)
			retired = append(retired, retirePair{g: old, addrs: addrs})
		} else {
			old.state = genRetained
			old.recordHandoff(now, "retained", ng.id, "kept for pinned traffic")
			e.retained = append(e.retained, old)
		}
	}
	e.cur = ng
	return retired
}

// exclusiveOf recomputes a retired generation's exclusive addresses
// after the new snapshot has been published, so a just-published set is
// taken into account. The caller holds no lock.
func (d *carrierDirectory) exclusiveOf(g *carrierGen, cached []netip.AddrPort) []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	live := d.liveAddrsLocked()
	out := cached[:0]
	for _, a := range g.addrs {
		if !live[genAddr{transport: g.transport, addr: a}] {
			out = append(out, a)
		}
	}
	return out
}

// findRetainedLocked returns the retained generation of carrier whose
// address SET equals addrs (an address switchback), or nil. The caller
// holds mu.
func (d *carrierDirectory) findRetainedLocked(carrier string, addrs []netip.AddrPort) *carrierGen {
	e := d.entries[carrier]
	if e == nil {
		return nil
	}
	for _, g := range e.retained {
		if sameAddrSet(g.addrs, addrs) {
			return g
		}
	}
	return nil
}

// sameAddrSet compares two address lists as sets: SRV's weighted order
// can reorder the same targets between two resolutions.
func sameAddrSet(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[netip.AddrPort]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x] == 0 {
			return false
		}
		seen[x]--
	}
	return true
}

func oldID(g *carrierGen) uint64 {
	if g == nil {
		return 0
	}
	return g.id
}

func genAddrCount(g *carrierGen) int {
	if g == nil {
		return 0
	}
	return len(g.addrs)
}

func sprintAddrs(addrs []netip.AddrPort) string { return fmt.Sprint(addrs) }

// Run refreshes the directory until ctx ends: once at once, then whenever
// an entry's cache window has passed (checked at half the negative TTL).
func (d *carrierDirectory) Run(ctx context.Context) {
	d.refresh(ctx)
	t := time.NewTicker(carrierDNSNegTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.refresh(ctx)
		}
	}
}

// resolve returns the destinations of one DNS-name carrier, in preference
// order, and how they resolved (carrierModeSRV or carrierModeA).
func (d *carrierDirectory) resolve(ctx context.Context, c config.Carrier) ([]netip.AddrPort, string, error) {
	if c.ExplicitPort {
		addrs, err := d.hostAddrs(ctx, c.Host, uint16(c.Port))
		return addrs, carrierModeA, err
	}
	service, proto := srvName(c.Transport)
	sctx, cancel := context.WithTimeout(ctx, carrierLookupTimeout)
	_, recs, err := d.lookupSRV(sctx, service, proto, c.Host)
	cancel()
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return nil, "", fmt.Errorf("srv lookup: %w", err)
		}
		recs = nil // no SRV record: fall back to the host itself
	}
	var out []netip.AddrPort
	var lastErr error
	for _, t := range orderSRV(recs, d.rnd) {
		addrs, err := d.hostAddrs(ctx, t.host, t.port)
		if err != nil {
			lastErr = err
			continue
		}
		out = append(out, addrs...)
	}
	if len(out) > 0 {
		return dedupeAddrPorts(out), carrierModeSRV, nil
	}
	if len(recs) > 0 && lastErr != nil {
		return nil, "", lastErr // SRV exists but none of its targets resolved
	}
	addrs, err := d.hostAddrs(ctx, c.Host, uint16(c.DialPort()))
	return addrs, carrierModeA, err
}

// srvName is the SRV service and protocol of a carrier transport (RFC 3263
// §4.2): _sip._udp, _sip._tcp, and _sips._tcp for tls.
func srvName(transport string) (service, proto string) {
	switch transport {
	case config.CarrierTLS:
		return "sips", "tcp"
	case config.CarrierTCP:
		return "sip", "tcp"
	}
	return "sip", "udp"
}

// hostAddrs resolves host to A/AAAA addresses on port.
func (d *carrierDirectory) hostAddrs(ctx context.Context, host string, port uint16) ([]netip.AddrPort, error) {
	lctx, cancel := context.WithTimeout(ctx, carrierLookupTimeout)
	defer cancel()
	ips, err := d.lookupIP(lctx, host)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", host, err)
	}
	out := make([]netip.AddrPort, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap().WithZone("")
		if ip.IsUnspecified() {
			continue
		}
		out = append(out, netip.AddrPortFrom(ip, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("lookup %s: no addresses", host)
	}
	return out, nil
}

func dedupeAddrPorts(in []netip.AddrPort) []netip.AddrPort {
	seen := map[netip.AddrPort]bool{}
	out := in[:0]
	for _, a := range in {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// srvTarget is one usable SRV record.
type srvTarget struct {
	host string
	port uint16
}

// orderSRV orders SRV records by priority ascending, then by RFC 2782
// weighted-random selection within each priority. Records whose target is
// "." (service unavailable) or whose port is 0 are skipped.
func orderSRV(recs []*net.SRV, rnd *rand.Rand) []srvTarget {
	byPrio := map[uint16][]*net.SRV{}
	var prios []uint16
	for _, rec := range recs {
		if rec.Target == "." || rec.Port == 0 {
			continue
		}
		if _, seen := byPrio[rec.Priority]; !seen {
			prios = append(prios, rec.Priority)
		}
		byPrio[rec.Priority] = append(byPrio[rec.Priority], rec)
	}
	sort.Slice(prios, func(i, j int) bool { return prios[i] < prios[j] })

	var out []srvTarget
	for _, p := range prios {
		// RFC 2782: weight-0 records go first, so they keep a small chance
		// of being picked.
		var zeros, nonzeros []*net.SRV
		for _, rec := range byPrio[p] {
			if rec.Weight == 0 {
				zeros = append(zeros, rec)
			} else {
				nonzeros = append(nonzeros, rec)
			}
		}
		group := append(zeros, nonzeros...)
		for len(group) > 0 {
			total := 0
			for _, rec := range group {
				total += int(rec.Weight)
			}
			pick := 0
			if total == 0 {
				pick = rnd.Intn(len(group))
			} else {
				target := rnd.Intn(total + 1) // 0..total inclusive
				acc := 0
				for i, rec := range group {
					acc += int(rec.Weight)
					if acc >= target {
						pick = i
						break
					}
				}
			}
			rec := group[pick]
			out = append(out, srvTarget{host: strings.TrimSuffix(rec.Target, "."), port: rec.Port})
			group = append(group[:pick], group[pick+1:]...)
		}
	}
	return out
}

// CarrierInfo is the operator view of one configured carrier.
type CarrierInfo struct {
	Name string
	// Host is the configured host[:port] as written.
	Host      string
	Transport string
	// Mode is "literal", "srv" or "a" (A/AAAA). Empty until a lookup has
	// succeeded.
	Mode string
	// Addresses are the CURRENT generation's destinations in preference
	// order; the first is the one in use.
	Addresses []CarrierAddress
	// GenerationID is the current generation's id, 0 while unresolved.
	GenerationID uint64
	// Generations is the generation ledger: the current one, retained ones
	// still carrying traffic, and the most recently retired ones.
	Generations []CarrierGenerationInfo
	// ResolvedAt and ExpiresAt bound the cache window; both are zero for a
	// literal or an unresolved carrier. A failing carrier's ExpiresAt is
	// its next retry.
	ResolvedAt time.Time
	ExpiresAt  time.Time
	// Failing is true while the latest lookup failed (the current
	// generation, if any, is the last good set). LastError is its text.
	Failing   bool
	LastError string
}

// CarrierAddress is one resolved carrier destination.
type CarrierAddress struct {
	Address string // "IP:port"
	InUse   bool
}

// CarrierGenRefs is what still pins one generation, by kind.
type CarrierGenRefs struct {
	Connections   int
	Registrations int
	Dialogs       int
	Transactions  int
}

// CarrierGenHandoff is one recorded generation transition.
type CarrierGenHandoff struct {
	At         time.Time
	Kind       string // "superseded", "retained", "readopted", "retired", "closed"
	Generation uint64 // the other generation in the handoff
	Detail     string
}

// CarrierGenerationInfo is the operator view of one carrier generation.
type CarrierGenerationInfo struct {
	ID           uint64
	State        string // current, retained, retired, closed
	Mode         string // literal, srv, a
	Born         string // literal, startup, refresh, switchback
	Addresses    []string
	ResolvedAt   time.Time
	SupersededAt time.Time
	RetiredAt    time.Time
	ClosedAt     time.Time
	SupersededBy uint64
	Refs         CarrierGenRefs
	Handoffs     []CarrierGenHandoff
}

// snapshotInfo copies the state of every configured carrier under mu, sorted by
// name. The result is never nil.
func (d *carrierDirectory) snapshotInfo() []CarrierInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]CarrierInfo, 0, len(d.carriers))
	for _, c := range d.carriers {
		host := c.Host
		if c.ExplicitPort {
			host = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
		}
		transport := carrierTransport(c)
		info := CarrierInfo{Name: c.Name, Host: host, Transport: transport, Addresses: []CarrierAddress{}}
		if c.Literal() {
			g := d.statics[c.Name]
			info.Mode = carrierModeLiteral
			if g != nil {
				info.GenerationID = g.id
				info.Addresses = addrsInfo(g.addrs, true)
				info.Generations = []CarrierGenerationInfo{d.genInfo(g)}
			}
			out = append(out, info)
			continue
		}
		if e := d.entries[c.Name]; e != nil {
			info.Failing, info.LastError = e.failing, e.lastErr
			info.ExpiresAt = e.expiry // the next retry while unresolved too
			if e.cur != nil {
				info.Mode = e.cur.mode
				info.GenerationID = e.cur.id
				info.ResolvedAt = e.cur.resolvedAt
				info.Addresses = addrsInfo(e.cur.addrs, true)
				info.Generations = append(info.Generations, d.genInfo(e.cur))
			} else {
				info.Addresses = []CarrierAddress{}
			}
			for _, g := range e.retained {
				info.Generations = append(info.Generations, d.genInfo(g))
			}
			for i := len(e.history) - 1; i >= 0; i-- {
				info.Generations = append(info.Generations, d.genInfo(e.history[i]))
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// addrsInfo renders a generation's addresses, marking the first in use.
func addrsInfo(addrs []netip.AddrPort, firstInUse bool) []CarrierAddress {
	out := make([]CarrierAddress, 0, len(addrs))
	for i, a := range addrs {
		out = append(out, CarrierAddress{Address: a.String(), InUse: firstInUse && i == 0})
	}
	return out
}

// genInfo copies one generation for the operator view. The caller holds
// d.mu.
func (d *carrierDirectory) genInfo(g *carrierGen) CarrierGenerationInfo {
	addresses := make([]string, 0, len(g.addrs))
	for _, a := range g.addrs {
		addresses = append(addresses, a.String())
	}
	handoffs := make([]CarrierGenHandoff, 0, len(g.handoffs))
	for _, h := range g.handoffs {
		handoffs = append(handoffs, CarrierGenHandoff{
			At: h.At, Kind: h.Kind, Generation: h.OtherGen, Detail: h.Detail,
		})
	}
	return CarrierGenerationInfo{
		ID: g.id, State: g.state.String(), Mode: g.mode, Born: g.born,
		Addresses:  addresses,
		ResolvedAt: g.resolvedAt, SupersededAt: g.supersededAt,
		RetiredAt: g.retiredAt, ClosedAt: g.closedAt, SupersededBy: g.supersededBy,
		Refs: CarrierGenRefs{
			Connections: g.refs[refConn], Registrations: g.refs[refReg],
			Dialogs: g.refs[refDialog], Transactions: g.refs[refTx],
		},
		Handoffs: handoffs,
	}
}

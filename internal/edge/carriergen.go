package edge

import (
	"net/netip"
	"time"

	"github.com/freesbc/freesbc/internal/config"
)

// This file is the carrier address-generation model behind the directory
// (carrierdns.go).
//
// Every successful DNS resolution that changes a carrier's address set
// opens a new GENERATION: an immutable address list with a monotonically
// increasing id. The newest generation is the current one; it alone is
// picked for a new request. A generation that was current once is kept
// alive, as a RETAINED one, for as long as existing work is pinned to it:
// a stream connection to one of its addresses, a live carrier REGISTER
// binding made through it, or a dialog opened on it. While retained its
// addresses keep their carrier-source qualification, so the responses,
// in-dialog requests and registration-return traffic still bound to the
// old addresses are recognised and routed; but no new request is ever
// sent to them. Once its last reference is gone the generation is
// RETIRED: its connections are closed and its addresses leave the source
// set, all of it recorded as a handoff the operator can still query.
//
// Resolution failures never open a generation: the current one, with its
// last good addresses, stays current and usable. A resolution that
// returns the set of a still-retained generation READOPTS it as current
// (an address switchback) instead of opening another one. A literal-IP
// carrier has one static generation for the life of the process.

// carrierGenState is where one generation stands.
type carrierGenState uint8

const (
	// genCurrent is the generation new requests select.
	genCurrent carrierGenState = iota
	// genRetained was superseded but is still pinned by existing
	// connections, registrations or dialogs.
	genRetained
	// genRetired has no references left: its connections are closed and
	// its addresses are no carrier sources.
	genRetired
	// genClosed was still live when the process shut down.
	genClosed
)

func (s carrierGenState) String() string {
	switch s {
	case genCurrent:
		return "current"
	case genRetained:
		return "retained"
	case genRetired:
		return "retired"
	case genClosed:
		return "closed"
	}
	return "unknown"
}

// How a generation became current.
const (
	genBirthLiteral    = "literal"
	genBirthStartup    = "startup"
	genBirthRefresh    = "refresh"
	genBirthSwitchback = "switchback"
)

// Why a generation retired.
const (
	genRetireReplaced = "superseded" // replaced with no references, at handoff
	genRetireDrained  = "drained"    // its last reference was released
)

// refKind names what pins a retained generation, so the operator view can
// say what is still keeping old addresses alive.
type refKind uint8

const (
	refConn   refKind = iota // an open tcp/tls connection to a generation address
	refReg                   // a live carrier REGISTER binding
	refDialog                // an open dialog
	refTx                    // a request/response exchange in flight
	numRefKinds
)

// carrierGen is one address generation of one carrier. Its identity — id,
// carrier, transport, addrs — is set once and read lock-free from a
// published snapshot. Everything mutable is guarded by carrierDirectory.mu.
type carrierGen struct {
	id        uint64
	carrier   string
	transport string
	addrs     []netip.AddrPort
	// static is the one permanent generation of a literal-IP carrier: it is
	// never superseded, retired or reference-counted.
	static bool

	state genState

	mode       string // carrierModeLiteral, carrierModeSRV or carrierModeA
	born       string // genBirth*
	resolvedAt time.Time
	expiresAt  time.Time // end of the cache window of the resolution that last (re)adopted it

	supersededAt time.Time
	supersededBy uint64
	promotedAt   time.Time // readopted as current on a switchback
	retiredAt    time.Time
	retiredWhy   string
	closedAt     time.Time

	refs [numRefKinds]int

	handoffs []genHandoff
}

// genState is exported in the field name sense only through methods; keep
// the field name short via an alias type to avoid churn below.
type genState = carrierGenState

// totalRefs is how many pins the generation currently holds.
func (g *carrierGen) totalRefs() int {
	n := 0
	for _, r := range g.refs {
		n += r
	}
	return n
}

// livePins counts the pins that represent existing work: registrations,
// dialogs and exchanges. A connection is only the route that work takes,
// so a superseded generation whose only pins are connections is drained
// (its connections are closed) rather than keeping a decommissioned
// gateway a carrier source forever.
func (g *carrierGen) livePins() int {
	return g.refs[refReg] + g.refs[refDialog] + g.refs[refTx]
}

// genHandoff is one recorded transition of a generation, kept so the
// operator can query how an address set was taken over, readopted,
// drained or closed after the fact.
type genHandoff struct {
	At       time.Time
	Kind     string // genState of the resulting side, or "readopted"
	OtherGen uint64 // the other generation in the handoff, when there is one
	Detail   string
}

// recordHandoff appends one bounded handoff record to a generation.
func (g *carrierGen) recordHandoff(at time.Time, kind string, other uint64, detail string) {
	g.handoffs = append(g.handoffs, genHandoff{At: at, Kind: kind, OtherGen: other, Detail: detail})
	if len(g.handoffs) > carrierGenHistory {
		g.handoffs = g.handoffs[len(g.handoffs)-carrierGenHistory:]
	}
}

// carrierGenHistory bounds the handoff records kept per generation.
const carrierGenHistory = 8

// acquire pins g for one reference of kind. It reports false once the
// generation has retired or the directory is closing: a caller that then
// still names the old address must not use it (requireFlow answers with
// errNoFlow, admission drops). A literal generation always succeeds.
// caller holds no lock.
func (d *carrierDirectory) acquire(g *carrierGen, kind refKind) bool {
	if g == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if g.static {
		return true
	}
	if d.closed || g.state == genRetired || g.state == genClosed {
		return false
	}
	g.refs[kind]++
	return true
}

// release undoes one acquire. A retained generation whose last reference
// is released retires here: it is buried, a new snapshot revokes its
// source qualification, and the connections no other live generation
// shares are closed. caller holds no lock.
func (d *carrierDirectory) release(g *carrierGen, kind refKind) {
	if g == nil || g.static {
		return
	}
	d.mu.Lock()
	if d.closed || g.state == genRetired || g.state == genClosed {
		d.mu.Unlock()
		return
	}
	if g.refs[kind] > 0 {
		g.refs[kind]--
	}
	// Retire once no registration, dialog or exchange is pinned any
	// more: the connections then have nothing left to carry, so they
	// are closed and the old addresses lose their source qualification.
	if g.state != genRetained || g.livePins() > 0 {
		d.mu.Unlock()
		return
	}
	g.state = genRetired
	g.retiredAt = d.now()
	g.retiredWhy = genRetireDrained
	g.recordHandoff(g.retiredAt, genRetired.String(), 0, "last pinned registration, dialog or exchange ended")
	d.buryLocked(g) // take it out of the live set BEFORE measuring exclusivity
	conns := d.exclusiveConnsLocked(g)
	d.publish()
	d.mu.Unlock()

	d.closeGenConns(g, conns)
}

// exclusiveConnsLocked lists the transport/address pairs of g that no
// other LIVE generation still names: only those may be closed when g
// retires, so an address two generations share stays open.
// caller holds d.mu.
func (d *carrierDirectory) exclusiveConnsLocked(g *carrierGen) []netip.AddrPort {
	if g.transport == config.CarrierUDP || g.static {
		return nil
	}
	live := d.liveAddrsLocked()
	out := make([]netip.AddrPort, 0, len(g.addrs))
	for _, a := range g.addrs {
		if !live[genAddr{transport: g.transport, addr: a}] {
			out = append(out, a)
		}
	}
	return out
}

// genAddr identifies a stream destination across generations.
type genAddr struct {
	transport string
	addr      netip.AddrPort
}

// closeGenConns closes the pooled stream connections to addrs of g. It is
// the one place retirement frees a connection: the normal read-error and
// idle paths close them through streamConn.Close.
func (d *carrierDirectory) closeGenConns(g *carrierGen, addrs []netip.AddrPort) {
	if len(addrs) == 0 || d.closeConn == nil {
		return
	}
	for _, a := range addrs {
		d.closeConn(g.transport, a.String())
	}
	if d.log != nil {
		d.log.Info("carrier address generation retired; closed its connections",
			"carrier", g.carrier, "generation", g.id, "addrs", sprintAddrs(addrs), "reason", g.retiredWhy)
	}
}

// currentGen returns the carrier's current generation, if it has resolved.
func (d *carrierDirectory) currentGen(name string) (*carrierGen, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if e := d.entries[name]; e != nil && e.cur != nil {
		return e.cur, true
	}
	if g := d.statics[name]; g != nil {
		return g, true
	}
	return nil, false
}

// genByDest names the live (current or retained) generation whose
// resolved set contains dest on network, for a stream request FreeSBC is
// about to send. It is the dial guard: a destination only a retired
// generation named is no carrier destination, so sipgo never dials it and
// a pinned request whose generation is gone fails as it would for any
// lost flow.
func (d *carrierDirectory) genByDest(network, dest string) (carrier string, g *carrierGen, ok bool) {
	snap := d.snap.Load()
	for _, name := range snap.names {
		if snap.transports[name] != network {
			continue
		}
		for _, lg := range snap.live[name] {
			for _, a := range lg.addrs {
				if a.String() == dest {
					carrier, g, ok = name, lg, true
					break
				}
			}
			if ok {
				break
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		return "", nil, false
	}
	// A publish that retires g may lag the pointer in the snapshot by a
	// hair; the authoritative state is under mu.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || (g.state != genCurrent && g.state != genRetained) {
		return "", nil, false
	}
	return carrier, g, true
}

// sourceGen is carrierFor plus the generation the source matched: the
// current generation first (an address two generations share belongs to
// the new one), then retained ones. A match on edge.carrier_sources alone
// returns the carrierUnknown name and no generation.
func (d *carrierDirectory) sourceGen(src netip.AddrPort, network string) (name string, g *carrierGen, ok bool) {
	return d.snap.Load().sourceGen(src, network)
}

// shutdown marks every live generation closed, recording the final
// handoff (with what still referenced it) so the generation ledger stays
// queryable during shutdown and the log carries the handover. It closes
// nothing itself: the listener teardown in Run closes every carrier
// connection as part of process shutdown.
func (d *carrierDirectory) shutdown() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	now := d.now()
	var all []*carrierGen
	for _, e := range d.entries {
		if e.cur != nil {
			all = append(all, e.cur)
		}
		all = append(all, e.retained...)
	}
	for _, g := range all {
		if g.state == genRetired {
			continue
		}
		refs := g.totalRefs()
		g.state = genClosed
		g.closedAt = now
		g.recordHandoff(now, genClosed.String(), 0,
			"process shutdown; references at close: "+itoa(refs))
		// Retained generations leave the live set for the history; the
		// current one stays cur (a closed process neither admits nor
		// sends) and is not logged twice.
		if e := d.entries[g.carrier]; e != nil && e.cur != g {
			d.buryLocked(g)
		}
	}
	d.publish()
	d.mu.Unlock()

	for _, g := range all {
		if g.state != genClosed {
			continue
		}
		d.log.Info("carrier address generation closed with the process",
			"carrier", g.carrier, "generation", g.id, "state", "closed",
			"addrs", sprintAddrs(g.addrs), "references", g.totalRefs())
	}
}

// itoa avoids importing strconv for one debug string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

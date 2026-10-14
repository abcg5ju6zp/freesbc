package edge

import (
	"errors"
	fsip "github.com/freesbc/freesbc/internal/sip"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Binding is one registered contact: everything the proxy needs to deliver
// an inbound request to a client, and nothing more.
//
// It is deliberately NOT a registration record. FreeSWITCH is the
// authoritative registrar: it owns the AoR, the credentials and the
// authoritative expiry. This table exists only because an inbound request
// from FreeSWITCH arrives addressed to a contact FreeSBC invented, and
// something has to turn that back into a real client address — and, for
// WebSocket clients, into the specific connection that client is on.
type Binding struct {
	// Token is the opaque identifier FreeSBC put in the Contact it
	// registered upstream. FreeSWITCH echoes it in the Request-URI of an
	// inbound request, which is how one of a user's several devices is
	// picked out.
	Token string
	// AOR is the address-of-record, "user@domain", lower-cased.
	AOR string
	// User is the AoR's user part, used to build the Request-URI sent to
	// the client.
	User string
	// Transport is the public transport the client registered over.
	Transport string
	// Source is the transport source address the REGISTER actually came
	// from. This — never the Contact host — is where requests are sent:
	// it is the far side of the client's NAT pinhole for UDP, and the
	// pooled connection key for WS/WSS.
	Source netip.AddrPort
	// ExpiresAt is when FreeSWITCH said the registration lapses. It is
	// taken from the 200 OK, never from the phone's request: the registrar
	// may grant less than was asked for.
	ExpiresAt time.Time
	// CallID and CSeq identify the registration flow, so a refresh
	// replaces the right binding rather than creating a second one.
	CallID string
	// FlowID is the stream connection (tcp, tls, ws, wss) this
	// registration was accepted over, fixed at the successful REGISTER.
	// Zero means UDP: the binding owns no connection the proxy can close
	// and is left to its registrar-granted expiry. Cleanup of a closed
	// connection removes a binding by THIS, never by Source: a new
	// connection that reused the same transport and IP:port gets its own
	// flow ID and is invisible to the old connection's retirement.
	FlowID flowID
	// gen is the binding version: 1 on first insert, incremented on every
	// accepted refresh. A registrar response observed an earlier gen
	// (an un-REGISTER or a granted REGISTER whose answer was delayed) may
	// only retire or overwrite the binding while that gen is still
	// current; a replacement registration wins and stays.
	gen uint64
}

// Expired reports whether the binding has lapsed as of now.
func (b *Binding) Expired(now time.Time) bool { return !now.Before(b.ExpiresAt) }

// Location is the runtime table of registration bindings.
//
// Bounded on purpose (spec §16): an unauthenticated flood of REGISTERs
// that FreeSWITCH happens to accept must not be able to grow this map
// without limit. Entries are keyed by token and indexed by AoR and by
// transport source. The three maps always hold the same set of bindings:
// every insertion goes through Put and every removal through
// deleteLocked.
type Location struct {
	mu      sync.RWMutex
	byToken map[string]*Binding
	byAOR   map[string][]*Binding
	// bySource indexes bindings by the transport source address the
	// REGISTER came from (Binding.Source). It is what the INVITE admission
	// check (HasSource) looks up, so it does not scan the table. One
	// source may hold several bindings (a phone registering several lines
	// over one socket); it is deliberately NOT what a connection close
	// retires by, because a new connection may reuse the same address.
	bySource map[netip.AddrPort][]*Binding
	// byIP counts the bindings per source IP (HasIP), so the admission
	// strike exemption is a map lookup, not a scan.
	byIP map[netip.Addr]int
	// byFlow indexes bindings by the stream connection that owns them
	// (Binding.FlowID); it is the ONLY index a connection close retires
	// by. UDP bindings (flow 0) are not in it. One flow may hold several
	// bindings (a phone registering several lines over one socket).
	byFlow   map[flowID][]*Binding
	maxTotal int
	// maxPerAOR caps how many devices one user may have registered at
	// once, so a single compromised account cannot consume the table.
	maxPerAOR int

	// flowAlive reports whether a stream flow is still open. Commit
	// consults it before installing a stream binding, so the delayed 2xx
	// of a REGISTER sent over a connection that has since closed cannot
	// land a binding aimed at a dead socket. nil (table tests) accepts
	// every flow.
	flowAlive func(id flowID) bool

	// onRemove, when set, is told the tokens of bindings that left the
	// table (SetOnRemove). removed collects them under mu; the mutating
	// methods hand them over only after mu is released, so the hook may
	// take its own locks without an ordering constraint.
	onRemove func(tokens []string)
	removed  []string
}

// Default table bounds. A single node targets a few thousand
// registrations; 20 000 leaves generous headroom while still being a
// bound. Ten devices per user is far above real usage.
const (
	defaultMaxBindings = 20000
	defaultMaxPerAOR   = 10
)

// ErrTooManyBindings is returned when the table is full; the caller maps
// it to a 503 rather than silently dropping the registration.
type ErrTooManyBindings struct{ Scope string }

func (e *ErrTooManyBindings) Error() string {
	return "proxy: registration table full (" + e.Scope + ")"
}

func NewLocation() *Location {
	return &Location{
		byToken:   map[string]*Binding{},
		byAOR:     map[string][]*Binding{},
		bySource:  map[netip.AddrPort][]*Binding{},
		byIP:      map[netip.Addr]int{},
		byFlow:    map[flowID][]*Binding{},
		maxTotal:  defaultMaxBindings,
		maxPerAOR: defaultMaxPerAOR,
	}
}

// ErrStaleBinding is returned by Commit when the registrar response does
// not correspond to the binding version the edge observed when it
// forwarded the REGISTER: another registration superseded it, its flow has
// closed, or its binding already left the table. The response is ignored
// rather than overwriting newer state.
var ErrStaleBinding = errors.New("proxy: registration response stale to a newer binding")

// Put installs or refreshes a binding UNCONDITIONALLY. It is the test and
// administrative back door; the REGISTER response path uses Commit, which
// compares the binding version it observed. A refresh is recognised by the
// (AoR, Call-ID) pair — the same client re-registering — and reuses the
// existing token, so the contact FreeSWITCH has stored stays valid across
// refreshes.
//
// It returns the stored binding, whose Token is the one to advertise
// upstream.
func (l *Location) Put(b Binding) (*Binding, error) {
	return l.commit(b, 0, true)
}

// Commit installs or refreshes a binding from a successful registrar
// response, and only while the response is still authoritative:
//
//   - observedGen 0 expects no live binding for the (AoR, Call-ID) pair —
//     a first registration. If one exists, another REGISTER won and the
//     response is stale.
//   - observedGen > 0 expects that exact binding version. A replacement
//     registration (another connection, a re-REGISTER) bumps the gen and a
//     delayed response then changes nothing: it can neither move the
//     binding back onto a closed socket nor shorten a newer expiry.
//
// A stream binding whose flow is no longer open is refused the same way:
// a 200 that arrives after its connection closed cannot be delivered to.
// ErrStaleBinding distinguishes these from ErrTooManyBindings.
func (l *Location) Commit(b Binding, observedGen uint64) (*Binding, error) {
	return l.commit(b, observedGen, false)
}

func (l *Location) commit(b Binding, observedGen uint64, force bool) (*Binding, error) {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Only THIS AoR is swept, not the whole table: a REGISTER is the
	// hottest path here and sweeping every binding on each one makes the
	// cost of one registration grow with the size of the table. What the
	// sweep is needed for is local — a device whose previous binding has
	// lapsed must not count against the per-AoR cap — and reclaiming
	// everyone else's expired bindings is the periodic Prune's job.
	l.pruneAORLocked(b.AOR, time.Now())

	if !force && b.FlowID != 0 && l.flowAlive != nil && !l.flowAlive(b.FlowID) {
		// The response's connection is gone; its binding is retired or
		// about to be, and installing here would aim requests at a socket
		// nobody holds.
		return nil, ErrStaleBinding
	}

	existing := l.byAOR[b.AOR]
	for _, e := range existing {
		if e.CallID != b.CallID {
			continue
		}
		if !force && (observedGen == 0 || e.gen != observedGen) {
			// A version this response did not observe is installed: the
			// newer registration's own success or expiry is the fresher
			// registrar judgement. Leave it and hand it back so the caller
			// does not count a new registration.
			return e, ErrStaleBinding
		}
		// Refresh in place: the token must not change, or FreeSWITCH
		// would be left holding a contact that no longer resolves.
		b.Token = e.Token
		b.gen = e.gen + 1
		// The refresh may come from a new source on a new flow (the phone
		// reconnected), so re-index under both.
		l.unindexLocked(e)
		*e = b
		l.indexLocked(e)
		return e, nil
	}
	// No live binding for the (AoR, Call-ID). A first registration
	// (observedGen 0) installs with a minted token. A renewal whose
	// previous binding already expired and was pruned before its fresh
	// grant arrived is the same registrar judgement with a new lifetime,
	// so it installs with the token it kept — a refresh that observed
	// something only ever carries that binding's own token, and the
	// retired-flow case was rejected above.
	if !force && b.Token != "" {
		if _, taken := l.byToken[b.Token]; taken {
			// The token belongs to another live identity: this response
			// cannot take it over.
			return nil, ErrStaleBinding
		}
	}
	if len(existing) >= l.maxPerAOR {
		return nil, &ErrTooManyBindings{Scope: "per address-of-record"}
	}
	if len(l.byToken) >= l.maxTotal {
		return nil, &ErrTooManyBindings{Scope: "total"}
	}
	if b.Token == "" {
		b.Token = fsip.NewToken()
	}
	b.gen = 1
	nb := &b
	l.byToken[nb.Token] = nb
	l.byAOR[nb.AOR] = append(l.byAOR[nb.AOR], nb)
	l.indexLocked(nb)
	return nb, nil
}

// bindingObs identifies one observed binding version: the token the
// registrar holds and the gen it had when a cleanup decision was made.
type bindingObs struct {
	Token string
	Gen   uint64
}

// ObservedBinding returns the live (AoR, Call-ID) binding's identity, for
// a REGISTER to stamp the response path with the version it is allowed to
// retire or replace.
func (l *Location) ObservedBinding(aor, callID string) (bindingObs, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, e := range l.byAOR[aor] {
		if e.CallID == callID && !e.Expired(time.Now()) {
			return bindingObs{Token: e.Token, Gen: e.gen}, true
		}
	}
	return bindingObs{}, false
}

// ObservedAOR returns the identity of every live binding of an
// address-of-record: the set a wildcard ("Contact: *") un-REGISTER may
// retire when its response returns.
func (l *Location) ObservedAOR(aor string) []bindingObs {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	var out []bindingObs
	for _, e := range l.byAOR[aor] {
		if !e.Expired(now) {
			out = append(out, bindingObs{Token: e.Token, Gen: e.gen})
		}
	}
	return out
}

// Remove drops the binding for an (AoR, Call-ID) pair unconditionally. It
// is the test/back-door counterpart of Put; response paths use
// RetireObserved.
func (l *Location) Remove(aor, callID string) *Binding {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	list := l.byAOR[aor]
	for i, e := range list {
		if e.CallID == callID {
			b := *list[i]
			l.deleteLocked(aor, i)
			return &b
		}
	}
	return nil
}

// RetireObserved drops the (AoR, Call-ID) binding only while it is still
// the version observedGen identified — the explicit un-REGISTER path. A
// binding replaced (new gen) or already gone after the decision is left
// untouched, and the method reports nil.
func (l *Location) RetireObserved(aor, callID string, observedGen uint64) *Binding {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	if observedGen == 0 {
		return nil
	}
	list := l.byAOR[aor]
	for i, e := range list {
		if e.CallID != callID {
			continue
		}
		if e.gen != observedGen {
			return nil
		}
		b := *list[i]
		l.deleteLocked(aor, i)
		return &b
	}
	return nil
}

// RetireAOR drops the bindings of an AoR a wildcard un-REGISTER observed,
// version by version: only the exact (token, gen) pairs leave, so a device
// that registered between the request and the response keeps its binding.
// It returns the retired bindings.
func (l *Location) RetireAOR(aor string, observed []bindingObs) []Binding {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	want := make(map[string]uint64, len(observed))
	for _, o := range observed {
		want[o.Token] = o.Gen
	}
	var out []Binding
	for _, e := range append([]*Binding(nil), l.byAOR[aor]...) {
		if gen, ok := want[e.Token]; ok && gen == e.gen {
			for i, x := range l.byAOR[aor] {
				if x == e {
					out = append(out, *x)
					l.deleteLocked(aor, i)
					break
				}
			}
		}
	}
	return out
}

// RetireFlow drops every binding owned by flowID — the connection close
// path — and returns the retired bindings. The flow ID is fixed for a
// connection's life, so a newer connection that reuses the same transport
// and source address, and an unconnected UDP binding (flow 0), are never
// touched. Bindings the expiry scan or an un-REGISTER removed first are
// simply absent.
func (l *Location) RetireFlow(id flowID) []Binding {
	if id == 0 {
		return nil
	}
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Binding
	for _, b := range append([]*Binding(nil), l.byFlow[id]...) {
		for i, e := range l.byAOR[b.AOR] {
			if e == b {
				out = append(out, *e)
				l.deleteLocked(b.AOR, i)
				break
			}
		}
	}
	return out
}

// HasSource reports whether a live (unexpired) binding was registered over
// transport from exactly src. It is the edge INVITE admission check: a
// public client may place a call from the transport address its
// registration came from. transport is compared case-insensitively.
func (l *Location) HasSource(transport string, src netip.AddrPort) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	for _, b := range l.bySource[src] {
		if strings.EqualFold(b.Transport, transport) && !b.Expired(now) {
			return true
		}
	}
	return false
}

// HasIP reports whether any binding (live, or expired and not yet pruned)
// was registered from ip on any port or transport.
func (l *Location) HasIP(ip netip.Addr) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.byIP[ip.Unmap()] > 0
}

// SourceBinding returns a live binding registered over transport from
// exactly src: the one whose User equals user (case-insensitively), else
// the first live one. ok is false when the source holds none. It is
// HasSource that also says which registration the source is.
func (l *Location) SourceBinding(transport string, src netip.AddrPort, user string) (Binding, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	var first *Binding
	for _, b := range l.bySource[src] {
		if !strings.EqualFold(b.Transport, transport) || b.Expired(now) {
			continue
		}
		if user != "" && strings.EqualFold(b.User, user) {
			return *b, true
		}
		if first == nil {
			first = b
		}
	}
	if first == nil {
		return Binding{}, false
	}
	return *first, true
}

// indexLocked adds b to the source, IP and flow indexes. Caller holds the
// lock.
func (l *Location) indexLocked(b *Binding) {
	l.bySource[b.Source] = append(l.bySource[b.Source], b)
	l.byIP[b.Source.Addr().Unmap()]++
	if b.FlowID != 0 {
		l.byFlow[b.FlowID] = append(l.byFlow[b.FlowID], b)
	}
}

// unindexLocked removes b from the source, IP and flow indexes. Caller
// holds the lock.
func (l *Location) unindexLocked(b *Binding) {
	ip := b.Source.Addr().Unmap()
	if l.byIP[ip] <= 1 {
		delete(l.byIP, ip)
	} else {
		l.byIP[ip]--
	}
	list := l.bySource[b.Source]
	for i, e := range list {
		if e == b {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(l.bySource, b.Source)
	} else {
		l.bySource[b.Source] = list
	}
	if b.FlowID != 0 {
		flows := l.byFlow[b.FlowID]
		for i, e := range flows {
			if e == b {
				flows = append(flows[:i], flows[i+1:]...)
				break
			}
		}
		if len(flows) == 0 {
			delete(l.byFlow, b.FlowID)
		} else {
			l.byFlow[b.FlowID] = flows
		}
	}
}

// deleteLocked removes index i of an AoR's list, and the binding from every
// other index. Caller holds the lock.
func (l *Location) deleteLocked(aor string, i int) {
	list := l.byAOR[aor]
	delete(l.byToken, list[i].Token)
	if l.onRemove != nil {
		l.removed = append(l.removed, list[i].Token)
	}
	l.unindexLocked(list[i])
	list = append(list[:i], list[i+1:]...)
	if len(list) == 0 {
		delete(l.byAOR, aor)
		return
	}
	l.byAOR[aor] = list
}

// SetOnRemove registers f to be told the tokens of bindings that are
// removed (un-REGISTER, WebSocket close, expiry, the per-AoR sweep in Put).
// f runs after the table's lock is released, on the goroutine that made the
// change, so it may take locks of its own. A binding that is refreshed in
// place keeps its token and is not reported. Call it before the table is
// shared.
func (l *Location) SetOnRemove(f func(tokens []string)) {
	l.mu.Lock()
	l.onRemove = f
	l.mu.Unlock()
}

// flushRemoved hands the tokens collected by deleteLocked to the hook. It
// must run with mu NOT held (the mutating methods defer it before taking
// the lock, so it runs after their unlock).
func (l *Location) flushRemoved() {
	l.mu.Lock()
	f, tokens := l.onRemove, l.removed
	l.removed = nil
	l.mu.Unlock()
	if f != nil && len(tokens) > 0 {
		f(tokens)
	}
}

// ByToken looks up the binding FreeSWITCH addressed. Expired bindings are
// not returned.
func (l *Location) ByToken(token string) (Binding, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	b, ok := l.byToken[token]
	if !ok || b.Expired(time.Now()) {
		return Binding{}, false
	}
	return *b, true
}

// ByAOR returns every live binding for an address-of-record. It is the
// fallback when an inbound Request-URI carries no token — for instance
// from a FreeSWITCH dialplan that rewrote the contact.
func (l *Location) ByAOR(aor string) []Binding {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	var out []Binding
	for _, b := range l.byAOR[strings.ToLower(aor)] {
		if !b.Expired(now) {
			out = append(out, *b)
		}
	}
	return out
}

// Count is the number of live bindings, for metrics.
func (l *Location) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.byToken)
}

// CountByKind splits the live binding count into UDP bindings (flow 0) and
// stream bindings owned by an open connection. It is the shutdown residual
// report: stream bindings left behind mean a flow cleanup did not finish,
// UDP bindings age out on their registrar-granted expiry.
func (l *Location) CountByKind() (udp, stream int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, b := range l.byToken {
		if b.FlowID == 0 {
			udp++
		} else {
			stream++
		}
	}
	return udp, stream
}

// Prune drops expired bindings. Called periodically by the proxy so a
// client that vanishes without un-registering does not hold an entry past
// its registrar-granted lifetime.
func (l *Location) Prune() int {
	defer l.flushRemoved()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pruneLocked(time.Now())
}

func (l *Location) pruneLocked(now time.Time) int {
	n := 0
	for aor := range l.byAOR {
		n += l.pruneAORLocked(aor, now)
	}
	return n
}

// pruneAORLocked drops one address-of-record's expired bindings and
// returns how many went. Caller holds the lock.
func (l *Location) pruneAORLocked(aor string, now time.Time) int {
	n := 0
	list := l.byAOR[aor]
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].Expired(now) {
			l.deleteLocked(aor, i)
			list = l.byAOR[aor]
			n++
		}
	}
	return n
}

// RegistrationInfo is the operator view of one live binding. It leaves out
// the fsbc token and the Call-ID.
type RegistrationInfo struct {
	AOR       string
	User      string
	Transport string
	Source    string // transport source "IP:port"
	ExpiresAt time.Time
}

// maxRegistrationPage bounds one Registrations page.
const maxRegistrationPage = 1000

// Registrations returns one page of the live bindings and the total number
// matching. A non-empty user keeps the bindings whose user part contains it,
// case-insensitively. The order is AoR, then source, then transport, so
// pages are stable. limit is clamped to 1..maxRegistrationPage and a
// negative offset is 0. Matches are copied under the read lock; sorting and
// slicing happen after it. The page is never nil.
func (l *Location) Registrations(user string, limit, offset int) (page []RegistrationInfo, total int) {
	limit = min(max(limit, 1), maxRegistrationPage)
	offset = max(offset, 0)
	user = strings.ToLower(strings.TrimSpace(user))
	now := time.Now()
	l.mu.RLock()
	all := make([]RegistrationInfo, 0, len(l.byToken))
	for _, b := range l.byToken {
		if b.Expired(now) || (user != "" && !strings.Contains(strings.ToLower(b.User), user)) {
			continue
		}
		all = append(all, RegistrationInfo{AOR: b.AOR, User: b.User, Transport: b.Transport,
			Source: b.Source.String(), ExpiresAt: b.ExpiresAt})
	}
	l.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool {
		if all[i].AOR != all[j].AOR {
			return all[i].AOR < all[j].AOR
		}
		if all[i].Source != all[j].Source {
			return all[i].Source < all[j].Source
		}
		return all[i].Transport < all[j].Transport
	})
	total = len(all)
	if offset >= total {
		return []RegistrationInfo{}, total
	}
	return append([]RegistrationInfo{}, all[offset:min(offset+limit, total)]...), total
}

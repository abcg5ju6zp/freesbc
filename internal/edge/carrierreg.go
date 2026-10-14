package edge

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	fsip "github.com/freesbc/freesbc/internal/sip"
)

// This file is the switch's registration at a carrier (issue #96, "Carrier
// path"): the switch REGISTERs a gateway through FreeSBC, and FreeSBC
// proxies it with the Contact rewritten to a public address that carries an
// opaque token. The carrier then sends inbound calls to that Contact, and
// the token tells FreeSBC which switch node registered it and what the
// switch's own Contact was, so the call is delivered to that node with its
// own Contact as the Request-URI (what FreeSWITCH gw+<name> and Asterisk
// line= identify an inbound call by).
//
// The table is separate from the client Location on purpose: a client token
// is random and names a public client, a carrier token is derived and names
// a switch registration. Neither lookup ever resolves the other's token.
//
// FreeSBC holds no credential here either: the 401/407 challenge and the
// retried REGISTER pass through untouched.

// carrierBinding is one live carrier registration.
type carrierBinding struct {
	token   string
	carrier string  // edge.carriers name
	node    string  // edge.switch node name ("IP:port")
	contact sip.Uri // the switch's original Contact
	expires time.Time
	// gen is the address generation the registration was made through.
	// Every refresh and the un-REGISTER are pinned to the same carrier,
	// transport and target address the binding's Contact lives at, and
	// the binding pins that generation (refReg) until it expires.
	gen *carrierGen
}

// carrierRegTable is the set of live carrier registrations by token.
type carrierRegTable struct {
	mu      sync.Mutex
	byToken map[string]carrierBinding
	// acquireGen/releaseGen balance a registration's generation pin
	// (refReg). Wired in New; nil in standalone table tests.
	acquireGen func(*carrierGen) bool
	releaseGen func(*carrierGen)
}

func newCarrierRegTable() *carrierRegTable {
	return &carrierRegTable{byToken: map[string]carrierBinding{}}
}

// put installs or refreshes a binding. A binding replacing one on another
// generation moves the registration pin; it is not stored when its
// generation already retired.
func (t *carrierRegTable) put(b carrierBinding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.byToken[b.token]
	if old.gen != b.gen {
		if b.gen != nil && t.acquireGen != nil && !t.acquireGen(b.gen) {
			return // the generation retired between the 200 and now
		}
		if old.gen != nil && t.releaseGen != nil {
			t.releaseGen(old.gen)
		}
	}
	t.byToken[b.token] = b
}

// remove deletes the binding with this token.
func (t *carrierRegTable) remove(token string) {
	t.mu.Lock()
	b, ok := t.byToken[token]
	if ok {
		delete(t.byToken, token)
	}
	t.mu.Unlock()
	if ok && b.gen != nil && t.releaseGen != nil {
		t.releaseGen(b.gen)
	}
}

// removeNode deletes every binding a switch node holds at a carrier (a
// wildcard un-REGISTER), releasing their generation pins.
func (t *carrierRegTable) removeNode(carrier, node string) {
	t.mu.Lock()
	var gens []*carrierGen
	for k, b := range t.byToken {
		if b.carrier == carrier && b.node == node {
			gens = append(gens, b.gen)
			delete(t.byToken, k)
		}
	}
	t.mu.Unlock()
	if t.releaseGen != nil {
		for _, g := range gens {
			if g != nil {
				t.releaseGen(g)
			}
		}
	}
}

// nodeGens returns the distinct live generations a node's bindings at one
// carrier are pinned to: where a wildcard un-REGISTER must go to actually
// reach every gateway still holding the node's contacts.
func (t *carrierRegTable) nodeGens(carrier, node string) []*carrierGen {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []*carrierGen
	seen := map[*carrierGen]bool{}
	for _, b := range t.byToken {
		if b.carrier == carrier && b.node == node && b.gen != nil &&
			time.Now().Before(b.expires) && !seen[b.gen] {
			seen[b.gen] = true
			out = append(out, b.gen)
		}
	}
	return out
}

// lookup finds a live binding. An expired one is not found (the periodic
// prune only reclaims it).
func (t *carrierRegTable) lookup(token string) (carrierBinding, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.byToken[token]
	if !ok || !time.Now().Before(b.expires) {
		return carrierBinding{}, false
	}
	return b, true
}

// prune drops expired bindings, releasing their generation pins, and
// reports how many.
func (t *carrierRegTable) prune() int {
	now := time.Now()
	n := 0
	var gens []*carrierGen
	t.mu.Lock()
	for k, b := range t.byToken {
		if !now.Before(b.expires) {
			gens = append(gens, b.gen)
			delete(t.byToken, k)
			n++
		}
	}
	t.mu.Unlock()
	if t.releaseGen != nil {
		for _, g := range gens {
			if g != nil {
				t.releaseGen(g)
			}
		}
	}
	return n
}

// counts is the live binding count per carrier, with every configured
// carrier present (zero included) so a gauge drops to 0 instead of
// vanishing.
func (t *carrierRegTable) counts(names []string) map[string]int {
	out := make(map[string]int, len(names))
	for _, n := range names {
		out[n] = 0
	}
	now := time.Now()
	t.mu.Lock()
	for _, b := range t.byToken {
		if now.Before(b.expires) {
			out[b.carrier]++
		}
	}
	t.mu.Unlock()
	return out
}

// publishCarrierRegistrations refreshes the per-carrier gauge.
func (s *Server) publishCarrierRegistrations() {
	names := make([]string, 0, len(s.carrierURIs))
	for _, n := range s.carrierURIs {
		names = append(names, n)
	}
	s.metrics.SetCarrierRegistrations(s.carrierRegs.counts(names))
}

// carrierToken derives the opaque token of a carrier registration from the
// switch node and its original Contact. It is deterministic so a FreeSBC
// restart does not strand the Contact the carrier already holds: the
// switch's next refresh recreates the same token. Anyone who can guess a
// node name and a Contact can compute it; the token is an identifier, not a
// secret, and the carrier path admits only carrier sources.
func carrierToken(node, contact string) string {
	sum := sha256.Sum256([]byte(node + "\n" + contact))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return strings.ToLower(enc[:26])
}

// carrierDest is where a NEW request for a carrier is sent: the first
// address of its CURRENT generation. There is no failover across a DNS
// name's targets or across generations inside FreeSBC; the switch fails
// over between gateways, and existing traffic stays pinned to the
// generation it began on.
func (s *Server) carrierDest(name string) (string, *carrierGen, bool) {
	g, ok := s.carriers.currentGen(name)
	if !ok || len(g.addrs) == 0 {
		return "", nil, false
	}
	return g.addrs[0].String(), g, true
}

// switchNodeFor names the edge.switch node a request from the private
// socket came from: the entry with the source's IP, preferring an equal
// port, else the first (by name).
func (s *Server) switchNodeFor(src netip.AddrPort) (string, bool) {
	first := ""
	for _, name := range s.topo.upstreamNames {
		a := s.topo.upstreams[name].addr
		if a.Addr().Unmap() != src.Addr().Unmap() {
			continue
		}
		if a.Port() == src.Port() {
			return name, true
		}
		if first == "" {
			first = name
		}
	}
	return first, first != ""
}

// carrierContactURI is the Contact toward a carrier for a REGISTER: the
// switch's user at FreeSBC's public address on the carrier's transport
// (;transport=tcp|tls when not udp), carrying the token. For a tcp or tls
// carrier with no matching public listener the port is the transport's
// default and nothing listens there: the carrier can only send back over the
// connection FreeSBC opened to it.
func (s *Server) carrierContactURI(pub side, user, token string) sip.Uri {
	params := sip.NewParams()
	params.Add(contactTokenParam, token)
	if pub.transport != "udp" {
		params.Add("transport", pub.transport)
	}
	return sip.Uri{User: user, Host: pub.advIP.String(), Port: pub.advPort, UriParams: params}
}

// registerToCarrier proxies a REGISTER the switch sent for a carrier.
//
// The destination is pinned by generation: a refresh or an un-REGISTER of a
// live binding goes to the same carrier, transport and target address the
// binding was created on (its Contact lives there and, for tcp/tls, its
// connection is the carrier's only route back), a wildcard un-REGISTER
// goes to every generation the node's contacts live on, and only a brand
// new registration takes the current generation.
func (s *Server) registerToCarrier(req *sip.Request, tx sip.ServerTransaction, in inbound, carrier string) {
	pub, ok := s.carrierSide(carrier)
	node, nodeOK := s.switchNodeFor(in.src)
	if !ok || !nodeOK {
		s.reject(req, tx, 503, "Service Unavailable")
		return
	}
	wildcard := hasWildcardContact(req)
	requested, unregister := requestedExpires(req)
	if wildcard && (!unregister || len(req.GetHeaders("Contact")) != 1) {
		s.reject(req, tx, 400, "Bad Request")
		return
	}
	orig, hasContact := fsip.ContactURI(req)

	// Choose the generation set before touching the message.
	token := ""
	var gens []*carrierGen
	switch {
	case wildcard:
		gens = s.carrierRegs.nodeGens(carrier, node)
	case hasContact:
		token = carrierToken(node, orig.String())
		if b, found := s.carrierRegs.lookup(token); found {
			gens = append(gens, b.gen)
		}
	}
	if len(gens) == 0 {
		_, g, found := s.carrierDest(carrier)
		if !found {
			s.log.Warn("carrier has no resolved address", "carrier", carrier, "sip_call_id", fsip.CallID(req))
			s.reject(req, tx, 503, "Service Unavailable")
			return
		}
		gens = append(gens, g)
	}
	// Pin the destination generation(s) for the exchange itself, so a DNS
	// handoff while the REGISTER is in flight neither retires the
	// connection nor moves the request.
	for _, g := range gens {
		if !s.carriers.acquire(g, refTx) {
			s.reject(req, tx, 503, "Service Unavailable")
			return
		}
	}
	defer func() {
		for _, g := range gens {
			s.carriers.release(g, refTx)
		}
	}()

	s.metrics.CarrierRequest(carrier, dirOutbound, "REGISTER")
	if len(gens) > 1 {
		// A wildcard spanning a handoff: one REGISTER per gateway
		// generation that still holds one of the node's contacts.
		s.registerWildcard(req, tx, carrier, node, pub, gens)
		return
	}
	gen := gens[0]
	dest := gen.addrs[0].String()

	out, err := s.prepareForwardHidden(req, s.topo.private, pub, dest, false)
	if err != nil {
		s.reject(req, tx, 483, "Too Many Hops")
		return
	}
	if hs := req.GetHeaders("Contact"); len(hs) > 0 {
		if oc, isC := hs[0].(*sip.ContactHeader); isC {
			// The Contact header keeps its own parameters (expires, q); only
			// its address changes. A wildcard "*" goes upstream as it is.
			c := oc.Clone()
			if hasContact && !wildcard {
				c.Address = s.carrierContactURI(pub, orig.User, token)
			}
			fsip.RemoveHeaders(out, "Contact")
			out.AppendHeader(c)
		}
	}
	// The Request-URI, Authorization and Call-ID are untouched: the digest
	// the switch computed covers them.

	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	_, err = s.forwardAndRelay(ctx, req, tx, out, respToSwitch, func(relayed *sip.Response) error {
		if relayed.StatusCode/100 != 2 {
			return nil // challenges and failures pass through untouched
		}
		switch {
		case wildcard:
			s.carrierRegs.removeNode(carrier, node)
			fsip.RemoveHeaders(relayed, "Contact")
		case hasContact:
			granted := fsip.GrantedExpires(relayed, requested, func(u sip.Uri) bool {
				t, ok := u.UriParams.Get(contactTokenParam)
				return ok && t == token
			})
			secs := int(granted / time.Second)
			if unregister || granted <= 0 {
				s.carrierRegs.remove(token)
				secs = 0
			} else {
				s.carrierRegs.put(carrierBinding{
					token: token, carrier: carrier, node: node,
					contact: orig, expires: time.Now().Add(granted), gen: gen,
				})
			}
			restoreContact(relayed, orig, secs)
			s.log.Info("carrier registration", "carrier", carrier, "switch", node,
				"generation", gen.id, "expires", strconv.Itoa(secs))
		}
		s.publishCarrierRegistrations()
		return nil
	})
	if err != nil {
		s.log.Warn("forward carrier REGISTER", "err", err, "carrier", carrier, "sip_call_id", fsip.CallID(req))
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
	}
}

// registerWildcard forwards a Contact:* REGISTER to every generation one
// node's contacts are pinned to (registerToCarrier's multi-generation
// case). Each gateway is asked in turn; exactly one final response — the
// first 2xx, else the first final — is relayed to the switch, and the
// local bindings of every generation are removed only when a gateway
// accepted. Provisional responses are absorbed (sipgo's own 100 Trying
// already went to the switch).
func (s *Server) registerWildcard(req *sip.Request, tx sip.ServerTransaction, carrier, node string, pub side, gens []*carrierGen) {
	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	var chosen *sip.Response
	for _, gen := range gens {
		dest := gen.addrs[0].String()
		out, err := s.prepareForwardHidden(req, s.topo.private, pub, dest, false)
		if err != nil {
			continue
		}
		clTx, err := s.clientTx(ctx, out)
		if err != nil {
			s.log.Debug("wildcard carrier REGISTER not sent", "err", err, "carrier", carrier,
				"generation", gen.id, "sip_call_id", fsip.CallID(req))
			continue
		}
		final := s.pumpFinal(ctx, clTx)
		clTx.Terminate()
		if final == nil {
			continue
		}
		if chosen == nil || (chosen.StatusCode/100 != 2 && final.StatusCode/100 == 2) {
			chosen = final
		}
		if final.StatusCode/100 == 2 {
			break
		}
	}
	if chosen == nil {
		if ctx.Err() != nil {
			s.reject(req, tx, 504, "Server Time-out")
		} else {
			s.reject(req, tx, 503, "Service Unavailable")
		}
		return
	}
	if err := s.relayResponseHide(req, tx, chosen, respToSwitch, func(relayed *sip.Response) error {
		if relayed.StatusCode/100 == 2 {
			s.carrierRegs.removeNode(carrier, node)
			fsip.RemoveHeaders(relayed, "Contact")
			s.publishCarrierRegistrations()
		}
		return nil
	}); err != nil {
		s.log.Debug("relay wildcard REGISTER response", "err", err, "sip_call_id", fsip.CallID(req))
	}
}

// pumpFinal reads a non-INVITE client transaction to its first final
// (2xx–6xx) response, absorbing provisional ones and retransmissions.
func (s *Server) pumpFinal(ctx context.Context, clTx sip.ClientTransaction) *sip.Response {
	for {
		select {
		case res, ok := <-clTx.Responses():
			if !ok {
				return nil
			}
			if !fsip.Forwardable(res) {
				continue
			}
			if res.StatusCode >= 200 {
				return res
			}
		case <-clTx.Done():
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// carrierRURI resolves the outbound-registration token in a carrier's
// Request-URI. found is false for no token, or an unknown or expired one
// (logged: the request then falls back to the hash pool, Request-URI
// unchanged). A node that is no longer in the topology is treated the same.
func (s *Server) carrierRURI(req *sip.Request, carrier string) (carrierBinding, bool) {
	tok, ok := tokenOf(req.Recipient)
	if !ok {
		return carrierBinding{}, false
	}
	b, found := s.carrierRegs.lookup(tok)
	if found {
		if _, inPool := s.topo.upstreams[b.node]; inPool {
			return b, true
		}
	}
	s.log.Warn("carrier request names an unknown or expired registration token; treating it as addressed to the DID",
		"carrier", carrier, "sip_call_id", fsip.CallID(req))
	return carrierBinding{}, false
}

// CarrierRegistrationInfo is the operator view of one live carrier
// registration. The switch's original Contact is not included.
type CarrierRegistrationInfo struct {
	Carrier string
	User    string // user part of the switch's Contact
	Token   string
	Node    string // switch node "IP:port"
	Expires time.Time
}

// snapshot copies the live bindings under the lock, ordered by carrier,
// user, node and token. The result is never nil.
func (t *carrierRegTable) snapshot() []CarrierRegistrationInfo {
	now := time.Now()
	t.mu.Lock()
	out := make([]CarrierRegistrationInfo, 0, len(t.byToken))
	for _, b := range t.byToken {
		if now.Before(b.expires) {
			out = append(out, CarrierRegistrationInfo{Carrier: b.carrier, User: b.contact.User,
				Token: b.token, Node: b.node, Expires: b.expires})
		}
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Carrier != b.Carrier {
			return a.Carrier < b.Carrier
		}
		if a.User != b.User {
			return a.User < b.User
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Token < b.Token
	})
	return out
}

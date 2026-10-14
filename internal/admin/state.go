package admin

import (
	"net/http"
	"strconv"
	"time"
)

// This file serves the read-only live-state tables: client registrations,
// carrier registrations, shield bans, switch nodes and carriers. Each is a
// snapshot closure in Deps over the plain types below; app converts the
// planes' own records into them, so admin never imports edge or shield. No
// type here carries a client token, Call-ID, Contact or credential.

// Registration is one live client binding.
type Registration struct {
	AOR       string
	User      string
	Transport string
	Source    string // transport source "IP:port"
	ExpiresAt time.Time
}

// CarrierRegistration is one live switch-to-carrier registration.
type CarrierRegistration struct {
	Carrier string
	User    string
	Token   string // the opaque fsbc token FreeSBC put in the carrier Contact
	Node    string // switch node "IP:port"
	Expires time.Time
}

// Ban is one live shield ban.
type Ban struct {
	Source string // IP, or IP:port for a UDP socket ban
	Kind   string // "ip", "udp_ip" or "udp_socket"
	Reason string // "scanner", "register" or "admission"
	// Generation is the shield rule generation the ban was created under.
	Generation string
	Since      time.Time
	Until      time.Time
}

// Offender is one source with shield strikes in an open window.
type Offender struct {
	Source string // IPv4 address, or IPv6 /64 prefix
	Reason string // "register", "admission" or "admission_udp"
	// Generation is the shield rule generation the window opened under.
	Generation string
	Strikes    int
	Since      time.Time // the window opened
	Until      time.Time // the window closes
}

// SwitchNode is the passive health of one switch node.
type SwitchNode struct {
	Address           string
	State             string // "healthy" or "cooling_down"
	CooldownRemaining time.Duration
	LastFailure       time.Time // zero if never
}

// CarrierAddress is one resolved carrier destination.
type CarrierAddress struct {
	Address string
	InUse   bool
}

// Carrier is the resolution state of one configured carrier.
type Carrier struct {
	Name       string
	Host       string
	Transport  string
	Mode       string // "literal", "srv", "a", or "" until resolved
	Addresses  []CarrierAddress
	ResolvedAt time.Time // zero for a literal or unresolved carrier
	ExpiresAt  time.Time
	Failing    bool
	LastError  string
}

const (
	// defaultPageLimit and maxPageLimit bound one page of /api/registrations
	// and /api/shield/bans. A larger limit is clamped, not refused.
	defaultPageLimit = 100
	maxPageLimit     = 1000
	// maxUserFilter bounds the registrations user filter.
	maxUserFilter = 256
)

// pageParams parses limit and offset. A value that is not a non-negative
// integer (limit: positive) is a 400.
func pageParams(w http.ResponseWriter, r *http.Request) (limit, offset int, ok bool) {
	q := r.URL.Query()
	limit = defaultPageLimit
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "limit must be a positive integer", http.StatusBadRequest)
			return 0, 0, false
		}
		limit = min(n, maxPageLimit)
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			http.Error(w, "offset must be a non-negative integer", http.StatusBadRequest)
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// stateGET admits only GET (405 + Allow otherwise) and a configured
// closure (404 when nil, like /api/drain).
func stateGET(w http.ResponseWriter, r *http.Request, configured bool) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !configured {
		http.NotFound(w, r)
		return false
	}
	return true
}

// secondsUntil is the whole seconds from now to t, never negative.
func secondsUntil(t, now time.Time) int {
	return max(int(t.Sub(now).Seconds()), 0)
}

// rfc3339 renders t in UTC, or nil for the zero time (JSON null).
func rfc3339(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// handleRegistrations serves GET /api/registrations?user=&limit=&offset=:
// one page of the live client bindings and the total matching the filter.
func (s *Server) handleRegistrations(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Registrations != nil) {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	user := r.URL.Query().Get("user")
	if len(user) > maxUserFilter {
		http.Error(w, "user filter too long", http.StatusBadRequest)
		return
	}
	regs, total := s.deps.Registrations(user, limit, offset)
	now := time.Now()
	items := make([]map[string]any, 0, len(regs))
	for _, g := range regs {
		items = append(items, map[string]any{
			"aor":        g.AOR,
			"user":       g.User,
			"transport":  g.Transport,
			"source":     g.Source,
			"expires_in": secondsUntil(g.ExpiresAt, now),
		})
	}
	writeJSON(w, map[string]any{"items": items, "total": total, "limit": limit, "offset": offset})
}

// handleCarrierRegistrations serves GET /api/carrier-registrations: always
// an array.
func (s *Server) handleCarrierRegistrations(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.CarrierRegistrations != nil) {
		return
	}
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.CarrierRegistrations() {
		out = append(out, map[string]any{
			"carrier":    c.Carrier,
			"user":       c.User,
			"token":      c.Token,
			"node":       c.Node,
			"expires_in": secondsUntil(c.Expires, now),
		})
	}
	writeJSON(w, out)
}

// handleBans serves /api/shield/bans: GET lists one page of the live bans;
// DELETE removes exactly the ban named by kind, source and its rule
// generation. Auth, the Host check and (for DELETE) the Origin check run
// before it.
func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.deps.Bans == nil {
			http.NotFound(w, r)
			return
		}
		s.listBans(w, r)
	case http.MethodDelete:
		if s.deps.Unban == nil {
			http.NotFound(w, r)
			return
		}
		s.handleUnban(w, r)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// listBans serves GET /api/shield/bans?limit=&offset=: one page of the
// live bans, the total, and the cumulative ban additions refused at the ban
// table's cap.
func (s *Server) listBans(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	bans, total, rejected := s.deps.Bans(limit, offset)
	now := time.Now()
	items := make([]map[string]any, 0, len(bans))
	for _, b := range bans {
		items = append(items, map[string]any{
			"source":     b.Source,
			"kind":       b.Kind,
			"reason":     b.Reason,
			"generation": b.Generation,
			"since":      rfc3339(b.Since),
			"remaining":  secondsUntil(b.Until, now),
		})
	}
	writeJSON(w, map[string]any{
		"items": items, "total": total, "limit": limit, "offset": offset,
		"ban_adds_rejected": rejected,
	})
}

// handleUnban serves DELETE /api/shield/bans?kind=&source=&generation=: an
// explicit unban acts only on the ban matching all three, so a ban made
// under older rules is never released by an unban aimed at the current
// generation. A clean miss is 404; malformed selectors are 400.
func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind, source, generation := q.Get("kind"), q.Get("source"), q.Get("generation")
	switch kind {
	case "ip", "udp_ip", "udp_socket":
	default:
		http.Error(w, "kind must be ip, udp_ip or udp_socket", http.StatusBadRequest)
		return
	}
	if source == "" || len(source) > 128 {
		http.Error(w, "source is required (IP, or IP:port for udp_socket)", http.StatusBadRequest)
		return
	}
	if len(generation) != 64 {
		http.Error(w, "generation (64 hex chars) is required: an unban must name the rules the ban was created under", http.StatusBadRequest)
		return
	}
	removed, err := s.deps.Unban(kind, source, generation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !removed {
		http.Error(w, "no live ban matches this kind, source and generation", http.StatusNotFound)
		return
	}
	s.audit.record(AuditShieldUnban, remoteIP(r), AuditResultOK)
	s.log.Info("admin: shield ban removed",
		"remote", r.RemoteAddr, "kind", kind, "source", source, "generation", generation)
	writeJSON(w, map[string]any{"unbanned": true, "kind": kind, "source": source, "generation": generation})
}

// handleOffenders serves GET /api/shield/offenders?limit=: the sources with
// strikes in an open window, most strikes first (at most limit, default
// 100, at most 1000), and the total.
func (s *Server) handleOffenders(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Offenders != nil) {
		return
	}
	limit, _, ok := pageParams(w, r)
	if !ok {
		return
	}
	top, total := s.deps.Offenders(limit)
	now := time.Now()
	items := make([]map[string]any, 0, len(top))
	for _, o := range top {
		items = append(items, map[string]any{
			"source":     o.Source,
			"reason":     o.Reason,
			"generation": o.Generation,
			"strikes":    o.Strikes,
			"since":      rfc3339(o.Since),
			"remaining":  secondsUntil(o.Until, now),
		})
	}
	writeJSON(w, map[string]any{"items": items, "total": total, "limit": limit})
}

// handleShieldState serves GET /api/shield/state: the snapshot persistence
// and recovery status (see shield.Status).
func (s *Server) handleShieldState(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.ShieldState != nil) {
		return
	}
	st := s.deps.ShieldState()
	writeJSON(w, map[string]any{
		"enabled":             st.Enabled,
		"path":                st.Path,
		"phase":               st.Phase,
		"recovery_result":     st.RecoveryResult,
		"active_generation":   st.ActiveGeneration,
		"snapshot_generation": rfc3339ish(st.SnapshotGeneration),
		"restored_at":         rfc3339(st.RestoredAt),
		"restored": map[string]any{
			"ip_bans":         st.Restored.IPBans,
			"udp_ip_bans":     st.Restored.UDPIPBans,
			"udp_socket_bans": st.Restored.UDPSocketBans,
			"offenders":       st.Restored.Offenders,
			"buckets":         st.Restored.Buckets,
		},
		"expired_skipped":    st.ExpiredSkipped,
		"stale_generations":  st.StaleGenerations,
		"last_save_at":       rfc3339(st.LastSaveAt),
		"last_save_error":    nonEmpty(st.LastSaveError),
		"last_save_error_at": rfc3339(st.LastSaveErrorAt),
		"saves_ok":           st.SavesOK,
		"saves_failed":       st.SavesFailed,
		"fatal_error":        nonEmpty(st.FatalError),
	})
}

// rfc3339ish renders a non-empty string as-is (the generation hashes are
// already safe), JSON null otherwise.
func rfc3339ish(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nonEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// handleSwitchNodes serves GET /api/switch-nodes: always an array.
func (s *Server) handleSwitchNodes(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.SwitchNodes != nil) {
		return
	}
	out := []map[string]any{}
	for _, n := range s.deps.SwitchNodes() {
		out = append(out, map[string]any{
			"address":            n.Address,
			"state":              n.State,
			"cooldown_remaining": int(n.CooldownRemaining.Seconds()),
			"last_failure":       rfc3339(n.LastFailure),
		})
	}
	writeJSON(w, out)
}

// handleCarriers serves GET /api/carriers: always an array.
func (s *Server) handleCarriers(w http.ResponseWriter, r *http.Request) {
	if !stateGET(w, r, s.deps.Carriers != nil) {
		return
	}
	now := time.Now()
	out := []map[string]any{}
	for _, c := range s.deps.Carriers() {
		addrs := make([]map[string]any, 0, len(c.Addresses))
		for _, a := range c.Addresses {
			addrs = append(addrs, map[string]any{"address": a.Address, "in_use": a.InUse})
		}
		var age any // null for a literal or never-resolved carrier
		if !c.ResolvedAt.IsZero() {
			age = max(int(now.Sub(c.ResolvedAt).Seconds()), 0)
		}
		out = append(out, map[string]any{
			"name":              c.Name,
			"host":              c.Host,
			"transport":         c.Transport,
			"mode":              c.Mode,
			"addresses":         addrs,
			"resolved_at":       rfc3339(c.ResolvedAt),
			"expires_at":        rfc3339(c.ExpiresAt),
			"cache_age_seconds": age,
			"failing":           c.Failing,
			"last_error":        c.LastError,
		})
	}
	writeJSON(w, out)
}

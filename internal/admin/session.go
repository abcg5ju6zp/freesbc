package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Session constants (design.md §13.4, §15.2). They are not config keys.
const (
	// sessionIdleTimeout ends a session that made no request for this long.
	sessionIdleTimeout = 30 * time.Minute
	// sessionMaxAge ends a session this long after login, whatever its
	// activity (an open dashboard polls, so this is what ends it).
	sessionMaxAge = 12 * time.Hour
	// sessionMax is how many sessions may be live; a login past it evicts
	// the oldest by creation time.
	sessionMax = 8
	// sessionCookieName is the session cookie.
	sessionCookieName = "freesbc_session"
	// loginBodyMax caps the POST /api/login body.
	loginBodyMax = 4 << 10
)

// session is one live login. The ID is never stored: the map key is its
// SHA-256.
type session struct {
	created time.Time
	last    time.Time
}

// sessionStore holds the live sessions in memory only (a restart logs
// everyone out). The zero value is usable.
type sessionStore struct {
	mu   sync.Mutex
	byID map[[sha256.Size]byte]*session
}

func sessionKey(id string) [sha256.Size]byte { return sha256.Sum256([]byte(id)) }

// expiredLocked reports whether sess is past either timeout at now.
func (st *sessionStore) expiredLocked(sess *session, now time.Time) bool {
	return now.Sub(sess.last) >= sessionIdleTimeout || now.Sub(sess.created) >= sessionMaxAge
}

// pruneLocked drops every expired session.
func (st *sessionStore) pruneLocked(now time.Time) {
	for k, sess := range st.byID {
		if st.expiredLocked(sess, now) {
			delete(st.byID, k)
		}
	}
}

// create starts a session and returns its ID (32 random bytes, base64url
// without padding). Expired sessions are pruned first; if the store is still
// full the oldest by creation is evicted.
func (st *sessionStore) create(now time.Time) string {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("admin: crypto/rand: " + err.Error()) // never fails on supported platforms
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.byID == nil {
		st.byID = make(map[[sha256.Size]byte]*session)
	}
	st.pruneLocked(now)
	for len(st.byID) >= sessionMax {
		keys := make([][sha256.Size]byte, 0, len(st.byID))
		for k := range st.byID {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return st.byID[keys[i]].created.Before(st.byID[keys[j]].created) })
		delete(st.byID, keys[0])
	}
	st.byID[sessionKey(id)] = &session{created: now, last: now}
	return id
}

// valid reports whether id names a live session and, if so, touches its idle
// timer. An expired session is removed.
func (st *sessionStore) valid(id string, now time.Time) bool {
	if id == "" {
		return false
	}
	k := sessionKey(id)
	st.mu.Lock()
	defer st.mu.Unlock()
	sess, ok := st.byID[k]
	if !ok {
		return false
	}
	if st.expiredLocked(sess, now) {
		delete(st.byID, k)
		return false
	}
	sess.last = now
	return true
}

// drop deletes the session id names and reports whether it was live.
func (st *sessionStore) drop(id string, now time.Time) bool {
	if id == "" {
		return false
	}
	k := sessionKey(id)
	st.mu.Lock()
	defer st.mu.Unlock()
	sess, ok := st.byID[k]
	if !ok {
		return false
	}
	delete(st.byID, k)
	return !st.expiredLocked(sess, now)
}

// sessionFrom returns the session cookie value, or "".
func sessionFrom(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// hasSession reports whether r carries a live session cookie.
func (s *Server) hasSession(r *http.Request) bool {
	return s.sessions.valid(sessionFrom(r), s.clock())
}

func (s *Server) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge, // 0 omits it on login; -1 sends Max-Age=0 on logout
		HttpOnly: true,
		Secure:   s.useTLS(),
		SameSite: http.SameSiteStrictMode,
	}
}

// handleLogin serves POST /api/login. It shares the Basic path's limiter
// (reserve before bcrypt) and audit events.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, loginBodyMax))
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := remoteIP(r)
	slot, ok, first := s.limiter.reserve(ip, s.clock())
	if !ok {
		s.audit.count(AuditResultRateLimited)
		if first {
			s.audit.record(AuditLoginLimited, ip, AuditResultRateLimited)
		}
		http.Error(w, "too many failed attempts", http.StatusTooManyRequests)
		return
	}
	// The form has no user field: the user is always admin.
	if bcrypt.CompareHashAndPassword([]byte(s.cfg.PasswordHash), []byte(body.Password)) != nil {
		s.audit.count(AuditResultBadCredentials)
		s.audit.record(AuditLoginFailed, ip, AuditResultBadCredentials)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.limiter.refund(slot)
	id := s.sessions.create(s.clock())
	http.SetCookie(w, s.sessionCookie(id, 0))
	s.audit.record(AuditLoginOK, ip, AuditResultOK)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout serves POST /api/logout: idempotent, always clears the cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sessions.drop(sessionFrom(r), s.clock()) {
		s.audit.record(AuditLogout, remoteIP(r), AuditResultOK)
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

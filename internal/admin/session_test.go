package admin

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freesbc/freesbc/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func loginReq(s *Server, remote, password string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := newReq("POST", "/api/login", strings.NewReader(`{"password":"`+password+`"}`))
	if remote != "" {
		req.RemoteAddr = remote
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func cookieOf(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func getWith(s *Server, path string, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := newReq("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func postWith(s *Server, path string, c *http.Cookie) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := newReq("POST", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	s.handler().ServeHTTP(rr, req)
	return rr
}

func mustLogin(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	rr := loginReq(s, "", "secret")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("login: %d want 204", rr.Code)
	}
	c := cookieOf(rr)
	if c == nil || c.Value == "" {
		t.Fatal("login set no session cookie")
	}
	return c
}

func auditTypes(s *Server) []AuditType {
	var out []AuditType
	for _, e := range s.audit.snapshot() {
		out = append(out, e.Type)
	}
	return out
}

func TestLoginOKFailedLimited(t *testing.T) {
	s := testServer(t)
	c := mustLogin(t, s)
	if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusOK {
		t.Fatalf("status with session: %d", rr.Code)
	}
	if got := auditTypes(s); len(got) != 1 || got[0] != AuditLoginOK {
		t.Fatalf("audit after login: %v", got)
	}
	// A request served by the cookie is not an event.
	getWith(s, "/api/status", c, nil)
	if got := auditTypes(s); len(got) != 1 {
		t.Fatalf("session request was audited: %v", got)
	}

	const src = "198.51.100.77:1"
	rr := loginReq(s, src, "wrong")
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") != "" || cookieOf(rr) != nil {
		t.Fatalf("bad password: %d www=%q cookie=%v", rr.Code, rr.Header().Get("WWW-Authenticate"), cookieOf(rr))
	}
	for i := 1; i < authFailLimit; i++ {
		loginReq(s, src, "wrong")
	}
	if rr := loginReq(s, src, "secret"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d want 429", rr.Code)
	}
	loginReq(s, src, "wrong")
	var failed, limited int
	for _, ty := range auditTypes(s) {
		switch ty {
		case AuditLoginFailed:
			failed++
		case AuditLoginLimited:
			limited++
		}
	}
	if failed != authFailLimit || limited != 1 {
		t.Fatalf("audit failed=%d limited=%d, want %d and 1", failed, limited, authFailLimit)
	}
}

func TestLoginSuccessRefundsAndSharesLimiter(t *testing.T) {
	s := testServer(t)
	const src = "198.51.100.78:1"
	for i := 0; i < authFailLimit-1; i++ {
		loginReq(s, src, "wrong")
	}
	// Basic failures share the budget: this one is the 10th.
	if got := auditReq(s, src, "admin", sp("nope")).Code; got != http.StatusUnauthorized {
		t.Fatalf("basic fail: %d", got)
	}
	if rr := loginReq(s, src, "secret"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("form after shared budget spent: %d want 429", rr.Code)
	}
}

func TestLoginBadBody(t *testing.T) {
	s := testServer(t)
	for name, body := range map[string]string{
		"malformed": "{nope",
		"oversize":  `{"password":"` + strings.Repeat("a", loginBodyMax) + `"}`,
	} {
		rr := httptest.NewRecorder()
		s.handler().ServeHTTP(rr, newReq("POST", "/api/login", strings.NewReader(body)))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: %d want 400", name, rr.Code)
		}
	}
	if s.limiter.over("192.0.2.1", time.Now()) || len(s.audit.snapshot()) != 0 {
		t.Error("a bad body must not count or be audited")
	}
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/api/login", nil))
	if rr.Code != http.StatusMethodNotAllowed || rr.Header().Get("Allow") != "POST" {
		t.Errorf("GET /api/login: %d allow=%q", rr.Code, rr.Header().Get("Allow"))
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	s := testServer(t)
	c := mustLogin(t, s)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure {
		t.Errorf("plain http cookie attrs: %+v", c)
	}
	if c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Errorf("login cookie must be a browser-session cookie: %+v", c)
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	cfg := &config.AdminConfig{Listen: "127.0.0.1:8443", PasswordHash: string(hash), AllowRemote: true}
	ts := New(cfg, &config.TLSConfig{Cert: "x", Key: "y"}, config.NewStore(mustCfg(t)), emptyDeps(),
		slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"secret"}`))
	req.Host = "127.0.0.1:8443"
	req.Header.Set("Origin", "https://127.0.0.1:8443")
	rr := httptest.NewRecorder()
	ts.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("tls login: %d", rr.Code)
	}
	if tc := cookieOf(rr); tc == nil || !tc.Secure || !tc.HttpOnly || tc.SameSite != http.SameSiteStrictMode {
		t.Errorf("tls cookie attrs: %+v", tc)
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	s := testServer(t)
	clock := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clock }
	c := mustLogin(t, s)
	// Activity inside the idle window keeps it alive well past 30 minutes.
	for i := 0; i < 4; i++ {
		clock = clock.Add(sessionIdleTimeout - time.Minute)
		if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusOK {
			t.Fatalf("step %d: %d want 200", i, rr.Code)
		}
	}
	clock = clock.Add(sessionIdleTimeout)
	if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after idle timeout: %d want 401", rr.Code)
	}
}

func TestSessionAbsoluteExpiry(t *testing.T) {
	s := testServer(t)
	clock := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clock }
	c := mustLogin(t, s)
	for elapsed := time.Duration(0); elapsed+20*time.Minute < sessionMaxAge; elapsed += 20 * time.Minute {
		clock = clock.Add(20 * time.Minute)
		if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusOK {
			t.Fatalf("at %v: %d want 200", elapsed, rr.Code)
		}
	}
	clock = clock.Add(20 * time.Minute) // keep-alive polling does not matter past 12 h
	if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("after absolute timeout: %d want 401", rr.Code)
	}
}

func TestSessionCapEvictsOldest(t *testing.T) {
	s := testServer(t)
	clock := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return clock }
	var cookies []*http.Cookie
	for i := 0; i < sessionMax+1; i++ {
		clock = clock.Add(time.Second)
		cookies = append(cookies, mustLogin(t, s))
	}
	if rr := getWith(s, "/api/status", cookies[0], nil); rr.Code != http.StatusUnauthorized {
		t.Errorf("oldest session after cap: %d want 401", rr.Code)
	}
	for i, c := range cookies[1:] {
		if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusOK {
			t.Errorf("session %d: %d want 200", i+1, rr.Code)
		}
	}
	if n := len(s.sessions.byID); n != sessionMax {
		t.Errorf("live sessions = %d want %d", n, sessionMax)
	}
}

func TestLogout(t *testing.T) {
	s := testServer(t)
	c := mustLogin(t, s)
	rr := postWith(s, "/api/logout", c)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rr.Code)
	}
	if cc := cookieOf(rr); cc == nil || cc.MaxAge >= 0 || cc.Value != "" {
		t.Errorf("logout cookie not cleared: %+v", cc)
	}
	if !strings.Contains(strings.Join(rr.Header().Values("Set-Cookie"), ";"), "Max-Age=0") {
		t.Errorf("Set-Cookie lacks Max-Age=0: %v", rr.Header().Values("Set-Cookie"))
	}
	if r2 := getWith(s, "/api/status", c, nil); r2.Code != http.StatusUnauthorized {
		t.Fatalf("old cookie after logout: %d want 401", r2.Code)
	}
	if got := auditTypes(s); got[0] != AuditLogout {
		t.Fatalf("audit = %v, want logout first", got)
	}
	// Idempotent: no cookie and a dead cookie are 204 with no event.
	n := len(s.audit.snapshot())
	if postWith(s, "/api/logout", nil).Code != http.StatusNoContent || postWith(s, "/api/logout", c).Code != http.StatusNoContent {
		t.Error("repeat logout must be 204")
	}
	if len(s.audit.snapshot()) != n {
		t.Error("a logout that dropped nothing was audited")
	}
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("GET", "/api/logout", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/logout: %d want 405", rr.Code)
	}
}

func TestLoginLogoutCrossOriginRefused(t *testing.T) {
	s := testServer(t)
	c := mustLogin(t, s)
	for _, path := range []string{"/api/login", "/api/logout"} {
		for _, origin := range []string{"http://evil.example", "null"} {
			rr := httptest.NewRecorder()
			req := newReq("POST", path, strings.NewReader(`{"password":"secret"}`))
			req.Header.Set("Origin", origin)
			req.AddCookie(c)
			s.handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("%s Origin %q: %d want 403", path, origin, rr.Code)
			}
		}
	}
	if rr := getWith(s, "/api/status", c, nil); rr.Code != http.StatusOK {
		t.Error("a refused cross-origin logout must not drop the session")
	}
	if n := len(s.audit.snapshot()); n != 1 {
		t.Errorf("audit events = %d want 1 (the login)", n)
	}
}

func TestBasicStillAccepted(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/metrics", "/api/status", "/api/audit"} {
		rr := httptest.NewRecorder()
		req := newReq("GET", path, nil)
		req.SetBasicAuth("admin", "secret")
		s.handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("Basic %s: %d want 200", path, rr.Code)
		}
	}
	// A dead cookie does not block valid Basic credentials.
	rr := httptest.NewRecorder()
	req := newReq("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "unknown"})
	req.SetBasicAuth("admin", "secret")
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("stale cookie + Basic: %d want 200", rr.Code)
	}
}

func TestNoCredentialResponses(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		name     string
		method   string
		mode     string
		code     int
		location string
		www      bool
	}{
		{"navigate", "GET", "navigate", http.StatusSeeOther, "/login", false},
		{"navigate HEAD", "HEAD", "navigate", http.StatusSeeOther, "/login", false},
		{"fetch", "GET", "cors", http.StatusUnauthorized, "", false},
		{"same-origin fetch", "GET", "same-origin", http.StatusUnauthorized, "", false},
		{"curl", "GET", "", http.StatusUnauthorized, "", true},
	}
	for _, tc := range cases {
		for _, path := range []string{"/", "/api/status"} {
			rr := httptest.NewRecorder()
			req := newReq(tc.method, path, nil)
			if tc.mode != "" {
				req.Header.Set("Sec-Fetch-Mode", tc.mode)
			}
			s.handler().ServeHTTP(rr, req)
			if rr.Code != tc.code || rr.Header().Get("Location") != tc.location ||
				(rr.Header().Get("WWW-Authenticate") != "") != tc.www {
				t.Errorf("%s %s: %d loc=%q www=%q", tc.name, path, rr.Code, rr.Header().Get("Location"), rr.Header().Get("WWW-Authenticate"))
			}
		}
	}
	// An unknown cookie is treated as no credentials and counts nothing.
	rr := getWith(s, "/api/status", &http.Cookie{Name: sessionCookieName, Value: "bogus"}, nil)
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("bogus cookie: %d", rr.Code)
	}
	if len(s.audit.snapshot()) != 0 || s.limiter.over("192.0.2.1", time.Now()) {
		t.Error("no-credential requests must not be audited or counted")
	}
}

func TestLoginPageAndAssetsPublic(t *testing.T) {
	s := testServer(t)
	rr := getWith(s, "/login", nil, nil)
	if rr.Code != http.StatusOK || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET /login: %d %q", rr.Code, rr.Header().Get("Content-Type"))
	}
	if csp := rr.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'none'") || rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("login page headers: csp=%q", csp)
	}
	for _, a := range []string{"/assets/login.js", "/assets/tokens.css", "/assets/ui.css", "/assets/theme.js"} {
		if !strings.Contains(rr.Body.String(), a) {
			t.Errorf("login.html does not load %s", a)
		}
		if r := getWith(s, a, nil, nil); r.Code != http.StatusOK {
			t.Errorf("GET %s without auth: %d want 200", a, r.Code)
		}
	}
	for _, p := range []string{"/", "/assets/app.js", "/assets/missing.css", "/api/status", "/api/audit", "/metrics", "/index.html"} {
		if r := getWith(s, p, nil, nil); r.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without auth: %d want 401", p, r.Code)
		}
	}
	rr = httptest.NewRecorder()
	s.handler().ServeHTTP(rr, newReq("POST", "/login", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /login: %d want 405", rr.Code)
	}
}

func TestSessionServesUIAndPprofGate(t *testing.T) {
	s := testServer(t)
	c := mustLogin(t, s)
	for _, p := range []string{"/", "/assets/app.js", "/api/audit", "/metrics"} {
		if r := getWith(s, p, c, nil); r.Code != http.StatusOK {
			t.Errorf("GET %s with session: %d want 200", p, r.Code)
		}
	}
	var evs []AuditEvent
	r := getWith(s, "/api/audit", c, nil)
	if err := json.Unmarshal(r.Body.Bytes(), &evs); err != nil || len(evs) != 1 || evs[0].Type != AuditLoginOK {
		t.Errorf("audit body: %v %s", err, r.Body.String())
	}
}

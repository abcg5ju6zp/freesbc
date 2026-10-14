package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testGen = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func unbanDo(s *Server, target string) *httptest.ResponseRecorder {
	req := newReq(http.MethodDelete, target, nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	return rr
}

func TestUnbanEndpoint(t *testing.T) {
	var gotKind, gotSource, gotGen string
	var calls int
	d := stateDeps()
	d.Unban = func(kind, source, generation string) (bool, error) {
		calls++
		gotKind, gotSource, gotGen = kind, source, generation
		return true, nil
	}
	s := newTestServer(t, d)

	rr := unbanDo(s, "/api/shield/bans?kind=udp_socket&source=198.51.100.9:5060&generation="+testGen)
	if rr.Code != http.StatusOK {
		t.Fatalf("unban = %d %s", rr.Code, rr.Body.String())
	}
	if calls != 1 || gotKind != "udp_socket" || gotSource != "198.51.100.9:5060" || gotGen != testGen {
		t.Fatalf("closure got %q %q %q after %d calls", gotKind, gotSource, gotGen, calls)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body["unbanned"] != true {
		t.Fatalf("body = %s", rr.Body.String())
	}
	// A successful unban is audited.
	var found bool
	for _, ev := range s.audit.snapshot() {
		if ev.Type == AuditShieldUnban {
			found = true
		}
	}
	if !found {
		t.Error("no shield_unban audit event")
	}
}

func TestUnbanValidation(t *testing.T) {
	var calls int
	d := stateDeps()
	d.Unban = func(kind, source, generation string) (bool, error) {
		calls++
		return false, errors.New("should not be called")
	}
	s := newTestServer(t, d)
	for _, q := range []string{
		"kind=nope&source=1.2.3.4&generation=" + testGen,
		"kind=ip&source=&generation=" + testGen,
		"kind=ip&source=1.2.3.4",
		"kind=ip&source=1.2.3.4&generation=short",
	} {
		if rr := unbanDo(s, "/api/shield/bans?"+q); rr.Code != http.StatusBadRequest {
			t.Errorf("DELETE ?%s = %d, want 400", q, rr.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid requests reached the closure %d times", calls)
	}

	// A clean miss is 404, not an error.
	miss := stateDeps()
	miss.Unban = func(kind, source, generation string) (bool, error) { return false, nil }
	if rr := unbanDo(newTestServer(t, miss), "/api/shield/bans?kind=ip&source=1.2.3.4&generation="+testGen); rr.Code != http.StatusNotFound {
		t.Errorf("miss = %d, want 404", rr.Code)
	}
	// A bad selector reported by the plane is 400.
	badSel := stateDeps()
	badSel.Unban = func(kind, source, generation string) (bool, error) { return false, errors.New("invalid ban source") }
	if rr := unbanDo(newTestServer(t, badSel), "/api/shield/bans?kind=udp_socket&source=1.2.3.4&generation="+testGen); rr.Code != http.StatusBadRequest {
		t.Errorf("plane error = %d, want 400", rr.Code)
	}
}

// Without the closures configured, the actions answer 404 like a missing
// route.
func TestUnbanNilClosure(t *testing.T) {
	s := newTestServer(t, emptyDeps())
	if rr := unbanDo(s, "/api/shield/bans?kind=ip&source=1.2.3.4&generation="+testGen); rr.Code != http.StatusNotFound {
		t.Errorf("nil closure = %d, want 404", rr.Code)
	}
	req := newReq(http.MethodGet, "/api/shield/state", nil)
	req.SetBasicAuth("admin", "secret")
	rr := httptest.NewRecorder()
	s.handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("nil state closure = %d, want 404", rr.Code)
	}
}

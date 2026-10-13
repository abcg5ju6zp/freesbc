package admin

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// webuiFS holds the single-page UI: index.html, login.html and their static
// assets (tokens.css, ui.css, theme.js, app.js, login.js). Everything is compiled into the
// binary; the page loads nothing from outside the admin origin.
//
//go:embed webui
var webuiFS embed.FS

// assetsFS is webui/assets, served under /assets/.
var assetsFS = func() fs.FS {
	sub, err := fs.Sub(webuiFS, "webui/assets")
	if err != nil {
		panic(err) // the embed pattern above guarantees the directory
	}
	return sub
}()

var assetServer = http.StripPrefix("/assets/", http.FileServerFS(assetsFS))

// uiCSP allows only same-origin script, style and fetch, and forbids
// framing. The UI therefore keeps all script and style in /assets/ files:
// an inline <script>, <style> or style="" attribute is blocked by the
// browser, which TestUIHasNoInlineScriptOrStyle guards against.
const uiCSP = "default-src 'none'; script-src 'self'; style-src 'self'; " +
	"img-src 'self' data:; connect-src 'self'; base-uri 'none'; " +
	"form-action 'none'; frame-ancestors 'none'"

// publicAssets are the only files served without auth: the login page needs
// them to render. Anything new here is a deliberate decision (design.md §13.7).
var publicAssets = map[string]bool{
	"/assets/login.js":   true,
	"/assets/tokens.css": true,
	"/assets/ui.css":     true,
	"/assets/theme.js":   true,
}

// handleAssets serves /assets/<file>: the login page's four files without
// auth, everything else (app.js, 404s) behind requireAuth.
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	if publicAssets[r.URL.Path] {
		s.handleUI(w, r)
		return
	}
	s.requireAuth(s.handleUI)(w, r)
}

// handleLoginPage serves the embedded login.html at /login, without auth.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := webuiFS.ReadFile("webui/login.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", uiCSP)
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// handleUI serves the embedded single-page web UI. It is the catch-all route
// ("/"), so the explicit /api/*, /metrics, and /healthz routes take precedence
// in the mux. /assets/<file> serves a static asset (404 when absent, never
// the page or a directory listing); any other path serves the SPA.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", uiCSP)
	// nosniff, X-Frame-Options, Referrer-Policy and Cache-Control: no-store
	// are set by recoverMW on every response (no-store: every one but
	// /healthz), so an upgraded binary never serves a stale UI. Do not
	// weaken them here.

	if strings.HasPrefix(r.URL.Path, "/assets/") {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		assetServer.ServeHTTP(w, r)
		return
	}

	data, err := webuiFS.ReadFile("webui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

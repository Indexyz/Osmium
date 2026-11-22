package web_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/indexyz/osmium/web"
)

func TestHandlerServesBuiltBundleAndCSP(t *testing.T) {
	h := web.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: status=%d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'wasm-unsafe-eval'") || !strings.Contains(csp, "connect-src 'self' data:") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
	if strings.Contains(csp, "jsdelivr") {
		t.Fatalf("CSP still references external CDN: %q", csp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "./assets/osmium.js") || !strings.Contains(body, "./assets/osmium.css") {
		t.Fatalf("index.html missing built assets: %s", body)
	}
	if strings.Contains(body, "jsdelivr") {
		t.Fatalf("index.html still references external CDN: %s", body)
	}

	for _, asset := range []string{"/assets/osmium.js", "/assets/osmium.css"} {
		a := httptest.NewRecorder()
		h.ServeHTTP(a, httptest.NewRequest(http.MethodGet, asset, nil))
		if a.Code != http.StatusOK || a.Body.Len() == 0 {
			t.Fatalf("GET %s: status=%d len=%d", asset, a.Code, a.Body.Len())
		}
	}
}

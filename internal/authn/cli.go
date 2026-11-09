package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/indexyz/osmium/internal/audit"
)

// CLI login: the osmium CLI starts a loopback listener and opens
//
//	GET /auth/cli?port=P&state=S&code_challenge=C
//
// in the user's browser. A logged-in user confirms (POST, CSRF protected) and
// is redirected to http://127.0.0.1:P/callback?code=..&state=.. . The CLI then
// exchanges the code with its PKCE verifier at POST /auth/cli/token for an
// opaque Bearer token. Codes are single use and short lived; tokens are kept
// as hashes only and are separate from Web sessions.

const (
	cliCodeTTL    = 2 * time.Minute
	cliTokenPfx   = "osm_"
	maxPendingCLI = 10000
)

type cliCode struct {
	user      User
	challenge string
	expires   time.Time
}

// CLIToken is a CLI Bearer credential.
type CLIToken struct {
	User      User
	ExpiresAt time.Time
}

// SafeNext returns p if it is a same-origin absolute path, else "/".
func SafeNext(p string) string {
	if p == "" || len(p) > 2048 || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") {
		return "/"
	}
	return p
}

type cliParams struct {
	Port      int
	State     string
	Challenge string
}

func urlSafe(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func parseCLIParams(get func(string) string) (cliParams, bool) {
	port, err := strconv.Atoi(get("port"))
	p := cliParams{Port: port, State: get("state"), Challenge: get("code_challenge")}
	if err != nil || port < 1024 || port > 65535 || !urlSafe(p.State, 16, 128) || !urlSafe(p.Challenge, 43, 43) {
		return p, false
	}
	return p, true
}

var cliPage = template.Must(template.New("cli").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 osmium CLI</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.6}
button{font-size:1rem;padding:.5rem 1.2rem}code{background:#eee;padding:0 .3em}</style></head>
<body>
<h1>授权 osmium CLI</h1>
{{if .User}}
<p>本机的 osmium CLI 请求以 <strong>{{.User}}</strong> 的身份登录。只有在你刚刚运行了 <code>osmium login</code> 时才应该授权。</p>
<form method="post" action="/auth/cli">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="port" value="{{.Port}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.Challenge}}">
<button type="submit">授权</button>
</form>
{{else}}
<p>{{.Message}}</p>
{{end}}
</body></html>`))

// HandleCLIAuthorize shows the confirmation page (GET /auth/cli).
func (a *Authenticator) HandleCLIAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := parseCLIParams(r.URL.Query().Get)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		_ = cliPage.Execute(w, map[string]any{"Message": "无效的 CLI 登录请求，请重新运行 osmium login。"})
		return
	}
	s, ok := a.Lookup(r)
	if !ok {
		if a.oauth != nil {
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = cliPage.Execute(w, map[string]any{"Message": "请先在此浏览器中登录 Web 界面，然后重新运行 osmium login。"})
		return
	}
	name := s.User.DisplayName
	if name == "" {
		name = s.User.ID
	}
	_ = cliPage.Execute(w, map[string]any{"User": name, "CSRF": s.CSRF, "Port": p.Port, "State": p.State, "Challenge": p.Challenge})
}

// HandleCLIApprove issues a one-time code (POST /auth/cli). The caller must
// enforce a same-origin Origin header.
func (a *Authenticator) HandleCLIApprove(w http.ResponseWriter, r *http.Request) {
	s, ok := a.Lookup(r)
	if !ok {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if c := r.PostForm.Get("csrf"); c == "" || subtle.ConstantTimeCompare([]byte(c), []byte(s.CSRF)) != 1 {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	p, ok := parseCLIParams(r.PostForm.Get)
	if !ok {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	code := random(32)
	a.mu.Lock()
	now := time.Now()
	for k, c := range a.cliCodes {
		if now.After(c.expires) {
			delete(a.cliCodes, k)
		}
	}
	if len(a.cliCodes) >= maxPendingCLI {
		a.mu.Unlock()
		http.Error(w, "too many pending CLI logins", http.StatusServiceUnavailable)
		return
	}
	a.cliCodes[key(code)] = cliCode{user: s.User, challenge: p.Challenge, expires: now.Add(cliCodeTTL)}
	a.mu.Unlock()
	a.audit.Record(audit.Event{Actor: "user:" + s.User.ID, Action: "cli.authorize", Result: "ok"})
	// Only ever redirect to the loopback interface of the user's machine.
	q := url.Values{"code": {code}, "state": {p.State}}
	http.Redirect(w, r, "http://127.0.0.1:"+strconv.Itoa(p.Port)+"/callback?"+q.Encode(), http.StatusSeeOther)
}

// HandleCLIToken exchanges a code + PKCE verifier for a Bearer token
// (POST /auth/cli/token).
func (a *Authenticator) HandleCLIToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code     string `json:"code"`
		Verifier string `json:"code_verifier"`
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 4096))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil || !urlSafe(body.Code, 16, 128) || !urlSafe(body.Verifier, 43, 128) {
		writeErr(w, http.StatusBadRequest, "INVALID_REQUEST")
		return
	}
	a.mu.Lock()
	c, ok := a.cliCodes[key(body.Code)]
	delete(a.cliCodes, key(body.Code)) // single use, even on failure
	a.mu.Unlock()
	sum := sha256.Sum256([]byte(body.Verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ok || time.Now().After(c.expires) || subtle.ConstantTimeCompare([]byte(challenge), []byte(c.challenge)) != 1 {
		a.audit.Record(audit.Event{Action: "cli.token", Result: "denied"})
		writeErr(w, http.StatusBadRequest, "INVALID_GRANT")
		return
	}
	tok := cliTokenPfx + random(32)
	t := &CLIToken{User: c.user, ExpiresAt: time.Now().Add(a.cfg.SessionTTL)}
	a.mu.Lock()
	now := time.Now()
	for k, v := range a.cliTokens {
		if now.After(v.ExpiresAt) {
			delete(a.cliTokens, k)
		}
	}
	a.cliTokens[key(tok)] = t
	a.mu.Unlock()
	a.audit.Record(audit.Event{Actor: "user:" + c.user.ID, Action: "cli.token", Result: "ok"})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_at": t.ExpiresAt, "user": c.user})
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	t := strings.TrimSpace(h[7:])
	if !strings.HasPrefix(t, cliTokenPfx) {
		return ""
	}
	return t
}

// HasBearer reports whether the request carries a CLI Bearer token.
func HasBearer(r *http.Request) bool { return bearer(r) != "" }

// LookupBearer returns the CLI token of the request.
func (a *Authenticator) LookupBearer(r *http.Request) (*CLIToken, bool) {
	t := bearer(r)
	if t == "" {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cliTokens[key(t)]
	if !ok || time.Now().After(c.ExpiresAt) {
		delete(a.cliTokens, key(t))
		return nil, false
	}
	return c, true
}

// RevokeBearer deletes the request's CLI token.
func (a *Authenticator) RevokeBearer(r *http.Request) {
	if t := bearer(r); t != "" {
		a.mu.Lock()
		delete(a.cliTokens, key(t))
		a.mu.Unlock()
	}
}

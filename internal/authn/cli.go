package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/indexyz/osmium/internal/audit"
)

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
	ID         string
	User       User
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// CLITokenInfo is the admin-visible metadata of an active CLI token. Neither
// the raw token nor its hash is ever exposed.
type CLITokenInfo struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastUsedAt  time.Time `json:"last_used_at,omitzero"`
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

const cliPageHead = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>授权 osmium CLI</title>
<style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.6}
button{font-size:1rem;padding:.5rem 1.2rem}code{background:#eee;padding:0 .3em}</style></head>
<body>
<h1>授权 osmium CLI</h1>
`

const cliPageTail = `</body></html>`

func writeCLIPage(w io.Writer, body string) {
	_, _ = io.WriteString(w, cliPageHead+body+cliPageTail)
}

func cliMessage(msg string) string { return "<p>" + html.EscapeString(msg) + "</p>\n" }

func cliConfirm(user, csrf string, p cliParams) string {
	input := func(name, value string) string {
		return `<input type="hidden" name="` + name + `" value="` + html.EscapeString(value) + `">` + "\n"
	}
	return "<p>本机的 osmium CLI 请求以 <strong>" + html.EscapeString(user) + "</strong> 的身份登录。只有在你刚刚运行了 <code>osmium login</code> 时才应该授权。</p>\n" +
		`<form method="post" action="/auth/cli">` + "\n" +
		input("csrf", csrf) + input("port", strconv.Itoa(p.Port)) + input("state", p.State) + input("code_challenge", p.Challenge) +
		`<button type="submit">授权</button>` + "\n</form>\n"
}

// HandleCLIAuthorize shows the confirmation page (GET /auth/cli).
func (a *Authenticator) HandleCLIAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := parseCLIParams(r.URL.Query().Get)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		writeCLIPage(w, cliMessage("无效的 CLI 登录请求，请重新运行 osmium login。"))
		return
	}
	s, ok := a.Lookup(r)
	if !ok {
		if a.oauth != nil {
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		writeCLIPage(w, cliMessage("请先在此浏览器中登录 Web 界面，然后重新运行 osmium login。"))
		return
	}
	name := s.User.DisplayName
	if name == "" {
		name = s.User.ID
	}
	writeCLIPage(w, cliConfirm(name, s.CSRF, p))
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
	k := key(code)
	now := time.Now()
	a.mu.Lock()
	for len(a.cliCodes) >= maxPendingCLI && len(a.cliCodeOrder) > 0 {
		oldest := a.cliCodeOrder[0]
		if c, ok := a.cliCodes[oldest]; ok && !now.After(c.expires) {
			break
		}
		a.cliCodeOrder = a.cliCodeOrder[1:]
		delete(a.cliCodes, oldest)
	}
	if len(a.cliCodes) >= maxPendingCLI {
		a.mu.Unlock()
		http.Error(w, "too many pending CLI logins", http.StatusServiceUnavailable)
		return
	}
	a.cliCodes[k] = cliCode{user: s.User, challenge: p.Challenge, expires: now.Add(cliCodeTTL)}
	a.cliCodeOrder = append(a.cliCodeOrder, k)
	a.mu.Unlock()
	a.audit.Record(audit.Event{Actor: "user:" + s.User.ID, User: s.User.DisplayName, Action: "cli.authorize", Result: "ok"})
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
	ck := key(body.Code)
	a.mu.Lock()
	c, ok := a.cliCodes[ck]
	delete(a.cliCodes, ck) // single use, even on failure
	a.mu.Unlock()
	sum := sha256.Sum256([]byte(body.Verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ok || time.Now().After(c.expires) || subtle.ConstantTimeCompare([]byte(challenge), []byte(c.challenge)) != 1 {
		a.audit.Record(audit.Event{Action: "cli.token", Result: "denied"})
		writeErr(w, http.StatusBadRequest, "INVALID_GRANT")
		return
	}
	tok := cliTokenPfx + random(32)
	tk := key(tok)
	now := time.Now().UTC()
	t := &CLIToken{ID: "ct-" + random(9), User: c.user, CreatedAt: now, ExpiresAt: now.Add(a.cfg.SessionTTL)}
	var evicted []string
	a.mu.Lock()
	for len(a.cliTokens) >= maxCLITokens && len(a.cliTokenOrder) > 0 {
		oldest := a.cliTokenOrder[0]
		a.cliTokenOrder = a.cliTokenOrder[1:]
		if _, exists := a.cliTokens[oldest]; exists {
			delete(a.cliTokens, oldest)
			evicted = append(evicted, oldest)
		}
	}
	a.cliTokens[tk] = t
	a.cliTokenOrder = append(a.cliTokenOrder, tk)
	a.mu.Unlock()
	if a.store != nil {
		for _, ek := range evicted {
			_ = a.store.DeleteCLIToken(ek)
		}
		if err := a.store.SaveCLIToken(tk, t); err != nil && a.log != nil {
			a.log.Error("persist cli token failed", "err", err)
		}
	}
	a.audit.Record(audit.Event{Actor: "user:" + c.user.ID, User: c.user.DisplayName, Action: "cli.token", Result: "ok", Extra: map[string]any{"token_id": t.ID}})
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
	tk := key(t)
	now := time.Now().UTC()
	a.mu.Lock()
	c, ok := a.cliTokens[tk]
	if !ok || now.After(c.ExpiresAt) {
		delete(a.cliTokens, tk)
		a.mu.Unlock()
		if ok && a.store != nil {
			_ = a.store.DeleteCLIToken(tk)
		}
		return nil, false
	}
	shouldTouch := now.Sub(c.LastUsedAt) >= time.Minute
	c.LastUsedAt = now
	cp := *c
	a.mu.Unlock()
	if shouldTouch && a.store != nil {
		_ = a.store.TouchCLIToken(tk, now)
	}
	return &cp, true
}

// RevokeBearer deletes the request's CLI token.
func (a *Authenticator) RevokeBearer(r *http.Request) {
	if t := bearer(r); t != "" {
		tk := key(t)
		a.mu.Lock()
		delete(a.cliTokens, tk)
		a.mu.Unlock()
		if a.store != nil {
			_ = a.store.DeleteCLIToken(tk)
		}
	}
}

func tokenInfo(c *CLIToken) CLITokenInfo {
	return CLITokenInfo{
		ID:          c.ID,
		UserID:      c.User.ID,
		DisplayName: c.User.DisplayName,
		Issuer:      c.User.Issuer,
		CreatedAt:   c.CreatedAt,
		ExpiresAt:   c.ExpiresAt,
		LastUsedAt:  c.LastUsedAt,
	}
}

// ListCLITokens returns metadata for all non-expired CLI tokens, newest first.
func (a *Authenticator) ListCLITokens() []CLITokenInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	out := make([]CLITokenInfo, 0, len(a.cliTokens))
	for k, c := range a.cliTokens {
		if now.After(c.ExpiresAt) {
			delete(a.cliTokens, k)
			continue
		}
		out = append(out, tokenInfo(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// RevokeCLITokenByID removes one CLI token by its non-secret metadata ID.
func (a *Authenticator) RevokeCLITokenByID(id string) (CLITokenInfo, bool) {
	a.mu.Lock()
	var rmKey string
	var info CLITokenInfo
	for k, c := range a.cliTokens {
		if c.ID == id {
			info = tokenInfo(c)
			rmKey = k
			delete(a.cliTokens, k)
			break
		}
	}
	a.mu.Unlock()
	if rmKey == "" {
		return CLITokenInfo{}, false
	}
	if a.store != nil {
		_ = a.store.DeleteCLIToken(rmKey)
	}
	return info, true
}

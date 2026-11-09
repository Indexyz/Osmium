// Package authn handles Web login: OIDC authorization code flow with PKCE,
// server-side Web sessions in an HttpOnly cookie, and CSRF tokens. The OIDC
// ID token is used once at login and never kept as a signing credential.
package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
)

const (
	cookieName  = "web_session"
	stateCookie = "oidc_state"
)

// User is the internal user identity.
type User struct {
	ID          string   `json:"id"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
}

// UserID derives a stable internal ID from (issuer, subject). Email is never
// part of the security identity.
func UserID(issuer, subject string) string {
	h := sha256.Sum256([]byte(issuer + "\x00" + subject))
	return "u-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:10]))
}

// WebSession is a server-side login session.
type WebSession struct {
	User      User
	CSRF      string
	ExpiresAt time.Time
}

// OIDCConfig configures the identity provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	GroupsClaim  string
}

// Config configures the authenticator.
type Config struct {
	OIDC         *OIDCConfig
	DevLogin     bool // local development only: /auth/dev-login?user=NAME
	SessionTTL   time.Duration
	SecureCookie bool
}

// Authenticator implements login and session lookup.
type Authenticator struct {
	cfg      Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	audit    *audit.Logger
	log      *slog.Logger

	mu       sync.Mutex
	sessions map[string]*WebSession // key: sha256(cookie)
	pending  map[string]pendingLogin

	cliCodes  map[string]cliCode   // key: sha256(code)
	cliTokens map[string]*CLIToken // key: sha256(token)
}

type pendingLogin struct {
	nonce, verifier, browserBinding, next string
	expires                               time.Time
}

// New creates the authenticator, discovering the OIDC provider if set.
func New(ctx context.Context, cfg Config, a *audit.Logger, log *slog.Logger) (*Authenticator, error) {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	au := &Authenticator{cfg: cfg, audit: a, log: log, sessions: map[string]*WebSession{}, pending: map[string]pendingLogin{}, cliCodes: map[string]cliCode{}, cliTokens: map[string]*CLIToken{}}
	if cfg.OIDC == nil && !cfg.DevLogin {
		return nil, errors.New("authn: configure oidc (or dev_login for local development)")
	}
	if cfg.OIDC != nil {
		p, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
		if err != nil {
			return nil, fmt.Errorf("authn: oidc discovery: %w", err)
		}
		scopes := cfg.OIDC.Scopes
		if len(scopes) == 0 {
			scopes = []string{oidc.ScopeOpenID, "profile", "email"}
		}
		au.provider = p
		au.verifier = p.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
		au.oauth = &oauth2.Config{ClientID: cfg.OIDC.ClientID, ClientSecret: cfg.OIDC.ClientSecret, RedirectURL: cfg.OIDC.RedirectURL, Endpoint: p.Endpoint(), Scopes: scopes}
	}
	return au, nil
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func key(token string) string {
	h := sha256.Sum256([]byte(token))
	return string(h[:])
}

// Lookup returns the Web session for the request cookie.
func (a *Authenticator) Lookup(r *http.Request) (*WebSession, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key(c.Value)]
	if !ok || time.Now().After(s.ExpiresAt) {
		delete(a.sessions, key(c.Value))
		return nil, false
	}
	return s, true
}

// CheckCSRF validates the X-CSRF-Token header against the session.
func CheckCSRF(r *http.Request, s *WebSession) bool {
	h := r.Header.Get("X-CSRF-Token")
	return h != "" && subtle.ConstantTimeCompare([]byte(h), []byte(s.CSRF)) == 1
}

// Subject builds the authorization subject for a user.
func Subject(u User, snap *authz.Snapshot) authz.Subject {
	s := authz.Subject{UserID: u.ID, Issuer: u.Issuer, Sub: u.Subject, Groups: u.Groups}
	s.IsAdmin = snap.IsAdmin(s)
	return s
}

func (a *Authenticator) startSession(w http.ResponseWriter, u User) {
	tok := random(32)
	s := &WebSession{User: u, CSRF: random(24), ExpiresAt: time.Now().Add(a.cfg.SessionTTL)}
	a.mu.Lock()
	now := time.Now()
	for k, v := range a.sessions {
		if now.After(v.ExpiresAt) {
			delete(a.sessions, k)
		}
	}
	a.sessions[key(tok)] = s
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, Expires: s.ExpiresAt})
	a.audit.Record(audit.Event{Actor: "user:" + u.ID, Action: "web.login", Result: "ok", Extra: map[string]any{"issuer": u.Issuer}})
}

// HandleLogin starts the OIDC flow.
func (a *Authenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	state, nonce, verifier, binding := random(24), random(24), oauth2.GenerateVerifier(), random(24)
	a.mu.Lock()
	now := time.Now()
	for k, p := range a.pending {
		if now.After(p.expires) {
			delete(a.pending, k)
		}
	}
	if len(a.pending) > 10000 {
		a.mu.Unlock()
		http.Error(w, "too many pending logins", http.StatusServiceUnavailable)
		return
	}
	a.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, browserBinding: binding, next: SafeNext(r.URL.Query().Get("next")), expires: now.Add(10 * time.Minute)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: binding, Path: "/auth/", HttpOnly: true, Secure: a.cfg.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// HandleCallback completes the OIDC flow.
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if a.oauth == nil {
		http.Error(w, "oidc not configured", http.StatusNotFound)
		return
	}
	state := r.URL.Query().Get("state")
	a.mu.Lock()
	p, ok := a.pending[state]
	delete(a.pending, state)
	a.mu.Unlock()
	bc, _ := r.Cookie(stateCookie)
	if !ok || time.Now().After(p.expires) || bc == nil || subtle.ConstantTimeCompare([]byte(bc.Value), []byte(p.browserBinding)) != 1 {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth/", MaxAge: -1})
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(p.verifier))
	if err != nil {
		a.log.Warn("oidc code exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(p.nonce)) != 1 {
		a.log.Warn("id token rejected", "err", err)
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	u := User{ID: UserID(idt.Issuer, idt.Subject), Issuer: idt.Issuer, Subject: idt.Subject}
	for _, k := range []string{"name", "preferred_username", "email"} {
		if v, ok := claims[k].(string); ok && v != "" {
			u.DisplayName = v
			break
		}
	}
	if gc := a.cfg.OIDC.GroupsClaim; gc != "" {
		if arr, ok := claims[gc].([]any); ok {
			for _, g := range arr {
				if s, ok := g.(string); ok {
					u.Groups = append(u.Groups, s)
				}
			}
		}
	}
	a.startSession(w, u)
	http.Redirect(w, r, p.next, http.StatusFound)
}

// HandleDevLogin creates a session for a named local user. Development only.
func (a *Authenticator) HandleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.DevLogin {
		http.NotFound(w, r)
		return
	}
	name := r.URL.Query().Get("user")
	if !authz.ValidID(name) {
		http.Error(w, "invalid user", http.StatusBadRequest)
		return
	}
	var groups []string
	for _, g := range r.URL.Query()["group"] {
		if authz.ValidID(g) {
			groups = append(groups, g)
		}
	}
	a.startSession(w, User{ID: UserID("dev", name), Issuer: "dev", Subject: name, DisplayName: name + " (dev)", Groups: groups})
	http.Redirect(w, r, SafeNext(r.URL.Query().Get("next")), http.StatusFound)
}

// HandleLogout ends the Web session (CSRF protected).
func (a *Authenticator) HandleLogout(w http.ResponseWriter, r *http.Request) {
	s, ok := a.Lookup(r)
	if ok && !CheckCSRF(r, s) {
		http.Error(w, "csrf", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(cookieName); err == nil {
		a.mu.Lock()
		delete(a.sessions, key(c.Value))
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.cfg.SecureCookie})
	w.WriteHeader(http.StatusNoContent)
}

// OIDCEnabled reports whether OIDC login is configured.
func (a *Authenticator) OIDCEnabled() bool { return a.oauth != nil }

// DevLoginEnabled reports whether dev login is on.
func (a *Authenticator) DevLoginEnabled() bool { return a.cfg.DevLogin }

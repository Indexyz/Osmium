// Package server wires the Web API, the browser terminal WebSocket and the
// Agent endpoints together.
package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/indexyz/osmium/internal/agenthub"
	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/sessions"
	"github.com/indexyz/osmium/web"
)

// Server holds the HTTP handlers.
type Server struct {
	Store    *authz.Store
	Hub      *agenthub.Hub
	Sessions *sessions.Manager
	Direct   *DirectCertIssuer
	Auth     *authn.Authenticator
	Audit    *audit.Logger
	Log      *slog.Logger
	// AllowedOrigins for browser WebSockets, e.g. "https://ssh.example.com".
	AllowedOrigins []string
}

// WebHandler returns the browser-facing handler.
func (s *Server) WebHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", web.Handler())
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /auth/login", s.Auth.HandleLogin)
	mux.HandleFunc("GET /auth/callback", s.Auth.HandleCallback)
	mux.HandleFunc("GET /auth/dev-login", s.Auth.HandleDevLogin)
	mux.HandleFunc("POST /auth/logout", s.Auth.HandleLogout)
	mux.HandleFunc("GET /auth/cli", s.Auth.HandleCLIAuthorize)
	mux.HandleFunc("POST /auth/cli", s.sameOrigin(s.Auth.HandleCLIApprove))
	mux.HandleFunc("POST /auth/cli/token", s.Auth.HandleCLIToken)
	mux.HandleFunc("POST /api/v1/cli/logout", s.authed(s.cliLogout))
	mux.HandleFunc("POST /api/v1/native-sessions", s.authed(s.createNative))
	mux.HandleFunc("POST /api/v1/direct-certs", s.authed(s.issueDirectCert))
	mux.HandleFunc("GET /api/v1/host-cas", s.authed(s.hostCAs))
	mux.HandleFunc("GET /api/v1/ssh-sessions/{session_id}/tunnel", s.authed(s.nativeTunnel))
	mux.HandleFunc("GET /api/v1/me", s.authed(s.me))
	mux.HandleFunc("GET /api/v1/hosts", s.authed(s.listHosts))
	mux.HandleFunc("GET /api/v1/ssh-sessions", s.authed(s.listSessions))
	mux.HandleFunc("POST /api/v1/ssh-sessions", s.authed(s.csrf(s.createSession)))
	mux.HandleFunc("GET /api/v1/ssh-sessions/{session_id}", s.authed(s.getSession))
	mux.HandleFunc("POST /api/v1/ssh-sessions/{session_id}/close", s.authed(s.csrf(s.closeSession)))
	mux.HandleFunc("GET /api/v1/ssh-sessions/{session_id}/terminal", s.authed(s.terminal))
	mux.HandleFunc("GET /api/v1/admin/agents", s.authed(s.adminAgents))
	mux.HandleFunc("GET /api/v1/admin/audit", s.authed(s.adminAudit))
	mux.HandleFunc("GET /api/v1/admin/cli-tokens", s.authed(s.adminListCLITokens))
	mux.HandleFunc("POST /api/v1/admin/cli-tokens/{token_id}/revoke", s.authed(s.csrf(s.adminRevokeCLIToken)))
	mux.HandleFunc("POST /api/v1/admin/users/{user_id}/revoke", s.authed(s.csrf(s.adminRevokeUser)))
	mux.HandleFunc("PUT /api/v1/admin/hosts/{host_id}", s.authed(s.csrf(s.adminUpsertHost)))
	mux.HandleFunc("DELETE /api/v1/admin/hosts/{host_id}", s.authed(s.csrf(s.adminDeleteHost)))
	mux.HandleFunc("PUT /api/v1/admin/grants/{grant_id}", s.authed(s.csrf(s.adminUpsertGrant)))
	mux.HandleFunc("DELETE /api/v1/admin/grants/{grant_id}", s.authed(s.csrf(s.adminDeleteGrant)))
	mux.HandleFunc("GET /api/v1/admin/cert-roles", s.authed(s.adminListCertRoles))
	mux.HandleFunc("PUT /api/v1/admin/cert-roles/{role_id}", s.authed(s.csrf(s.adminUpsertCertRole)))
	mux.HandleFunc("DELETE /api/v1/admin/cert-roles/{role_id}", s.authed(s.csrf(s.adminDeleteCertRole)))
	mux.HandleFunc("PUT /api/v1/admin/host-cas", s.authed(s.csrf(s.adminSetHostCAs)))
	return securityHeaders(mux)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AgentHandler returns the handler for the mTLS Agent listener.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.TunnelPath, s.Hub.HandleTunnel)
	return mux
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

type reqCtx struct {
	web     *authn.WebSession // nil for CLI Bearer requests
	user    authn.User
	bearer  bool
	subject authz.Subject
	id      string
}

func requestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "r-" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	id := ""
	if rc, ok := r.Context().Value(ctxKey{}).(*reqCtx); ok {
		id = rc.id
	} else {
		id = requestID()
	}
	writeJSON(w, status, map[string]string{"code": code, "message": msg, "request_id": id})
}

func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *reqCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rc := &reqCtx{id: requestID()}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, rc))
		// A request carrying a Bearer token is authenticated by that token
		// only; it never falls back to the ambient cookie.
		if authn.HasBearer(r) {
			t, ok := s.Auth.LookupBearer(r)
			if !ok {
				writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "invalid or expired token")
				return
			}
			rc.user, rc.bearer = t.User, true
		} else {
			ws, ok := s.Auth.Lookup(r)
			if !ok {
				writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "login required")
				return
			}
			rc.web, rc.user = ws, ws.User
		}
		snap := s.Store.Current()
		rc.subject = authn.Subject(rc.user, snap)
		if snap.IsDisabled(rc.subject) {
			s.Audit.Record(audit.Event{Actor: "user:" + rc.subject.UserID, User: rc.subject.Name, Action: "auth.access", Result: "denied", Revision: snap.Revision, Reason: "user_disabled"})
			writeError(w, r, http.StatusForbidden, "USER_DISABLED", "user is disabled")
			return
		}
		h(w, r, rc)
	}
}

// sameOrigin requires an Origin header matching the public origin.
func (s *Server) sameOrigin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r, false) {
			writeError(w, r, http.StatusForbidden, "ORIGIN", "origin not allowed")
			return
		}
		h(w, r)
	}
}

// csrf protects cookie-authenticated writes. Bearer requests are exempt: the
// token is never sent ambiently by a browser.
func (s *Server) csrf(h func(http.ResponseWriter, *http.Request, *reqCtx)) func(http.ResponseWriter, *http.Request, *reqCtx) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
		if rc.bearer {
			h(w, r, rc)
			return
		}
		if !authn.CheckCSRF(r, rc.web) || !s.originAllowed(r, true) {
			writeError(w, r, http.StatusForbidden, "CSRF", "missing or invalid CSRF token")
			return
		}
		h(w, r, rc)
	}
}

// originAllowed checks the Origin header. For WebSockets it is mandatory.
func (s *Server) originAllowed(r *http.Request, optional bool) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return optional
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return slices.Contains(s.AllowedOrigins, u.Scheme+"://"+u.Host)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	out := map[string]any{"user": rc.user, "is_admin": rc.subject.IsAdmin}
	if rc.web != nil {
		out["csrf_token"] = rc.web.CSRF
	}
	writeJSON(w, http.StatusOK, out)
}

type hostView struct {
	ID                string            `json:"id"`
	DisplayName       string            `json:"display_name"`
	ConnectionMode    string            `json:"connection_mode"`
	SSHAddress        string            `json:"ssh_address,omitempty"`
	Status            string            `json:"status"`
	PolicyLabels      map[string]string `json:"policy_labels"`
	AllowedLoginUsers []string          `json:"allowed_login_users"`
}

// parseLabelFilter parses repeated label=key=value (AND).
func parseLabelFilter(vals []string) (map[string]string, bool) {
	f := map[string]string{}
	if len(vals) > 32 {
		return nil, false
	}
	for _, v := range vals {
		k, val, ok := strings.Cut(v, "=")
		if !ok || k == "" || len(k) > 63 || len(val) > 256 {
			return nil, false
		}
		f[k] = val
	}
	return f, true
}

func decodeOpaqueCursor(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	if len(raw) > 256 {
		return "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) == 0 || len(b) > 128 {
		return "", false
	}
	id := string(b)
	if !authz.ValidID(id) {
		return "", false
	}
	return id, true
}

func encodeOpaqueCursor(id string) string {
	if id == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	q := r.URL.Query()
	filter, ok := parseLabelFilter(q["label"])
	if !ok {
		writeError(w, r, http.StatusBadRequest, "INVALID_FILTER", "label filter must be key=value")
		return
	}
	statusFilter := strings.TrimSpace(q.Get("status"))
	switch statusFilter {
	case "", "ready", "direct", "offline", "disabled":
	default:
		writeError(w, r, http.StatusBadRequest, "INVALID_FILTER", "status must be ready, direct, offline or disabled")
		return
	}
	limit := 50
	if rawLim := q.Get("limit"); rawLim != "" {
		n, err := strconv.Atoi(rawLim)
		if err != nil || n < 1 || n > 500 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "limit must be 1..500")
			return
		}
		limit = n
	}
	cursorID, ok := decodeOpaqueCursor(q.Get("cursor"))
	if !ok {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid cursor")
		return
	}
	searchQ := q.Get("q")
	if len(searchQ) > 128 {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "query too long")
		return
	}

	snap := s.Store.Current()
	page := snap.VisibleHostsPage(rc.subject, authz.HostPageQuery{
		Labels: filter,
		Query:  searchQ,
		Status: statusFilter,
		Cursor: cursorID,
		Limit:  limit,
	}, s.Hub.Status)

	items := make([]hostView, 0, len(page.Items))
	for _, entry := range page.Items {
		h := entry.Host
		items = append(items, hostView{
			ID:                h.ID,
			DisplayName:       h.DisplayName,
			ConnectionMode:    h.EffectiveMode(),
			SSHAddress:        h.SSHAddress,
			Status:            entry.Status,
			PolicyLabels:      h.PolicyLabels,
			AllowedLoginUsers: entry.AllowedLogins,
		})
	}
	out := map[string]any{"items": items, "total": page.Total}
	if page.NextCursor != "" {
		out["next_cursor"] = encodeOpaqueCursor(page.NextCursor)
	}
	writeJSON(w, http.StatusOK, out)
}

type createBody struct {
	HostID    string `json:"host_id"`
	LoginUser string `json:"login_user"`
	Terminal  struct {
		Rows int `json:"rows"`
		Cols int `json:"cols"`
	} `json:"terminal"`
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	idem := r.Header.Get("Idempotency-Key")
	if idem == "" || len(idem) > 128 {
		writeError(w, r, http.StatusBadRequest, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key header required")
		return
	}
	var body createBody
	d := json.NewDecoder(io.LimitReader(r.Body, 4096))
	d.DisallowUnknownFields() // principal, ttl, address etc. are not accepted
	if err := d.Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid body")
		return
	}
	sess, created, err := s.Sessions.Create(rc.subject, sessions.CreateRequest{
		HostID: body.HostID, Login: body.LoginUser, Rows: body.Terminal.Rows, Cols: body.Terminal.Cols,
		IdemKey: idem, BodyHash: sessions.BodyHash(body.HostID, body.LoginUser, itoa(body.Terminal.Rows), itoa(body.Terminal.Cols)),
	})
	switch {
	case errors.Is(err, sessions.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid host, login or terminal size")
	case errors.Is(err, sessions.ErrForbidden):
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "not allowed")
	case errors.Is(err, sessions.ErrConflict):
		writeError(w, r, http.StatusConflict, "IDEMPOTENCY_CONFLICT", "idempotency key reused with a different request")
	case errors.Is(err, sessions.ErrUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "HOST_UNAVAILABLE", "host agent is not ready")
	case errors.Is(err, sessions.ErrLimitReached):
		writeError(w, r, http.StatusConflict, "SESSION_LIMIT", "too many sessions")
	case err != nil:
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
	case created:
		writeJSON(w, http.StatusCreated, sess.View())
	default:
		writeJSON(w, http.StatusOK, sess.View())
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	items := s.Sessions.List(rc.subject)
	if items == nil {
		items = []sessions.View{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id := r.PathValue("session_id")
	if !authz.ValidID(id) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid session id")
		return
	}
	sess, err := s.Sessions.Get(rc.subject, id)
	if err != nil {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	writeJSON(w, http.StatusOK, sess.View())
}

func (s *Server) closeSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	id := r.PathValue("session_id")
	if !authz.ValidID(id) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid session id")
		return
	}
	sess, err := s.Sessions.Close(rc.subject, id, "user_close")
	if err != nil {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	writeJSON(w, http.StatusAccepted, sess.View())
}

func (s *Server) adminAgents(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	q := r.URL.Query()
	limit := 100
	if rawLim := q.Get("limit"); rawLim != "" {
		n, err := strconv.Atoi(rawLim)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "limit must be 1..1000")
			return
		}
		limit = n
	}
	cursorID, ok := decodeOpaqueCursor(q.Get("cursor"))
	if !ok {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid cursor")
		return
	}
	searchQ := q.Get("q")
	if len(searchQ) > 128 {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "query too long")
		return
	}
	page := s.Hub.AgentsPage(agenthub.AgentsPageQuery{
		Query:  searchQ,
		Cursor: cursorID,
		Limit:  limit,
	})
	out := map[string]any{"items": page.Items, "total": page.Total}
	if page.NextCursor != "" {
		out["next_cursor"] = encodeOpaqueCursor(page.NextCursor)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminUpsertHost(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	hostID := r.PathValue("host_id")
	if !authz.ValidID(hostID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid host id")
		return
	}
	var host authz.Host
	d := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&host); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid host payload")
		return
	}
	if host.ID != "" && host.ID != hostID {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "host id in body does not match path")
		return
	}
	host.ID = hostID
	snap, err := s.Store.UpsertHost(&host)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	saved, _ := snap.Host(hostID)
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.host_upsert", Result: "ok", Target: hostID, Revision: snap.Revision,
		Extra: map[string]any{"agent_id": saved.Agent.ID, "disabled": saved.Disabled},
	})
	writeJSON(w, http.StatusOK, map[string]any{"host": saved, "policy_revision": snap.Revision})
}

func (s *Server) adminDeleteHost(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	hostID := r.PathValue("host_id")
	if !authz.ValidID(hostID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid host id")
		return
	}
	snap, deleted, err := s.Store.DeleteHost(hostID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete host")
		return
	}
	if !deleted {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "host not found")
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.host_delete", Result: "ok", Target: hostID, Revision: snap.Revision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": hostID, "policy_revision": snap.Revision})
}

func (s *Server) adminUpsertGrant(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	grantID := r.PathValue("grant_id")
	if !authz.ValidID(grantID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid grant id")
		return
	}
	var g authz.Grant
	d := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&g); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid grant payload")
		return
	}
	if g.ID != "" && g.ID != grantID {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "grant id in body does not match path")
		return
	}
	g.ID = grantID
	snap, err := s.Store.UpsertGrant(g)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.grant_upsert", Result: "ok", Target: grantID, Revision: snap.Revision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"grant": g, "policy_revision": snap.Revision})
}

func (s *Server) adminDeleteGrant(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	grantID := r.PathValue("grant_id")
	if !authz.ValidID(grantID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid grant id")
		return
	}
	snap, deleted, err := s.Store.DeleteGrant(grantID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete grant")
		return
	}
	if !deleted {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "grant not found")
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.grant_delete", Result: "ok", Target: grantID, Revision: snap.Revision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": grantID, "policy_revision": snap.Revision})
}

func (s *Server) adminSetHostCAs(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	var body struct {
		HostCAPublicKeys []string `json:"host_ca_public_keys"`
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid body")
		return
	}
	snap, err := s.Store.SetHostCAs(body.HostCAPublicKeys)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.host_cas_update", Result: "ok", Revision: snap.Revision,
		Extra: map[string]any{"count": len(body.HostCAPublicKeys)},
	})
	writeJSON(w, http.StatusOK, map[string]any{"host_ca_public_keys": snap.HostCAPublicKeys(), "policy_revision": snap.Revision})
}

func (s *Server) adminListCLITokens(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Auth.ListCLITokens()})
}

func (s *Server) adminRevokeCLIToken(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	id := r.PathValue("token_id")
	if !authz.ValidID(id) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid token id")
		return
	}
	info, ok := s.Auth.RevokeCLITokenByID(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	s.Audit.Record(audit.Event{Actor: "user:" + rc.subject.UserID, User: rc.subject.Name, Action: "admin.cli_token_revoke", Result: "ok", Target: "user:" + info.UserID, Extra: map[string]any{"token_id": info.ID}})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": info})
}

func (s *Server) adminRevokeUser(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	userID := r.PathValue("user_id")
	if !authz.ValidID(userID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid user id")
		return
	}
	webN, cliN := s.Auth.RevokeUser(userID)
	sessN := s.Sessions.CloseUserSessions(userID, "user:"+rc.subject.UserID, "admin_user_revoke")
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.user_revoke", Result: "ok", Target: "user:" + userID,
		Extra: map[string]any{"revoked_web_sessions": webN, "revoked_cli_tokens": cliN, "closed_sessions": sessN},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":              userID,
		"revoked_web_sessions": webN,
		"revoked_cli_tokens":   cliN,
		"closed_sessions":      sessN,
	})
}

// adminAudit searches the persistent audit log (admins only). Query:
// from, to (RFC 3339; default the last 24h), user (display name or user ID),
// action, actor, session_id, target, limit (1..1000, default 100), cursor (from next_cursor).
func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	v := r.URL.Query()
	q := audit.Query{Action: v.Get("action"), User: v.Get("user"), Actor: v.Get("actor"), SessionID: v.Get("session_id"), Target: v.Get("target"), Cursor: v.Get("cursor"), Limit: 100}
	q.To = time.Now()
	var err error
	if p := v.Get("to"); p != "" {
		if q.To, err = time.Parse(time.RFC3339, p); err != nil {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "to must be RFC 3339")
			return
		}
	}
	q.From = q.To.Add(-24 * time.Hour)
	if p := v.Get("from"); p != "" {
		if q.From, err = time.Parse(time.RFC3339, p); err != nil {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "from must be RFC 3339")
			return
		}
	}
	if p := v.Get("limit"); p != "" {
		if q.Limit, err = strconv.Atoi(p); err != nil {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "limit must be an integer")
			return
		}
	}
	page, err := s.Audit.Search(r.Context(), q)
	switch {
	case errors.Is(err, audit.ErrBadQuery):
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
	case err != nil:
		s.Log.Error("audit search failed", "err", err)
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "audit search failed")
	default:
		if page.Events == nil {
			page.Events = []audit.Event{}
		}
		writeJSON(w, http.StatusOK, page)
	}
}

var errProtocol = errors.New("terminal protocol error")

// wsTerminal adapts the browser WebSocket to sessions.Terminal.
type wsTerminal struct {
	ws  *websocket.Conn
	ctx context.Context
}

func (t *wsTerminal) write(typ websocket.MessageType, b []byte) error {
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()
	return t.ws.Write(ctx, typ, b)
}

func (t *wsTerminal) State(state string) {
	_ = t.write(websocket.MessageText, protocol.EncodeTerminal(protocol.TypeTermState, protocol.TermState{State: state}))
}

func (t *wsTerminal) Exit(reason string, status *int) {
	_ = t.write(websocket.MessageText, protocol.EncodeTerminal(protocol.TypeTermExit, protocol.TermExit{Reason: reason, ExitStatus: status}))
}

func (t *wsTerminal) Output(p []byte) error { return t.write(websocket.MessageBinary, p) }

func (s *Server) terminal(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.originAllowed(r, false) {
		writeError(w, r, http.StatusForbidden, "ORIGIN", "origin not allowed")
		return
	}
	id := r.PathValue("session_id")
	sess, err := s.Sessions.Get(rc.subject, id)
	// Only the owner may attach; administrators may close but not watch.
	if err != nil || sess.Subject.UserID != rc.subject.UserID || sess.Mode != sessions.ModeWeb || rc.bearer {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	if sess.State() != sessions.StateCreated {
		writeError(w, r, http.StatusConflict, "ALREADY_ATTACHED", "session already attached or ended")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{protocol.SubprotocolTerminal},
		// Origin was verified above against the configured public origins.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	if ws.Subprotocol() != protocol.SubprotocolTerminal {
		ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	ws.SetReadLimit(64 * 1024)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	term := &wsTerminal{ws: ws, ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.Sessions.Attach(sess, term) }()
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, data, err := ws.Read(ctx)
			if err != nil {
				readErr <- err
				return
			}
			switch typ {
			case websocket.MessageBinary:
				if err := sess.Input(data); err != nil {
					s.Log.Debug("terminal input failed", "session_id", id, "err", err)
				}
			case websocket.MessageText:
				mt, resize, err := protocol.DecodeTerminal(data)
				if err != nil {
					readErr <- errProtocol
					return
				}
				switch mt {
				case protocol.TypeTermResize:
					_ = sess.Resize(resize.Rows, resize.Cols)
				case protocol.TypeTermClose:
					_, _ = s.Sessions.Close(rc.subject, id, "user_close")
				}
			}
		}
	}()
	select {
	case err := <-done:
		if err != nil {
			ws.Close(websocket.StatusPolicyViolation, "cannot attach")
		} else {
			ws.Close(websocket.StatusNormalClosure, "session ended")
		}
		cancel()
		<-readErr
	case err := <-readErr:
		if errors.Is(err, errProtocol) {
			_, _ = s.Sessions.Close(rc.subject, id, "terminal_protocol_error")
			<-done
			ws.Close(websocket.StatusPolicyViolation, "invalid terminal message")
			return
		}
		// Browser went away: cancel pending writes first so shutdown does not
		// block on write timeouts against a dead socket (pending decision O06).
		cancel()
		_, _ = s.Sessions.Close(rc.subject, id, "browser_disconnected")
		<-done
	}
}

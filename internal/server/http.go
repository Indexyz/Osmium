// Package server wires the Web API, the browser terminal WebSocket and the
// Agent endpoints together.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
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
	mux.HandleFunc("GET /auth/login", s.Auth.HandleLogin)
	mux.HandleFunc("GET /auth/callback", s.Auth.HandleCallback)
	mux.HandleFunc("GET /auth/dev-login", s.Auth.HandleDevLogin)
	mux.HandleFunc("POST /auth/logout", s.Auth.HandleLogout)
	mux.HandleFunc("GET /api/v1/me", s.authed(s.me))
	mux.HandleFunc("GET /api/v1/hosts", s.authed(s.listHosts))
	mux.HandleFunc("GET /api/v1/ssh-sessions", s.authed(s.listSessions))
	mux.HandleFunc("POST /api/v1/ssh-sessions", s.authed(s.csrf(s.createSession)))
	mux.HandleFunc("GET /api/v1/ssh-sessions/{session_id}", s.authed(s.getSession))
	mux.HandleFunc("POST /api/v1/ssh-sessions/{session_id}/close", s.authed(s.csrf(s.closeSession)))
	mux.HandleFunc("GET /api/v1/ssh-sessions/{session_id}/terminal", s.authed(s.terminal))
	mux.HandleFunc("GET /api/v1/admin/agents", s.authed(s.adminAgents))
	return securityHeaders(mux)
}

// AgentHandler returns the handler for the mTLS Agent listener.
func (s *Server) AgentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.ControlPath, s.Hub.HandleControl)
	mux.HandleFunc("GET "+protocol.DataPath, s.Hub.HandleData)
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
	web     *authn.WebSession
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
		ws, ok := s.Auth.Lookup(r)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "login required")
			return
		}
		rc.web = ws
		rc.subject = authn.Subject(ws.User, s.Store.Current())
		h(w, r, rc)
	}
}

func (s *Server) csrf(h func(http.ResponseWriter, *http.Request, *reqCtx)) func(http.ResponseWriter, *http.Request, *reqCtx) {
	return func(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
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
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       rc.web.User,
		"is_admin":   rc.subject.IsAdmin,
		"csrf_token": rc.web.CSRF,
	})
}

type hostView struct {
	ID                string            `json:"id"`
	DisplayName       string            `json:"display_name"`
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

func (s *Server) listHosts(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	filter, ok := parseLabelFilter(r.URL.Query()["label"])
	if !ok {
		writeError(w, r, http.StatusBadRequest, "INVALID_FILTER", "label filter must be key=value")
		return
	}
	snap := s.Store.Current()
	items := []hostView{}
	// Authorize first, then filter: the filter never widens visibility.
	for _, h := range snap.VisibleHosts(rc.subject) {
		match := true
		for k, v := range filter {
			if h.PolicyLabels[k] != v {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		items = append(items, hostView{ID: h.ID, DisplayName: h.DisplayName, Status: s.Hub.Status(h), PolicyLabels: h.PolicyLabels, AllowedLoginUsers: snap.AllowedLogins(rc.subject, h)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
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
	writeJSON(w, http.StatusOK, map[string]any{"items": s.Hub.Agents()})
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
	if err != nil || sess.Subject.UserID != rc.subject.UserID {
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
			return
		}
		ws.Close(websocket.StatusNormalClosure, "session ended")
	case err := <-readErr:
		if errors.Is(err, errProtocol) {
			_, _ = s.Sessions.Close(rc.subject, id, "terminal_protocol_error")
			<-done
			ws.Close(websocket.StatusPolicyViolation, "invalid terminal message")
			return
		}
		// Browser went away: the session ends (pending product decision O06).
		_, _ = s.Sessions.Close(rc.subject, id, "browser_disconnected")
		<-done
	}
}

package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/protocol"
	"github.com/indexyz/osmium/internal/sessions"
)

func (s *Server) cliLogout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.bearer {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "bearer token required")
		return
	}
	s.Auth.RevokeBearer(r)
	w.WriteHeader(http.StatusNoContent)
}

type nativeBody struct {
	HostID    string `json:"host_id"`
	LoginUser string `json:"login_user"`
	PublicKey string `json:"public_key"`
}

func (s *Server) createNative(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	var body nativeBody
	d := json.NewDecoder(io.LimitReader(r.Body, 4096))
	d.DisallowUnknownFields() // principal, ttl, extensions etc. are not accepted
	if err := d.Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid body")
		return
	}
	sess, err := s.Sessions.CreateNative(rc.subject, sessions.NativeRequest{HostID: body.HostID, Login: body.LoginUser, PublicKey: body.PublicKey})
	switch {
	case errors.Is(err, sessions.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid host, login or public key (ed25519/ecdsa only)")
	case errors.Is(err, sessions.ErrKeyReused):
		writeError(w, r, http.StatusBadRequest, "KEY_REUSED", "public key already used; generate a new key per connection")
	case errors.Is(err, sessions.ErrForbidden):
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "not allowed")
	case errors.Is(err, sessions.ErrUnavailable):
		writeError(w, r, http.StatusServiceUnavailable, "HOST_UNAVAILABLE", "host agent is not ready")
	case errors.Is(err, sessions.ErrLimitReached):
		writeError(w, r, http.StatusConflict, "SESSION_LIMIT", "too many sessions")
	case err != nil:
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "internal error")
	default:
		writeJSON(w, http.StatusCreated, sess.View())
	}
}

// nativeConn adapts the CLI WebSocket to sessions.NativeClient.
type nativeConn struct {
	ws  *websocket.Conn
	ctx context.Context
	net.Conn
}

func (c *nativeConn) text(typ string, payload any) error {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	return c.ws.Write(ctx, websocket.MessageText, protocol.EncodeTerminal(typ, payload))
}

func (c *nativeConn) State(state string) {
	_ = c.text(protocol.TypeNativeState, protocol.TermState{State: state})
}

func (c *nativeConn) Ready(cert *ssh.Certificate, hostKeys []ssh.PublicKey) error {
	r := protocol.NativeReady{
		Certificate: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0).UTC(),
	}
	for _, k := range hostKeys {
		r.HostKeys = append(r.HostKeys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
	}
	return c.text(protocol.TypeNativeReady, r)
}

// nativeTunnel relays a native session (GET .../tunnel). Bearer only: a
// browser can never open it with ambient cookies.
func (s *Server) nativeTunnel(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.bearer {
		writeError(w, r, http.StatusForbidden, "BEARER_REQUIRED", "the native tunnel requires a CLI token")
		return
	}
	id := r.PathValue("session_id")
	if !authz.ValidID(id) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid session id")
		return
	}
	sess, err := s.Sessions.Get(rc.subject, id)
	if err != nil || sess.Subject.UserID != rc.subject.UserID || sess.Mode != sessions.ModeNative {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "not found")
		return
	}
	if sess.State() != sessions.StateCreated {
		writeError(w, r, http.StatusConflict, "ALREADY_ATTACHED", "session already attached or ended")
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: []string{protocol.SubprotocolNative},
		// Bearer-authenticated, not cookie-authenticated: Origin is irrelevant.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	if ws.Subprotocol() != protocol.SubprotocolNative {
		ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	ws.SetReadLimit(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &nativeConn{ws: ws, ctx: ctx, Conn: websocket.NetConn(ctx, ws, websocket.MessageBinary)}
	if err := s.Sessions.AttachNative(sess, c); err != nil {
		ws.Close(websocket.StatusPolicyViolation, "cannot attach")
		return
	}
	reason := "closed"
	if v := sess.View(); v.EndReason != nil {
		reason = *v.EndReason
	}
	_ = c.text(protocol.TypeNativeExit, protocol.TermExit{Reason: reason})
	ws.Close(websocket.StatusNormalClosure, "session ended")
}

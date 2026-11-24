package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/ca"
	"github.com/indexyz/osmium/internal/sessions"
	"github.com/indexyz/osmium/internal/sshgateway"
)

const (
	directKeyReuseWindow = 24 * time.Hour
	maxDirectSeenKeys    = 100000
)

// DirectCertConfig controls direct (agentless) SSH user certificate issuance.
type DirectCertConfig struct {
	DefaultHostTTL     time.Duration // default 60s
	MaxHostTTL         time.Duration // default 5m
	DefaultRoleTTL     time.Duration // default 4h
	MaxRoleTTL         time.Duration // default 8h
	SourceAddressMode  string        // "", "none", "static", "client_ip"
	SourceAddressCIDRs string        // comma-separated CIDRs for "static" mode
	TrustedProxies     []string      // CIDRs/IPs trusted to supply X-Forwarded-For in "client_ip" mode
	MaxConcurrentSigns int           // default 16
}

// DirectCertIssuer issues direct (agentless) SSH user certificates with
// ephemeral key replay protection, concurrency bounding, and optional
// source-address restriction.
type DirectCertIssuer struct {
	signer         ca.Signer
	defaultHostTTL time.Duration
	maxHostTTL     time.Duration
	defaultRoleTTL time.Duration
	maxRoleTTL     time.Duration
	sourceMode     string
	staticCIDRs    string
	trustedProxies []netip.Prefix
	signSem        chan struct{}

	mu           sync.Mutex
	seenKeys     map[string]time.Time
	seenKeyOrder []string
}

// NewDirectCertIssuer validates cfg and builds a DirectCertIssuer.
func NewDirectCertIssuer(signer ca.Signer, cfg DirectCertConfig) (*DirectCertIssuer, error) {
	if signer == nil {
		return nil, errors.New("direct_ca: signer is required")
	}
	if cfg.DefaultHostTTL <= 0 {
		cfg.DefaultHostTTL = 60 * time.Second
	}
	if cfg.MaxHostTTL <= 0 {
		cfg.MaxHostTTL = max(5*time.Minute, cfg.DefaultHostTTL)
	}
	if cfg.DefaultHostTTL > cfg.MaxHostTTL {
		cfg.DefaultHostTTL = cfg.MaxHostTTL
	}
	if cfg.DefaultRoleTTL <= 0 {
		cfg.DefaultRoleTTL = 4 * time.Hour
	}
	if cfg.MaxRoleTTL <= 0 {
		cfg.MaxRoleTTL = max(8*time.Hour, cfg.DefaultRoleTTL)
	}
	if cfg.MaxRoleTTL > 24*time.Hour {
		return nil, errors.New("direct_ca: max_role_ttl cannot exceed 24h")
	}
	if cfg.DefaultRoleTTL > cfg.MaxRoleTTL {
		cfg.DefaultRoleTTL = cfg.MaxRoleTTL
	}
	if cfg.MaxConcurrentSigns <= 0 {
		cfg.MaxConcurrentSigns = 16
	}

	mode := strings.TrimSpace(cfg.SourceAddressMode)
	staticCIDRs := ""
	switch mode {
	case "", "none":
		mode = "none"
	case "static":
		parts := strings.Split(cfg.SourceAddressCIDRs, ",")
		var cleaned []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			pfx, err := parseCIDROrIP(p)
			if err != nil {
				return nil, fmt.Errorf("direct_ca: invalid source_address_cidrs entry %q: %w", p, err)
			}
			cleaned = append(cleaned, pfx.String())
		}
		if len(cleaned) == 0 {
			return nil, errors.New("direct_ca: source_address_cidrs is required when source_address_mode is \"static\"")
		}
		staticCIDRs = strings.Join(cleaned, ",")
	case "client_ip":
	default:
		return nil, fmt.Errorf("direct_ca: invalid source_address_mode %q (expected none, static, or client_ip)", mode)
	}

	var proxies []netip.Prefix
	for _, raw := range cfg.TrustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		pfx, err := parseCIDROrIP(raw)
		if err != nil {
			return nil, fmt.Errorf("direct_ca: invalid trusted_proxies entry %q: %w", raw, err)
		}
		proxies = append(proxies, pfx)
	}

	return &DirectCertIssuer{
		signer:         signer,
		defaultHostTTL: cfg.DefaultHostTTL,
		maxHostTTL:     cfg.MaxHostTTL,
		defaultRoleTTL: cfg.DefaultRoleTTL,
		maxRoleTTL:     cfg.MaxRoleTTL,
		sourceMode:     mode,
		staticCIDRs:    staticCIDRs,
		trustedProxies: proxies,
		signSem:        make(chan struct{}, cfg.MaxConcurrentSigns),
		seenKeys:       make(map[string]time.Time),
	}, nil
}

func parseCIDROrIP(raw string) (netip.Prefix, error) {
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func (d *DirectCertIssuer) isTrustedProxy(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, pfx := range d.trustedProxies {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP resolves the caller's IP address safely. X-Forwarded-For is
// honored ONLY when the TCP peer (r.RemoteAddr) matches a configured
// trusted_proxies prefix, walking right-to-left to defeat left-side spoofing.
func (d *DirectCertIssuer) extractClientIP(r *http.Request) (netip.Addr, error) {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	remote, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("cannot determine client IP from %q", r.RemoteAddr)
	}
	remote = remote.Unmap()
	if !d.isTrustedProxy(remote) {
		return remote, nil
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remote, nil
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(parts[i])
		if raw == "" {
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid X-Forwarded-For address %q", raw)
		}
		ip = ip.Unmap()
		if !d.isTrustedProxy(ip) {
			return ip, nil
		}
	}
	return remote, nil
}

func (d *DirectCertIssuer) resolveSourceAddress(r *http.Request) (string, error) {
	switch d.sourceMode {
	case "", "none":
		return "", nil
	case "static":
		return d.staticCIDRs, nil
	case "client_ip":
		ip, err := d.extractClientIP(r)
		if err != nil {
			return "", err
		}
		ip = ip.Unmap()
		if ip.Is4() {
			return ip.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	default:
		return "", fmt.Errorf("unsupported source_address_mode %q", d.sourceMode)
	}
}

func (d *DirectCertIssuer) checkKeyUnused(fp string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if seenAt, ok := d.seenKeys[fp]; ok {
		if now.Sub(seenAt) <= directKeyReuseWindow {
			return false
		}
		delete(d.seenKeys, fp)
	}
	return true
}

func (d *DirectCertIssuer) reserveKey(fp string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if seenAt, ok := d.seenKeys[fp]; ok {
		if now.Sub(seenAt) <= directKeyReuseWindow {
			return false
		}
		delete(d.seenKeys, fp)
	}
	// Evict expired or oldest keys when approaching capacity.
	for len(d.seenKeys) >= maxDirectSeenKeys && len(d.seenKeyOrder) > 0 {
		oldest := d.seenKeyOrder[0]
		d.seenKeyOrder = d.seenKeyOrder[1:]
		delete(d.seenKeys, oldest)
	}
	d.seenKeys[fp] = now
	d.seenKeyOrder = append(d.seenKeyOrder, fp)
	if len(d.seenKeyOrder) > len(d.seenKeys)*2 && len(d.seenKeyOrder) > 1024 {
		kept := d.seenKeyOrder[:0]
		for _, k := range d.seenKeyOrder {
			if seenAt, ok := d.seenKeys[k]; ok && now.Sub(seenAt) <= directKeyReuseWindow {
				kept = append(kept, k)
			} else {
				delete(d.seenKeys, k)
			}
		}
		d.seenKeyOrder = kept
	}
	return true
}

func (d *DirectCertIssuer) sign(ctx context.Context, req ca.Request) (*ssh.Certificate, error) {
	select {
	case d.signSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-d.signSem }()
	return d.signer.SignUserCert(ctx, req)
}

func newDirectCertID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return "dc-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

type directCertBody struct {
	Mode       string   `json:"mode"`                 // "host" or "role"
	HostID     string   `json:"host_id,omitempty"`    // required when mode == "host"
	LoginUser  string   `json:"login_user,omitempty"` // required when mode == "host"
	Principals []string `json:"principals,omitempty"` // optional narrowing subset when mode == "role"
	TTL        string   `json:"ttl,omitempty"`        // optional Go duration, strictly server-capped
	PublicKey  string   `json:"public_key"`           // ephemeral ed25519/ecdsa public key
}

type directCertResponse struct {
	CertID             string    `json:"cert_id"`
	Mode               string    `json:"mode"`
	Certificate        string    `json:"certificate"`
	KeyID              string    `json:"key_id"`
	Serial             string    `json:"serial"`
	Principals         []string  `json:"principals"`
	ValidAfter         time.Time `json:"valid_after"`
	ValidBefore        time.Time `json:"valid_before"`
	SourceAddress      string    `json:"source_address,omitempty"`
	SSHAddress         string    `json:"ssh_address,omitempty"`
	HostKeys           []string  `json:"host_keys,omitempty"`
	HostCAs            []string  `json:"host_cas,omitempty"`
	HostCertPrincipals []string  `json:"host_cert_principals,omitempty"`
}

// issueDirectCert handles POST /api/v1/direct-certs. Bearer-only so browsers
// with ambient cookies can never mint SSH certificates.
func (s *Server) issueDirectCert(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.bearer {
		writeError(w, r, http.StatusForbidden, "BEARER_REQUIRED", "direct certificate issuance requires a CLI token")
		return
	}
	if s.Direct == nil {
		writeError(w, r, http.StatusServiceUnavailable, "DIRECT_DISABLED", "direct certificate issuance is not enabled on this server")
		return
	}
	var body directCertBody
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid body")
		return
	}
	pubKey, err := sessions.ParseClientKey(body.PublicKey)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid public key (ed25519/ecdsa only)")
		return
	}
	fp := sshgateway.Fingerprint(pubKey)
	now := time.Now()
	if !s.Direct.checkKeyUnused(fp, now) {
		s.Audit.Record(audit.Event{
			Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
			Action: "direct.cert_sign", Result: "denied", Reason: "key_reused",
			Extra: map[string]any{"mode": body.Mode, "fingerprint": fp},
		})
		writeError(w, r, http.StatusBadRequest, "KEY_REUSED", "public key already used; generate a new key per certificate")
		return
	}

	snap := s.Store.Current()
	var (
		caReq       ca.Request
		targetAudit string
		ttl         time.Duration
		resp        directCertResponse
	)

	switch body.Mode {
	case "host":
		if len(body.Principals) > 0 || !authz.ValidID(body.HostID) || !authz.ValidLogin(body.LoginUser) {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "host mode requires valid host_id and login_user")
			return
		}
		ttl = s.Direct.defaultHostTTL
		if body.TTL != "" {
			reqTTL, err := time.ParseDuration(body.TTL)
			if err != nil || reqTTL < 30*time.Second || reqTTL > 24*time.Hour {
				writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "ttl must be a valid duration between 30s and 24h")
				return
			}
			ttl = min(reqTTL, s.Direct.maxHostTTL)
		}
		d, host := snap.CheckDirectHost(rc.subject, body.HostID, body.LoginUser)
		if !d.Allowed {
			s.Audit.Record(audit.Event{
				Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
				Action: "direct.cert_sign", Result: "denied", Target: body.HostID + "/" + body.LoginUser,
				Revision: d.Revision, Reason: d.Reason,
				Extra: map[string]any{"mode": "host"},
			})
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "not allowed")
			return
		}
		targetAudit = host.ID + "/" + body.LoginUser
		caReq = ca.Request{
			PublicKey:   pubKey,
			Principal:   d.Principal,
			ValidBefore: ttl.String(),
		}
		resp.SSHAddress = host.SSHAddress
		resp.HostCertPrincipals = host.CertPrincipals()
		for _, k := range host.HostKeys() {
			resp.HostKeys = append(resp.HostKeys, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))))
		}

	case "role":
		if body.HostID != "" || body.LoginUser != "" {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "role mode does not accept host_id or login_user")
			return
		}
		if len(body.Principals) > 32 {
			writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "too many principals requested")
			return
		}
		for _, p := range body.Principals {
			if !authz.ValidPrincipal(p) {
				writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid principal")
				return
			}
		}
		dec := snap.DirectCertPolicy(rc.subject, body.Principals)
		if !dec.Allowed {
			s.Audit.Record(audit.Event{
				Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
				Action: "direct.cert_sign", Result: "denied",
				Revision: dec.Revision, Reason: dec.Reason,
				Extra: map[string]any{"mode": "role"},
			})
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "not allowed")
			return
		}
		maxTTL := s.Direct.maxRoleTTL
		if dec.MaxTTL > 0 && dec.MaxTTL < maxTTL {
			maxTTL = dec.MaxTTL
		}
		ttl = min(s.Direct.defaultRoleTTL, maxTTL)
		if body.TTL != "" {
			reqTTL, err := time.ParseDuration(body.TTL)
			if err != nil || reqTTL < time.Minute || reqTTL > 24*time.Hour {
				writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "ttl must be a valid duration between 1m and 24h")
				return
			}
			ttl = min(reqTTL, maxTTL)
		}
		targetAudit = strings.Join(dec.Principals, ",")
		caReq = ca.Request{
			PublicKey:   pubKey,
			Principals:  dec.Principals,
			ValidBefore: ttl.String(),
			Extensions:  dec.Extensions,
		}

	default:
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "mode must be \"host\" or \"role\"")
		return
	}

	srcAddr, err := s.Direct.resolveSourceAddress(r)
	if err != nil {
		s.Audit.Record(audit.Event{
			Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
			Action: "direct.cert_sign", Result: "denied", Target: targetAudit,
			Reason: "invalid_source_address",
			Extra:  map[string]any{"mode": body.Mode},
		})
		writeError(w, r, http.StatusBadRequest, "INVALID_SOURCE_ADDRESS", "could not determine valid source address")
		return
	}
	caReq.SourceAddress = srcAddr

	if !s.Direct.reserveKey(fp, now) {
		s.Audit.Record(audit.Event{
			Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
			Action: "direct.cert_sign", Result: "denied", Target: targetAudit,
			Reason: "key_reused",
			Extra:  map[string]any{"mode": body.Mode, "fingerprint": fp},
		})
		writeError(w, r, http.StatusBadRequest, "KEY_REUSED", "public key already used; generate a new key per certificate")
		return
	}

	certID := newDirectCertID()
	caReq.KeyID = "user:" + rc.subject.UserID + "/direct:" + certID

	cert, err := s.Direct.sign(r.Context(), caReq)
	if err != nil {
		s.Log.Warn("direct cert sign failed", "user_id", rc.subject.UserID, "mode", body.Mode, "err", err)
		s.Audit.Record(audit.Event{
			Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
			Action: "direct.cert_sign", Result: "error", Target: targetAudit,
			Extra: map[string]any{"mode": body.Mode, "cert_id": certID, "fingerprint": fp},
		})
		writeError(w, r, http.StatusBadGateway, "CA_SIGN_FAILED", "certificate signing failed")
		return
	}

	// Re-check policy right after signing to close race windows where a user
	// was disabled or stripped of access while step-ca was signing.
	postSnap := s.Store.Current()
	if postSnap.IsDisabled(rc.subject) {
		s.Audit.Record(audit.Event{
			Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
			Action: "direct.cert_sign", Result: "denied", Target: targetAudit,
			Revision: postSnap.Revision, Reason: "user_disabled",
			Extra: map[string]any{"mode": body.Mode, "cert_id": certID},
		})
		writeError(w, r, http.StatusForbidden, "USER_DISABLED", "user is disabled")
		return
	}
	if body.Mode == "host" {
		if postDec, _ := postSnap.CheckDirectHost(rc.subject, body.HostID, body.LoginUser); !postDec.Allowed {
			s.Audit.Record(audit.Event{
				Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
				Action: "direct.cert_sign", Result: "denied", Target: targetAudit,
				Revision: postDec.Revision, Reason: postDec.Reason,
				Extra: map[string]any{"mode": "host", "cert_id": certID},
			})
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access revoked during signing")
			return
		}
	} else {
		if postDec := postSnap.DirectCertPolicy(rc.subject, cert.ValidPrincipals); !postDec.Allowed {
			s.Audit.Record(audit.Event{
				Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
				Action: "direct.cert_sign", Result: "denied", Target: targetAudit,
				Revision: postDec.Revision, Reason: postDec.Reason,
				Extra: map[string]any{"mode": "role", "cert_id": certID},
			})
			writeError(w, r, http.StatusForbidden, "FORBIDDEN", "access revoked during signing")
			return
		}
	}

	validAfter := time.Unix(int64(cert.ValidAfter), 0).UTC()
	validBefore := time.Unix(int64(cert.ValidBefore), 0).UTC()
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "direct.cert_sign", Result: "ok", Target: targetAudit,
		Revision: postSnap.Revision,
		Extra: map[string]any{
			"mode":           body.Mode,
			"cert_id":        certID,
			"serial":         fmt.Sprint(cert.Serial),
			"key_id":         cert.KeyId,
			"principals":     cert.ValidPrincipals,
			"valid_after":    validAfter,
			"valid_before":   validBefore,
			"fingerprint":    fp,
			"source_address": srcAddr,
		},
	})

	resp.CertID = certID
	resp.Mode = body.Mode
	resp.Certificate = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
	resp.KeyID = cert.KeyId
	resp.Serial = fmt.Sprint(cert.Serial)
	resp.Principals = cert.ValidPrincipals
	resp.ValidAfter = validAfter
	resp.ValidBefore = validBefore
	resp.SourceAddress = srcAddr
	resp.HostCAs = postSnap.HostCAPublicKeys()
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) hostCAs(w http.ResponseWriter, _ *http.Request, _ *reqCtx) {
	keys := s.Store.Current().HostCAPublicKeys()
	if keys == nil {
		keys = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"host_ca_public_keys": keys})
}

func (s *Server) adminListCertRoles(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	roles := s.Store.Current().Document().CertRoles
	if roles == nil {
		roles = []authz.CertRole{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (s *Server) adminUpsertCertRole(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	roleID := r.PathValue("role_id")
	if !authz.ValidID(roleID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid cert_role id")
		return
	}
	var role authz.CertRole
	d := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&role); err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid cert_role payload")
		return
	}
	if role.ID != "" && role.ID != roleID {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "cert_role id in body does not match path")
		return
	}
	role.ID = roleID
	snap, err := s.Store.UpsertCertRole(role)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.cert_role_upsert", Result: "ok", Target: roleID, Revision: snap.Revision,
		Extra: map[string]any{"principals": role.Principals, "max_ttl": role.MaxTTL},
	})
	writeJSON(w, http.StatusOK, map[string]any{"cert_role": role, "policy_revision": snap.Revision})
}

func (s *Server) adminDeleteCertRole(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !rc.subject.IsAdmin {
		writeError(w, r, http.StatusForbidden, "FORBIDDEN", "admin only")
		return
	}
	roleID := r.PathValue("role_id")
	if !authz.ValidID(roleID) {
		writeError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid cert_role id")
		return
	}
	snap, deleted, err := s.Store.DeleteCertRole(roleID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete cert_role")
		return
	}
	if !deleted {
		writeError(w, r, http.StatusNotFound, "NOT_FOUND", "cert_role not found")
		return
	}
	s.Audit.Record(audit.Event{
		Actor: "user:" + rc.subject.UserID, User: rc.subject.Name,
		Action: "admin.cert_role_delete", Result: "ok", Target: roleID, Revision: snap.Revision,
	})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": roleID, "policy_revision": snap.Revision})
}

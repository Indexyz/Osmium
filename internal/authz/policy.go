// Package authz holds the trusted inventory (hosts, their Agent identities and
// pinned SSH host keys) and the access grants, and answers the single question
// "may this user open login L on host H right now". Browser input never feeds
// into a decision other than as the (host_id, login_user) being asked about.
package authz

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"sort"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	idRe    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	loginRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,63}$`)
)

// ValidLogin reports whether s is an acceptable Linux login name.
func ValidLogin(s string) bool { return loginRe.MatchString(s) }

// ValidID reports whether s is an acceptable opaque identifier.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Subject is the trusted identity of a Web user, taken from the login session.
type Subject struct {
	UserID  string
	Issuer  string
	Sub     string
	Groups  []string
	IsAdmin bool
}

// SubjectSelector matches users. Exactly one form must be set.
type SubjectSelector struct {
	UserID  string `json:"user_id,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
	Group   string `json:"group,omitempty"`
}

func (s SubjectSelector) validate() error {
	n := 0
	if s.UserID != "" {
		n++
	}
	if s.Issuer != "" || s.Subject != "" {
		if s.Issuer == "" || s.Subject == "" {
			return errors.New("issuer and subject must be set together")
		}
		n++
	}
	if s.Group != "" {
		n++
	}
	if n != 1 {
		return errors.New("exactly one of user_id, issuer+subject or group required")
	}
	return nil
}

func (s SubjectSelector) matches(u Subject) bool {
	switch {
	case s.UserID != "":
		return s.UserID == u.UserID
	case s.Issuer != "":
		return s.Issuer == u.Issuer && s.Subject == u.Sub
	case s.Group != "":
		return slices.Contains(u.Groups, s.Group)
	}
	return false
}

// AgentBinding is the machine credential bound to a host.
type AgentBinding struct {
	ID           string `json:"id"`
	ClientCertCN string `json:"client_cert_cn"`
}

// Host is a trusted inventory entry. PolicyLabels are maintained by the
// operator; Agent-reported labels never land here.
type Host struct {
	ID                string            `json:"id"`
	DisplayName       string            `json:"display_name"`
	PolicyLabels      map[string]string `json:"policy_labels"`
	AllowedLoginUsers []string          `json:"allowed_login_users"`
	SSHHostKeys       []string          `json:"ssh_host_keys"`
	Disabled          bool              `json:"disabled"`
	Agent             AgentBinding      `json:"agent"`

	hostKeys []ssh.PublicKey
}

// HostKeys returns the pinned SSH host keys.
func (h *Host) HostKeys() []ssh.PublicKey { return h.hostKeys }

// HostSelector matches hosts by ID list and/or policy labels (AND).
type HostSelector struct {
	IDs    []string          `json:"ids,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

func (s HostSelector) matches(h *Host) bool {
	if len(s.IDs) > 0 && !slices.Contains(s.IDs, h.ID) {
		return false
	}
	for k, v := range s.Labels {
		if h.PolicyLabels[k] != v {
			return false
		}
	}
	return true
}

// Grant allows the matched subjects to use the listed logins on matched hosts.
type Grant struct {
	ID       string            `json:"id"`
	Subjects []SubjectSelector `json:"subjects"`
	Hosts    HostSelector      `json:"hosts"`
	Logins   []string          `json:"logins"`
}

// Document is the on-disk policy file.
type Document struct {
	Scope  string            `json:"scope"`
	Admins []SubjectSelector `json:"admins"`
	Hosts  []*Host           `json:"hosts"`
	Grants []Grant           `json:"grants"`
}

// Snapshot is an immutable, validated policy revision.
type Snapshot struct {
	Revision uint64
	Scope    string
	admins   []SubjectSelector
	hosts    map[string]*Host
	byCN     map[string]*Host
	grants   []Grant
}

// Parse validates a policy document.
func Parse(r io.Reader) (*Snapshot, error) {
	var doc Document
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if doc.Scope == "" {
		doc.Scope = "default"
	}
	if !idRe.MatchString(doc.Scope) || bytes.ContainsAny([]byte(doc.Scope), ":") {
		return nil, errors.New("policy: invalid scope")
	}
	s := &Snapshot{Scope: doc.Scope, admins: doc.Admins, hosts: map[string]*Host{}, byCN: map[string]*Host{}, grants: doc.Grants}
	for i, a := range doc.Admins {
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("policy: admins[%d]: %w", i, err)
		}
	}
	agentIDs := map[string]bool{}
	for _, h := range doc.Hosts {
		if !idRe.MatchString(h.ID) {
			return nil, fmt.Errorf("policy: invalid host id %q", h.ID)
		}
		if s.hosts[h.ID] != nil {
			return nil, fmt.Errorf("policy: duplicate host %q", h.ID)
		}
		if h.DisplayName == "" {
			h.DisplayName = h.ID
		}
		if h.PolicyLabels == nil {
			h.PolicyLabels = map[string]string{}
		}
		if len(h.PolicyLabels) > 64 {
			return nil, fmt.Errorf("policy: host %q has too many labels", h.ID)
		}
		for k, v := range h.PolicyLabels {
			if !labelRe.MatchString(k) || len(v) > 256 {
				return nil, fmt.Errorf("policy: host %q has invalid label %q", h.ID, k)
			}
		}
		for _, l := range h.AllowedLoginUsers {
			if !loginRe.MatchString(l) {
				return nil, fmt.Errorf("policy: host %q has invalid login %q", h.ID, l)
			}
		}
		if len(h.SSHHostKeys) == 0 {
			return nil, fmt.Errorf("policy: host %q has no pinned ssh_host_keys", h.ID)
		}
		for _, line := range h.SSHHostKeys {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				return nil, fmt.Errorf("policy: host %q: bad ssh host key: %w", h.ID, err)
			}
			if _, isCert := k.(*ssh.Certificate); isCert {
				return nil, fmt.Errorf("policy: host %q: pin plain host keys, not certificates", h.ID)
			}
			h.hostKeys = append(h.hostKeys, k)
		}
		if !idRe.MatchString(h.Agent.ID) || h.Agent.ClientCertCN == "" {
			return nil, fmt.Errorf("policy: host %q needs agent.id and agent.client_cert_cn", h.ID)
		}
		if agentIDs[h.Agent.ID] || s.byCN[h.Agent.ClientCertCN] != nil {
			return nil, fmt.Errorf("policy: agent identity of host %q is not unique", h.ID)
		}
		agentIDs[h.Agent.ID] = true
		s.hosts[h.ID] = h
		s.byCN[h.Agent.ClientCertCN] = h
	}
	for i, g := range doc.Grants {
		if len(g.Subjects) == 0 || len(g.Logins) == 0 {
			return nil, fmt.Errorf("policy: grants[%d] needs subjects and logins", i)
		}
		if len(g.Hosts.IDs) == 0 && len(g.Hosts.Labels) == 0 {
			return nil, fmt.Errorf("policy: grants[%d] needs a host selector (ids or labels)", i)
		}
		for _, sub := range g.Subjects {
			if err := sub.validate(); err != nil {
				return nil, fmt.Errorf("policy: grants[%d]: %w", i, err)
			}
		}
		for _, l := range g.Logins {
			if !loginRe.MatchString(l) {
				return nil, fmt.Errorf("policy: grants[%d] invalid login %q", i, l)
			}
		}
	}
	return s, nil
}

// IsAdmin reports whether u is an administrator.
func (s *Snapshot) IsAdmin(u Subject) bool {
	for _, a := range s.admins {
		if a.matches(u) {
			return true
		}
	}
	return false
}

// Host returns the host by ID.
func (s *Snapshot) Host(id string) (*Host, bool) {
	h, ok := s.hosts[id]
	return h, ok
}

// HostByAgentCN maps a verified Agent client certificate CN to its host.
func (s *Snapshot) HostByAgentCN(cn string) (*Host, bool) {
	h, ok := s.byCN[cn]
	return h, ok
}

// AllowedLogins returns the logins u may use on h, sorted.
func (s *Snapshot) AllowedLogins(u Subject, h *Host) []string {
	if h.Disabled {
		return nil
	}
	set := map[string]bool{}
	for _, g := range s.grants {
		if !g.Hosts.matches(h) || !slices.ContainsFunc(g.Subjects, func(sel SubjectSelector) bool { return sel.matches(u) }) {
			continue
		}
		for _, l := range g.Logins {
			if slices.Contains(h.AllowedLoginUsers, l) {
				set[l] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Decision is the result of an access check.
type Decision struct {
	Allowed   bool
	Reason    string
	Revision  uint64
	Principal string
}

// Check decides whether u may open login on hostID.
func (s *Snapshot) Check(u Subject, hostID, login string) Decision {
	d := Decision{Revision: s.Revision}
	h, ok := s.hosts[hostID]
	switch {
	case !ok:
		d.Reason = "unknown_host"
	case h.Disabled:
		d.Reason = "host_disabled"
	case !loginRe.MatchString(login):
		d.Reason = "invalid_login"
	case !slices.Contains(s.AllowedLogins(u, h), login):
		d.Reason = "not_granted"
	default:
		d.Allowed = true
		d.Principal = Principal(s.Scope, h.ID, login)
	}
	return d
}

// VisibleHosts returns hosts on which u has at least one login, sorted by ID.
func (s *Snapshot) VisibleHosts(u Subject) []*Host {
	var out []*Host
	for _, h := range s.hosts {
		if len(s.AllowedLogins(u, h)) > 0 {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Principal is the canonical target principal for (scope, host, login). All
// parts are validated identifiers without ':' so the result is unambiguous.
func Principal(scope, hostID, login string) string {
	return "tenant:" + scope + ":host:" + hostID + ":login:" + login
}

// Store holds the current snapshot and notifies listeners on change.
type Store struct {
	mu        sync.RWMutex
	cur       *Snapshot
	rev       uint64
	listeners []func(*Snapshot)
}

// NewStore creates a store with an initial snapshot.
func NewStore(s *Snapshot) *Store {
	st := &Store{}
	st.Replace(s)
	return st
}

// Current returns the current snapshot.
func (st *Store) Current() *Snapshot {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cur
}

// Replace installs a new snapshot with the next revision and notifies.
func (st *Store) Replace(s *Snapshot) {
	st.mu.Lock()
	st.rev++
	s.Revision = st.rev
	st.cur = s
	ls := slices.Clone(st.listeners)
	st.mu.Unlock()
	for _, l := range ls {
		l(s)
	}
}

// OnChange registers a listener invoked after each Replace.
func (st *Store) OnChange(f func(*Snapshot)) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

// LoadFile parses a policy file.
func LoadFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

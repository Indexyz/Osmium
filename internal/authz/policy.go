// Package authz holds the trusted inventory (hosts, their Agent identities,
// pinned SSH host keys and optional SSH Host CAs) and the access grants, and
// answers "may this user open login L on host H right now". Browser input never
// feeds into a decision other than as the (host_id, login_user) being asked about.
//
// Snapshots pre-build sorted host slices, per-grant ID sets, and inverted label
// indexes so cursor-paginated queries over 50,000+ hosts run in microseconds.
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
	"strings"
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
	// Name is the IdP display name, for audit and UI only; never used to
	// authorize.
	Name string
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
	ID                 string            `json:"id"`
	DisplayName        string            `json:"display_name"`
	PolicyLabels       map[string]string `json:"policy_labels"`
	AllowedLoginUsers  []string          `json:"allowed_login_users"`
	SSHHostKeys        []string          `json:"ssh_host_keys,omitempty"`
	HostCertPrincipals []string          `json:"host_cert_principals,omitempty"`
	Disabled           bool              `json:"disabled"`
	Agent              AgentBinding      `json:"agent"`

	hostKeys    []ssh.PublicKey
	allowedSet  map[string]struct{}
	lowerID     string
	lowerName   string
}

// HostKeys returns the pinned SSH plain host keys.
func (h *Host) HostKeys() []ssh.PublicKey { return h.hostKeys }

// CertPrincipals returns the acceptable SSH Host Certificate principals for h.
// Defaults to [h.ID] when HostCertPrincipals is unset.
func (h *Host) CertPrincipals() []string {
	if len(h.HostCertPrincipals) > 0 {
		return h.HostCertPrincipals
	}
	return []string{h.ID}
}

func cloneHost(src *Host) *Host {
	cp := *src
	cp.PolicyLabels = make(map[string]string, len(src.PolicyLabels))
	for k, v := range src.PolicyLabels {
		cp.PolicyLabels[k] = v
	}
	cp.AllowedLoginUsers = slices.Clone(src.AllowedLoginUsers)
	cp.SSHHostKeys = slices.Clone(src.SSHHostKeys)
	cp.HostCertPrincipals = slices.Clone(src.HostCertPrincipals)
	cp.hostKeys = nil
	cp.allowedSet = nil
	return &cp
}

// HostSelector matches hosts by ID list and/or policy labels (AND).
type HostSelector struct {
	IDs    []string          `json:"ids,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`

	idSet map[string]struct{}
}

func (s HostSelector) matches(h *Host) bool {
	if len(s.idSet) > 0 {
		if _, ok := s.idSet[h.ID]; !ok {
			return false
		}
	} else if len(s.IDs) > 0 && !slices.Contains(s.IDs, h.ID) {
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

func cloneGrant(g Grant) Grant {
	cp := Grant{
		ID:       g.ID,
		Subjects: slices.Clone(g.Subjects),
		Hosts: HostSelector{
			IDs:    slices.Clone(g.Hosts.IDs),
			Labels: make(map[string]string, len(g.Hosts.Labels)),
		},
		Logins: slices.Clone(g.Logins),
	}
	for k, v := range g.Hosts.Labels {
		cp.Hosts.Labels[k] = v
	}
	return cp
}

// Document is the on-disk / persisted policy document.
type Document struct {
	Scope            string            `json:"scope"`
	Admins           []SubjectSelector `json:"admins"`
	DisabledUsers    []SubjectSelector `json:"disabled_users,omitempty"`
	HostCAPublicKeys []string          `json:"host_ca_public_keys,omitempty"`
	Hosts            []*Host           `json:"hosts"`
	Grants           []Grant           `json:"grants"`
}

// Snapshot is an immutable, validated and indexed policy revision.
type Snapshot struct {
	Revision         uint64
	Scope            string
	admins           []SubjectSelector
	disabled         []SubjectSelector
	hostCAPublicKeys []string
	hostCAs          []ssh.PublicKey
	hosts            map[string]*Host
	byCN             map[string]*Host
	byAgentID        map[string]*Host
	sortedHosts      []*Host
	labelIndex       map[string]map[string][]*Host
	grants           []Grant
}

// HostCAs returns the parsed trusted SSH Host CA public keys.
func (s *Snapshot) HostCAs() []ssh.PublicKey { return s.hostCAs }

// HostCAPublicKeys returns the authorized_keys lines of the trusted Host CAs.
func (s *Snapshot) HostCAPublicKeys() []string { return slices.Clone(s.hostCAPublicKeys) }

// HostCount returns total hosts in the inventory.
func (s *Snapshot) HostCount() int { return len(s.sortedHosts) }

// Document exports an immutable deep copy of the snapshot as a Document.
func (s *Snapshot) Document() Document {
	hosts := make([]*Host, 0, len(s.sortedHosts))
	for _, h := range s.sortedHosts {
		hosts = append(hosts, cloneHost(h))
	}
	grants := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		grants = append(grants, cloneGrant(g))
	}
	return Document{
		Scope:            s.Scope,
		Admins:           slices.Clone(s.admins),
		DisabledUsers:    slices.Clone(s.disabled),
		HostCAPublicKeys: slices.Clone(s.hostCAPublicKeys),
		Hosts:            hosts,
		Grants:           grants,
	}
}

// Build validates and compiles an in-memory Document into an indexed Snapshot.
func Build(doc Document) (*Snapshot, error) {
	if doc.Scope == "" {
		doc.Scope = "default"
	}
	if !idRe.MatchString(doc.Scope) || bytes.ContainsAny([]byte(doc.Scope), ":") {
		return nil, errors.New("policy: invalid scope")
	}
	s := &Snapshot{
		Scope:            doc.Scope,
		admins:           slices.Clone(doc.Admins),
		disabled:         slices.Clone(doc.DisabledUsers),
		hostCAPublicKeys: slices.Clone(doc.HostCAPublicKeys),
		hosts:            make(map[string]*Host, len(doc.Hosts)),
		byCN:             make(map[string]*Host, len(doc.Hosts)),
		byAgentID:        make(map[string]*Host, len(doc.Hosts)),
		sortedHosts:      make([]*Host, 0, len(doc.Hosts)),
		labelIndex:       make(map[string]map[string][]*Host),
		grants:           make([]Grant, 0, len(doc.Grants)),
	}
	for i, a := range s.admins {
		if err := a.validate(); err != nil {
			return nil, fmt.Errorf("policy: admins[%d]: %w", i, err)
		}
	}
	for i, d := range s.disabled {
		if err := d.validate(); err != nil {
			return nil, fmt.Errorf("policy: disabled_users[%d]: %w", i, err)
		}
	}
	for i, line := range s.hostCAPublicKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("policy: host_ca_public_keys[%d]: %w", i, err)
		}
		if _, isCert := k.(*ssh.Certificate); isCert {
			return nil, fmt.Errorf("policy: host_ca_public_keys[%d]: must be a plain CA public key, not a certificate", i)
		}
		s.hostCAs = append(s.hostCAs, k)
	}

	for _, rawH := range doc.Hosts {
		if rawH == nil {
			return nil, errors.New("policy: nil host entry")
		}
		h := cloneHost(rawH)
		if err := validateAndCompileHost(h, len(s.hostCAs) > 0); err != nil {
			return nil, err
		}
		if s.hosts[h.ID] != nil {
			return nil, fmt.Errorf("policy: duplicate host %q", h.ID)
		}
		if s.byAgentID[h.Agent.ID] != nil || s.byCN[h.Agent.ClientCertCN] != nil {
			return nil, fmt.Errorf("policy: agent identity of host %q is not unique", h.ID)
		}
		s.hosts[h.ID] = h
		s.byAgentID[h.Agent.ID] = h
		s.byCN[h.Agent.ClientCertCN] = h
		s.sortedHosts = append(s.sortedHosts, h)
	}
	sort.Slice(s.sortedHosts, func(i, j int) bool { return s.sortedHosts[i].ID < s.sortedHosts[j].ID })

	// Build inverted label index in sorted host-ID order for fast label queries.
	for _, h := range s.sortedHosts {
		for k, v := range h.PolicyLabels {
			byVal := s.labelIndex[k]
			if byVal == nil {
				byVal = make(map[string][]*Host)
				s.labelIndex[k] = byVal
			}
			byVal[v] = append(byVal[v], h)
		}
	}

	for i, rawG := range doc.Grants {
		g := cloneGrant(rawG)
		if err := validateAndCompileGrant(&g, i); err != nil {
			return nil, err
		}
		s.grants = append(s.grants, g)
	}
	return s, nil
}

func validateAndCompileHost(h *Host, hasHostCA bool) error {
	if !idRe.MatchString(h.ID) {
		return fmt.Errorf("policy: invalid host id %q", h.ID)
	}
	if h.DisplayName == "" {
		h.DisplayName = h.ID
	}
	if h.PolicyLabels == nil {
		h.PolicyLabels = map[string]string{}
	}
	if len(h.PolicyLabels) > 64 {
		return fmt.Errorf("policy: host %q has too many labels", h.ID)
	}
	for k, v := range h.PolicyLabels {
		if !labelRe.MatchString(k) || len(v) > 256 {
			return fmt.Errorf("policy: host %q has invalid label %q", h.ID, k)
		}
	}
	h.allowedSet = make(map[string]struct{}, len(h.AllowedLoginUsers))
	for _, l := range h.AllowedLoginUsers {
		if !loginRe.MatchString(l) {
			return fmt.Errorf("policy: host %q has invalid login %q", h.ID, l)
		}
		h.allowedSet[l] = struct{}{}
	}
	for _, p := range h.HostCertPrincipals {
		if !idRe.MatchString(p) {
			return fmt.Errorf("policy: host %q has invalid host_cert_principal %q", h.ID, p)
		}
	}
	if len(h.SSHHostKeys) == 0 && !hasHostCA {
		return fmt.Errorf("policy: host %q has no pinned ssh_host_keys (and no host_ca_public_keys configured)", h.ID)
	}
	h.hostKeys = h.hostKeys[:0]
	for _, line := range h.SSHHostKeys {
		k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return fmt.Errorf("policy: host %q: bad ssh host key: %w", h.ID, err)
		}
		if _, isCert := k.(*ssh.Certificate); isCert {
			return fmt.Errorf("policy: host %q: pin plain host keys, not certificates", h.ID)
		}
		h.hostKeys = append(h.hostKeys, k)
	}
	if !idRe.MatchString(h.Agent.ID) || h.Agent.ClientCertCN == "" {
		return fmt.Errorf("policy: host %q needs agent.id and agent.client_cert_cn", h.ID)
	}
	h.lowerID = strings.ToLower(h.ID)
	h.lowerName = strings.ToLower(h.DisplayName)
	return nil
}

func validateAndCompileGrant(g *Grant, idx int) error {
	if len(g.Subjects) == 0 || len(g.Logins) == 0 {
		return fmt.Errorf("policy: grants[%d] needs subjects and logins", idx)
	}
	if len(g.Hosts.IDs) == 0 && len(g.Hosts.Labels) == 0 {
		return fmt.Errorf("policy: grants[%d] needs a host selector (ids or labels)", idx)
	}
	for _, sub := range g.Subjects {
		if err := sub.validate(); err != nil {
			return fmt.Errorf("policy: grants[%d]: %w", idx, err)
		}
	}
	for _, l := range g.Logins {
		if !loginRe.MatchString(l) {
			return fmt.Errorf("policy: grants[%d] invalid login %q", idx, l)
		}
	}
	if len(g.Hosts.IDs) > 0 {
		g.Hosts.idSet = make(map[string]struct{}, len(g.Hosts.IDs))
		for _, id := range g.Hosts.IDs {
			g.Hosts.idSet[id] = struct{}{}
		}
	}
	return nil
}

// Parse validates a JSON policy document.
func Parse(r io.Reader) (*Snapshot, error) {
	var doc Document
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Build(doc)
}

// IsDisabled reports whether u is explicitly disabled by policy.
func (s *Snapshot) IsDisabled(u Subject) bool {
	for _, d := range s.disabled {
		if d.matches(u) {
			return true
		}
	}
	return false
}

// IsAdmin reports whether u is an active administrator. Disabled users are
// never treated as administrators even if matched by admins.
func (s *Snapshot) IsAdmin(u Subject) bool {
	if s.IsDisabled(u) {
		return false
	}
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

// matchingGrants returns only the grants whose subject selector matches u.
func (s *Snapshot) matchingGrants(u Subject) []Grant {
	var out []Grant
	for _, g := range s.grants {
		for _, sel := range g.Subjects {
			if sel.matches(u) {
				out = append(out, g)
				break
			}
		}
	}
	return out
}

func allowedLoginsFromGrants(grants []Grant, h *Host) []string {
	if h.Disabled || len(grants) == 0 || len(h.allowedSet) == 0 {
		return nil
	}
	var out []string
	var set map[string]struct{}
	for _, g := range grants {
		if !g.Hosts.matches(h) {
			continue
		}
		for _, l := range g.Logins {
			if _, ok := h.allowedSet[l]; !ok {
				continue
			}
			if set == nil {
				set = make(map[string]struct{}, len(g.Logins))
			}
			if _, dup := set[l]; !dup {
				set[l] = struct{}{}
				out = append(out, l)
			}
		}
	}
	if len(out) > 1 {
		sort.Strings(out)
	}
	return out
}

// AllowedLogins returns the logins u may use on h, sorted.
func (s *Snapshot) AllowedLogins(u Subject, h *Host) []string {
	if h.Disabled || s.IsDisabled(u) {
		return nil
	}
	return allowedLoginsFromGrants(s.matchingGrants(u), h)
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
	if s.IsDisabled(u) {
		d.Reason = "user_disabled"
		return d
	}
	h, ok := s.hosts[hostID]
	switch {
	case !ok:
		d.Reason = "unknown_host"
	case h.Disabled:
		d.Reason = "host_disabled"
	case !loginRe.MatchString(login):
		d.Reason = "invalid_login"
	case !s.hasLoginGrant(u, h, login):
		d.Reason = "not_granted"
	default:
		d.Allowed = true
		d.Principal = Principal(s.Scope, h.ID, login)
	}
	return d
}

func (s *Snapshot) hasLoginGrant(u Subject, h *Host, login string) bool {
	if _, ok := h.allowedSet[login]; !ok {
		return false
	}
	for _, g := range s.grants {
		if !slices.Contains(g.Logins, login) {
			continue
		}
		if !slices.ContainsFunc(g.Subjects, func(sel SubjectSelector) bool { return sel.matches(u) }) {
			continue
		}
		if g.Hosts.matches(h) {
			return true
		}
	}
	return false
}

// VisibleHosts returns hosts on which u has at least one login, sorted by ID.
func (s *Snapshot) VisibleHosts(u Subject) []*Host {
	if s.IsDisabled(u) {
		return nil
	}
	grants := s.matchingGrants(u)
	if len(grants) == 0 {
		return nil
	}
	var out []*Host
	for _, h := range s.sortedHosts {
		if len(allowedLoginsFromGrants(grants, h)) > 0 {
			out = append(out, h)
		}
	}
	return out
}

// HostPageQuery filters and paginates visible hosts for a user.
type HostPageQuery struct {
	Labels map[string]string
	Query  string // case-insensitive substring on ID or DisplayName
	Status string // optional: "ready", "offline", "disabled"
	Cursor string // exclusive lower bound on host.ID
	Limit  int    // 1..500 (default 50)
}

// VisibleHostEntry pairs an authorized host with its pre-computed logins and
// status so callers never re-evaluate AllowedLogins or Status twice.
type VisibleHostEntry struct {
	Host          *Host
	Status        string
	AllowedLogins []string
}

// HostPageResult holds one page of authorized hosts.
type HostPageResult struct {
	Items      []VisibleHostEntry
	NextCursor string
	Total      int
}

// candidatesForFilter picks the smallest pre-sorted candidate slice using the
// inverted label index before checking authorization.
func (s *Snapshot) candidatesForFilter(labels map[string]string) []*Host {
	if len(labels) == 0 {
		return s.sortedHosts
	}
	var best []*Host
	for k, v := range labels {
		list := s.labelIndex[k][v]
		if len(list) == 0 {
			return nil
		}
		if best == nil || len(list) < len(best) {
			best = list
		}
	}
	return best
}

// VisibleHostsPage authorizes, filters and cursor-paginates hosts for u in a
// single pass. Filters never widen visibility beyond authorized grants.
func (s *Snapshot) VisibleHostsPage(u Subject, q HostPageQuery, statusFn func(*Host) string) HostPageResult {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 500 {
		q.Limit = 500
	}
	if s.IsDisabled(u) {
		return HostPageResult{}
	}
	grants := s.matchingGrants(u)
	if len(grants) == 0 {
		return HostPageResult{}
	}
	candidates := s.candidatesForFilter(q.Labels)
	if len(candidates) == 0 {
		return HostPageResult{}
	}
	needle := strings.ToLower(strings.TrimSpace(q.Query))
	statusFilter := strings.TrimSpace(q.Status)

	var res HostPageResult
	hasMore := false
	for _, h := range candidates {
		// Check remaining label filters (when >1 label specified).
		if len(q.Labels) > 1 {
			ok := true
			for k, v := range q.Labels {
				if h.PolicyLabels[k] != v {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		if needle != "" && !strings.Contains(h.lowerID, needle) && !strings.Contains(h.lowerName, needle) {
			continue
		}
		logins := allowedLoginsFromGrants(grants, h)
		if len(logins) == 0 {
			continue
		}
		st := ""
		if statusFn != nil {
			st = statusFn(h)
		}
		if statusFilter != "" && st != statusFilter {
			continue
		}
		res.Total++
		if q.Cursor != "" && h.ID <= q.Cursor {
			continue
		}
		if len(res.Items) < q.Limit {
			res.Items = append(res.Items, VisibleHostEntry{
				Host:          h,
				Status:        st,
				AllowedLogins: logins,
			})
		} else {
			hasMore = true
		}
	}
	if hasMore && len(res.Items) > 0 {
		res.NextCursor = res.Items[len(res.Items)-1].Host.ID
	}
	return res
}

// Principal is the canonical target principal for (scope, host, login). All
// parts are validated identifiers without ':' so the result is unambiguous.
func Principal(scope, hostID, login string) string {
	return "tenant:" + scope + ":host:" + hostID + ":login:" + login
}

// Persister optionally persists policy mutations (implemented by internal/storage).
type Persister interface {
	SaveDocument(doc Document) error
	UpsertHost(h *Host) error
	DeleteHost(hostID string) error
	UpsertGrant(g Grant) error
	DeleteGrant(grantID string) error
	SaveHostCAs(keys []string) error
	SaveDisabledUsers(disabled []SubjectSelector) error
}

// Store holds the current snapshot, persists incremental mutations if a
// Persister is attached, and notifies listeners on change.
type Store struct {
	mu            sync.RWMutex
	cur           *Snapshot
	rev           uint64
	persister     Persister
	listeners     []func(*Snapshot)
	hostListeners []func(snap *Snapshot, agentIDs []string)
}

// NewStore creates a store with an initial snapshot.
func NewStore(s *Snapshot) *Store {
	st := &Store{}
	st.Replace(s)
	return st
}

// SetPersister attaches an optional persistent backing store (e.g. SQLite WAL).
func (st *Store) SetPersister(p Persister) {
	st.mu.Lock()
	st.persister = p
	st.mu.Unlock()
}

// Current returns the current snapshot.
func (st *Store) Current() *Snapshot {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cur
}

// Replace installs a new snapshot with the next revision and notifies all
// listeners. If a Persister is attached, it also persists the full document.
func (st *Store) Replace(s *Snapshot) {
	st.mu.Lock()
	st.rev++
	s.Revision = st.rev
	st.cur = s
	p := st.persister
	ls := slices.Clone(st.listeners)
	st.mu.Unlock()
	if p != nil {
		_ = p.SaveDocument(s.Document())
	}
	for _, l := range ls {
		l(s)
	}
}

// OnChange registers a listener invoked after policy changes.
func (st *Store) OnChange(f func(*Snapshot)) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

// OnHostChange registers a fine-grained listener invoked for incremental single
// host updates with only the affected Agent IDs.
func (st *Store) OnHostChange(f func(snap *Snapshot, agentIDs []string)) {
	st.mu.Lock()
	st.hostListeners = append(st.hostListeners, f)
	st.mu.Unlock()
}

// UpsertHost atomically validates, persists and installs an updated or new host
// without requiring a full policy file reload.
func (st *Store) UpsertHost(h *Host) (*Snapshot, error) {
	st.mu.Lock()
	doc := st.cur.Document()
	var affectedAgents []string
	replaced := false
	for i, existing := range doc.Hosts {
		if existing.ID == h.ID {
			affectedAgents = append(affectedAgents, existing.Agent.ID)
			doc.Hosts[i] = cloneHost(h)
			replaced = true
			break
		}
	}
	if !replaced {
		doc.Hosts = append(doc.Hosts, cloneHost(h))
	}
	if !slices.Contains(affectedAgents, h.Agent.ID) {
		affectedAgents = append(affectedAgents, h.Agent.ID)
	}
	snap, err := Build(doc)
	if err != nil {
		st.mu.Unlock()
		return nil, err
	}
	if st.persister != nil {
		if err := st.persister.UpsertHost(snap.hosts[h.ID]); err != nil {
			st.mu.Unlock()
			return nil, err
		}
	}
	st.rev++
	snap.Revision = st.rev
	st.cur = snap
	ls := slices.Clone(st.listeners)
	hls := slices.Clone(st.hostListeners)
	st.mu.Unlock()

	if len(hls) > 0 {
		for _, hl := range hls {
			hl(snap, affectedAgents)
		}
	}
	for _, l := range ls {
		l(snap)
	}
	return snap, nil
}

// DeleteHost removes a single host and notifies listeners so its Agent and
// active sessions are terminated.
func (st *Store) DeleteHost(hostID string) (*Snapshot, bool, error) {
	st.mu.Lock()
	doc := st.cur.Document()
	idx := -1
	var agentID string
	for i, existing := range doc.Hosts {
		if existing.ID == hostID {
			idx = i
			agentID = existing.Agent.ID
			break
		}
	}
	if idx < 0 {
		st.mu.Unlock()
		return st.cur, false, nil
	}
	doc.Hosts = append(doc.Hosts[:idx], doc.Hosts[idx+1:]...)
	snap, err := Build(doc)
	if err != nil {
		st.mu.Unlock()
		return nil, false, err
	}
	if st.persister != nil {
		if err := st.persister.DeleteHost(hostID); err != nil {
			st.mu.Unlock()
			return nil, false, err
		}
	}
	st.rev++
	snap.Revision = st.rev
	st.cur = snap
	ls := slices.Clone(st.listeners)
	hls := slices.Clone(st.hostListeners)
	st.mu.Unlock()

	for _, hl := range hls {
		hl(snap, []string{agentID})
	}
	for _, l := range ls {
		l(snap)
	}
	return snap, true, nil
}

// UpsertGrant atomically validates, persists and activates a single grant.
func (st *Store) UpsertGrant(g Grant) (*Snapshot, error) {
	if !ValidID(g.ID) {
		return nil, fmt.Errorf("policy: invalid grant id %q", g.ID)
	}
	st.mu.Lock()
	doc := st.cur.Document()
	replaced := false
	for i, existing := range doc.Grants {
		if existing.ID == g.ID {
			doc.Grants[i] = cloneGrant(g)
			replaced = true
			break
		}
	}
	if !replaced {
		doc.Grants = append(doc.Grants, cloneGrant(g))
	}
	snap, err := Build(doc)
	if err != nil {
		st.mu.Unlock()
		return nil, err
	}
	if st.persister != nil {
		if err := st.persister.UpsertGrant(g); err != nil {
			st.mu.Unlock()
			return nil, err
		}
	}
	st.rev++
	snap.Revision = st.rev
	st.cur = snap
	ls := slices.Clone(st.listeners)
	st.mu.Unlock()

	for _, l := range ls {
		l(snap)
	}
	return snap, nil
}

// DeleteGrant removes one grant by ID and notifies listeners so revoked
// sessions are closed immediately.
func (st *Store) DeleteGrant(grantID string) (*Snapshot, bool, error) {
	st.mu.Lock()
	doc := st.cur.Document()
	idx := -1
	for i, existing := range doc.Grants {
		if existing.ID == grantID {
			idx = i
			break
		}
	}
	if idx < 0 {
		st.mu.Unlock()
		return st.cur, false, nil
	}
	doc.Grants = append(doc.Grants[:idx], doc.Grants[idx+1:]...)
	snap, err := Build(doc)
	if err != nil {
		st.mu.Unlock()
		return nil, false, err
	}
	if st.persister != nil {
		if err := st.persister.DeleteGrant(grantID); err != nil {
			st.mu.Unlock()
			return nil, false, err
		}
	}
	st.rev++
	snap.Revision = st.rev
	st.cur = snap
	ls := slices.Clone(st.listeners)
	st.mu.Unlock()

	for _, l := range ls {
		l(snap)
	}
	return snap, true, nil
}

// SetHostCAs updates the trusted SSH Host CA public keys (supporting seamless
// key rotation). Fails closed if removing all CAs leaves any host without
// pinned ssh_host_keys.
func (st *Store) SetHostCAs(keys []string) (*Snapshot, error) {
	st.mu.Lock()
	doc := st.cur.Document()
	doc.HostCAPublicKeys = slices.Clone(keys)
	snap, err := Build(doc)
	if err != nil {
		st.mu.Unlock()
		return nil, err
	}
	if st.persister != nil {
		if err := st.persister.SaveHostCAs(doc.HostCAPublicKeys); err != nil {
			st.mu.Unlock()
			return nil, err
		}
	}
	st.rev++
	snap.Revision = st.rev
	st.cur = snap
	ls := slices.Clone(st.listeners)
	st.mu.Unlock()

	for _, l := range ls {
		l(snap)
	}
	return snap, nil
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

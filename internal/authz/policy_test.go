package authz

import (
	"fmt"
	"strings"
	"testing"
)

const hostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"

func doc(grants string) string {
	return `{"scope":"t1","admins":[{"group":"admins"}],"hosts":[
 {"id":"host-123","policy_labels":{"env":"prod"},"allowed_login_users":["ops","deploy"],"ssh_host_keys":["` + hostKey + `"],"agent":{"id":"agent-123","client_cert_cn":"agent-123"}},
 {"id":"host-456","policy_labels":{"env":"dev"},"allowed_login_users":["ops"],"ssh_host_keys":["` + hostKey + `"],"agent":{"id":"agent-456","client_cert_cn":"agent-456"}}
],"grants":[` + grants + `]}`
}

var alice = Subject{UserID: "u-alice", Issuer: "https://idp", Sub: "alice"}
var bob = Subject{UserID: "u-bob", Issuer: "https://idp", Sub: "bob"}

func mustParse(t *testing.T, s string) *Snapshot {
	t.Helper()
	p, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A01/A02/A03/A04: grants live on the server; adding Bob needs no host change.
func TestDynamicGrant(t *testing.T) {
	st := NewStore(mustParse(t, doc(`{"id":"g1","subjects":[{"issuer":"https://idp","subject":"alice"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}`)))
	if d := st.Current().Check(alice, "host-123", "ops"); !d.Allowed || d.Principal != "tenant:t1:host:host-123:login:ops" {
		t.Fatalf("alice denied: %+v", d)
	}
	if st.Current().Check(bob, "host-123", "ops").Allowed {
		t.Fatal("bob allowed without grant")
	}
	st.Replace(mustParse(t, doc(`{"id":"g1","subjects":[{"issuer":"https://idp","subject":"alice"},{"user_id":"u-bob"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}`)))
	d := st.Current().Check(bob, "host-123", "ops")
	if !d.Allowed || d.Principal != "tenant:t1:host:host-123:login:ops" || d.Revision != 2 {
		t.Fatalf("bob not allowed after grant: %+v", d)
	}
}

// A06/A11/A12 and label policy.
func TestNegativeChecks(t *testing.T) {
	s := mustParse(t, doc(`{"id":"g1","subjects":[{"issuer":"https://idp","subject":"alice"}],"hosts":{"labels":{"env":"prod"}},"logins":["ops","root"]}`))
	if s.Check(alice, "host-456", "ops").Allowed {
		t.Fatal("label selector leaked to dev host")
	}
	if s.Check(alice, "host-123", "root").Allowed {
		t.Fatal("root allowed though not in host allowed_login_users")
	}
	if s.Check(alice, "host-123", "deploy").Allowed {
		t.Fatal("deploy allowed without grant")
	}
	other := alice
	other.Issuer = "https://other-idp"
	if s.Check(other, "host-123", "ops").Allowed {
		t.Fatal("same sub different issuer accepted")
	}
	if s.Check(alice, "host-999", "ops").Allowed || s.Check(alice, "host-123", "ops\nroot").Allowed {
		t.Fatal("unknown host or injected login accepted")
	}
	if got := s.VisibleHosts(alice); len(got) != 1 || got[0].ID != "host-123" {
		t.Fatalf("visible: %v", got)
	}
	if !s.IsAdmin(Subject{Groups: []string{"admins"}}) || s.IsAdmin(alice) {
		t.Fatal("admin selector wrong")
	}
}

func TestParseRejects(t *testing.T) {
	bad := []string{
		strings.Replace(doc(""), `"ssh_host_keys":["`+hostKey+`"],"agent":{"id":"agent-123"`, `"ssh_host_keys":[],"agent":{"id":"agent-123"`, 1),
		strings.Replace(doc(""), `"agent-456","client_cert_cn":"agent-456"`, `"agent-456","client_cert_cn":"agent-123"`, 1),
		strings.Replace(doc(""), `"scope":"t1"`, `"scope":"t1:x"`, 1),
		doc(`{"id":"g","subjects":[{"user_id":"u","group":"g"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}`),
		doc(`{"id":"g","subjects":[{"user_id":"u"}],"hosts":{},"logins":["ops"]}`),
		strings.Replace(doc(""), `"scope"`, `"unknown":1,"scope"`, 1),
		strings.Replace(doc(""), `"admins":`, `"disabled_users":[{"issuer":"only-issuer"}],"admins":`, 1),
	}
	for i, s := range bad {
		if _, err := Parse(strings.NewReader(s)); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestDisabledUsersOverrideGrantsAndAdmins(t *testing.T) {
	raw := `{"scope":"t1",
		"admins":[{"group":"admins"}],
		"disabled_users":[{"user_id":"u-alice"},{"issuer":"https://idp","subject":"bob"},{"group":"suspended"}],
		"hosts":[{"id":"host-123","policy_labels":{"env":"prod"},"allowed_login_users":["ops"],"ssh_host_keys":["` + hostKey + `"],"agent":{"id":"agent-123","client_cert_cn":"agent-123"}}],
		"grants":[{"id":"g1","subjects":[{"group":"ops"},{"group":"admins"}],"hosts":{"ids":["host-123"]},"logins":["ops"]}]
	}`
	s := mustParse(t, raw)

	aliceAdmin := Subject{UserID: "u-alice", Issuer: "https://idp", Sub: "alice", Groups: []string{"ops", "admins"}}
	if !s.IsDisabled(aliceAdmin) {
		t.Fatal("alice should be disabled")
	}
	if s.IsAdmin(aliceAdmin) {
		t.Fatal("disabled user retained admin privilege")
	}
	if d := s.Check(aliceAdmin, "host-123", "ops"); d.Allowed || d.Reason != "user_disabled" {
		t.Fatalf("expected user_disabled, got %+v", d)
	}
	if got := s.VisibleHosts(aliceAdmin); len(got) != 0 {
		t.Fatalf("disabled user saw hosts: %v", got)
	}

	bobOps := Subject{UserID: "u-bob", Issuer: "https://idp", Sub: "bob", Groups: []string{"ops"}}
	if d := s.Check(bobOps, "host-123", "ops"); d.Allowed || d.Reason != "user_disabled" {
		t.Fatalf("bob expected user_disabled, got %+v", d)
	}

	carolSuspended := Subject{UserID: "u-carol", Issuer: "https://idp", Sub: "carol", Groups: []string{"ops", "suspended"}}
	if d := s.Check(carolSuspended, "host-123", "ops"); d.Allowed || d.Reason != "user_disabled" {
		t.Fatalf("suspended group expected user_disabled, got %+v", d)
	}

	dave := Subject{UserID: "u-dave", Issuer: "https://idp", Sub: "dave", Groups: []string{"ops", "admins"}}
	if !s.IsAdmin(dave) || !s.Check(dave, "host-123", "ops").Allowed {
		t.Fatal("unaffected active user denied")
	}
}

func TestIndexedPaginationAndHostCAValidation(t *testing.T) {
	// 1) Build 10,000 hosts using Host CA (no per-host static keys needed).
	const totalHosts = 10000
	hosts := make([]*Host, 0, totalHosts)
	for i := 0; i < totalHosts; i++ {
		env := "dev"
		if i%2 == 0 {
			env = "prod"
		}
		id := fmt.Sprintf("host-%05d", i)
		hosts = append(hosts, &Host{
			ID:                id,
			DisplayName:       "node-" + id,
			PolicyLabels:      map[string]string{"env": env, "shard": fmt.Sprintf("s%d", i%10)},
			AllowedLoginUsers: []string{"ops"},
			Agent:             AgentBinding{ID: "agent-" + id, ClientCertCN: "agent-" + id},
		})
	}
	snap, err := Build(Document{
		Scope:            "scale",
		HostCAPublicKeys: []string{hostKey},
		Hosts:            hosts,
		Grants: []Grant{{
			ID:       "g-prod",
			Subjects: []SubjectSelector{{UserID: "u-alice"}},
			Hosts:    HostSelector{Labels: map[string]string{"env": "prod"}},
			Logins:   []string{"ops"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Filter by shard=s0 & env=prod -> 1000 hosts; walk cursor pages cleanly.
	seen := 0
	cursor := ""
	for {
		p := snap.VisibleHostsPage(alice, HostPageQuery{
			Labels: map[string]string{"shard": "s0"},
			Cursor: cursor,
			Limit:  200,
		}, func(*Host) string { return "ready" })
		if p.Total != 1000 {
			t.Fatalf("total=%d, want 1000", p.Total)
		}
		for _, item := range p.Items {
			if item.Host.PolicyLabels["env"] != "prod" || item.Host.PolicyLabels["shard"] != "s0" {
				t.Fatalf("unexpected host in page: %+v", item.Host)
			}
			seen++
		}
		if p.NextCursor == "" {
			break
		}
		cursor = p.NextCursor
	}
	if seen != 1000 {
		t.Fatalf("walked %d hosts, want 1000", seen)
	}
	// Label filter for unauthorized env=dev must never widen visibility.
	pDev := snap.VisibleHostsPage(alice, HostPageQuery{Labels: map[string]string{"env": "dev"}, Limit: 10}, nil)
	if pDev.Total != 0 || len(pDev.Items) != 0 {
		t.Fatalf("dev label widened visibility: %+v", pDev)
	}
}

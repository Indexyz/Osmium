package authz

import (
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
	}
	for i, s := range bad {
		if _, err := Parse(strings.NewReader(s)); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

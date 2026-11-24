package storage_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/storage"
)

func genPubLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
}

func TestSQLitePolicyPersistenceAndIncrementalCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "osmium.db")
	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	hk := genPubLine(t)
	hostCA := genPubLine(t)
	initial := authz.Document{
		Scope:  "prod",
		Admins: []authz.SubjectSelector{{Group: "admins"}},
		Hosts: []*authz.Host{{
			ID:                "host-1",
			DisplayName:       "web-1",
			PolicyLabels:      map[string]string{"env": "prod"},
			AllowedLoginUsers: []string{"ops"},
			SSHHostKeys:       []string{hk},
			Agent:             authz.AgentBinding{ID: "agent-1", ClientCertCN: "agent-1"},
		}},
		Grants: []authz.Grant{{
			ID:       "g-ops",
			Subjects: []authz.SubjectSelector{{Group: "ops"}},
			Hosts:    authz.HostSelector{Labels: map[string]string{"env": "prod"}},
			Logins:   []string{"ops"},
		}},
	}
	snap, err := authz.Build(initial)
	if err != nil {
		t.Fatal(err)
	}
	store := authz.NewStore(snap)
	store.SetPersister(db)
	if err := db.SaveDocument(snap.Document()); err != nil {
		t.Fatal(err)
	}

	// Incremental: add Host CA, then add a Host CA-only host (no static ssh_host_keys),
	// add a second grant, and update host-1.
	if _, err := store.SetHostCAs([]string{hostCA}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertHost(&authz.Host{
		ID:                 "host-2",
		DisplayName:        "edge-2",
		PolicyLabels:       map[string]string{"env": "edge"},
		AllowedLoginUsers:  []string{"ops"},
		HostCertPrincipals: []string{"host-2", "edge-2.internal"},
		Agent:              authz.AgentBinding{ID: "agent-2", ClientCertCN: "agent-2"},
	}); err != nil {
		t.Fatalf("Host CA-only host failed: %v", err)
	}
	if _, err := store.UpsertGrant(authz.Grant{
		ID:       "g-edge",
		Subjects: []authz.SubjectSelector{{UserID: "u-alice"}},
		Hosts:    authz.HostSelector{IDs: []string{"host-2"}},
		Logins:   []string{"ops"},
	}); err != nil {
		t.Fatal(err)
	}
	// Removing Host CA while host-2 has no static keys must fail closed!
	if _, err := store.SetHostCAs(nil); err == nil {
		t.Fatal("removing all Host CAs succeeded while CA-only host exists")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen DB from disk and verify everything survived restart.
	db2, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	doc, ok, err := db2.LoadDocument()
	if err != nil || !ok {
		t.Fatalf("reload failed: ok=%v err=%v", ok, err)
	}
	snap2, err := authz.Build(doc)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.HostCount() != 2 || len(snap2.HostCAs()) != 1 {
		t.Fatalf("hosts=%d cas=%d", snap2.HostCount(), len(snap2.HostCAs()))
	}
	h2, ok := snap2.Host("host-2")
	if !ok || len(h2.CertPrincipals()) != 2 {
		t.Fatalf("host-2: %+v", h2)
	}
	if d := snap2.Check(authz.Subject{UserID: "u-alice"}, "host-2", "ops"); !d.Allowed {
		t.Fatalf("persisted grant check failed: %+v", d)
	}
}

func TestSQLiteAuthPersistenceAndAuditIndexSearch(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")
	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	ws := &authn.WebSession{
		User:      authn.User{ID: "u-alice", Issuer: "dev", Subject: "alice", DisplayName: "Alice", Groups: []string{"ops"}},
		CSRF:      "csrf-secret",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := db.SaveWebSession("hash-web-1", ws); err != nil {
		t.Fatal(err)
	}
	ct := &authn.CLIToken{
		ID:        "ct-1",
		User:      ws.User,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := db.SaveCLIToken("hash-cli-1", ct); err != nil {
		t.Fatal(err)
	}
	used := now.Add(5 * time.Minute)
	if err := db.TouchCLIToken("hash-cli-1", used); err != nil {
		t.Fatal(err)
	}

	gotWS, err := db.LoadWebSessions(now)
	if err != nil || len(gotWS) != 1 || gotWS["hash-web-1"].CSRF != "csrf-secret" {
		t.Fatalf("web sessions: %+v %v", gotWS, err)
	}
	gotCT, err := db.LoadCLITokens(now)
	if err != nil || len(gotCT) != 1 || !gotCT["hash-cli-1"].LastUsedAt.Equal(used) {
		t.Fatalf("cli tokens: %+v %v", gotCT, err)
	}
	if err := db.PruneAuth(now.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if gotWS2, _ := db.LoadWebSessions(now); len(gotWS2) != 0 {
		t.Fatalf("prune did not remove expired web sessions: %+v", gotWS2)
	}

	// Indexed audit batch insert + filtered cursor pagination.
	batch := []audit.Event{
		{ID: "e1", Time: now.Add(1 * time.Second), Actor: "user:u-alice", User: "Alice", Action: "session.create", Result: "ok", Target: "host-1/ops", SessionID: "s1"},
		{ID: "e2", Time: now.Add(2 * time.Second), Actor: "user:u-bob", User: "Bob", Action: "ca.sign", Result: "ok", Target: "host-2/ops", SessionID: "s2"},
		{ID: "e3", Time: now.Add(3 * time.Second), Actor: "user:u-alice", User: "Alice", Action: "ca.sign", Result: "ok", Target: "host-1/ops", SessionID: "s1"},
	}
	if err := db.InsertAuditBatch(batch); err != nil {
		t.Fatal(err)
	}
	p1, handled, err := db.SearchAudit(context.Background(), audit.Query{
		From: now, To: now.Add(time.Minute), User: "alice", Limit: 1,
	})
	if err != nil || !handled || len(p1.Events) != 1 || p1.Events[0].ID != "e1" || p1.Next == "" {
		t.Fatalf("audit page 1: %+v handled=%v err=%v", p1, handled, err)
	}
	p2, _, err := db.SearchAudit(context.Background(), audit.Query{
		From: now, To: now.Add(time.Minute), User: "alice", Limit: 1, Cursor: p1.Next,
	})
	if err != nil || len(p2.Events) != 1 || p2.Events[0].ID != "e3" || p2.Next != "" {
		t.Fatalf("audit page 2: %+v err=%v", p2, err)
	}
	if _, _, err := db.SearchAudit(context.Background(), audit.Query{
		From: now, To: now.Add(time.Minute), Limit: 10, Cursor: "invalid!!!",
	}); !errors.Is(err, audit.ErrBadQuery) {
		t.Fatalf("expected ErrBadQuery for bad cursor, got %v", err)
	}
}

func TestSQLiteDirectHostsAndCertRolesPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "direct.db")
	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	hostCA := genPubLine(t)
	snap, err := authz.Build(authz.Document{
		Scope:            "prod",
		HostCAPublicKeys: []string{hostCA},
		Hosts: []*authz.Host{
			{ID: "direct-1", DisplayName: "db-1", ConnectionMode: authz.ConnModeDirect, SSHAddress: "10.0.1.10:22", AllowedLoginUsers: []string{"ops"}},
			{ID: "direct-2", DisplayName: "db-2", ConnectionMode: authz.ConnModeDirect, SSHAddress: "10.0.1.11:2222", AllowedLoginUsers: []string{"ops"}},
		},
		CertRoles: []authz.CertRole{
			{ID: "r-init", Subjects: []authz.SubjectSelector{{Group: "ops"}}, Principals: []string{"role:ops"}, MaxTTL: "4h"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := authz.NewStore(snap)
	store.SetPersister(db)
	if err := db.SaveDocument(snap.Document()); err != nil {
		t.Fatal(err)
	}
	// Incremental upsert + delete on direct host & cert roles.
	if _, err := store.UpsertHost(&authz.Host{
		ID: "direct-3", DisplayName: "db-3", ConnectionMode: authz.ConnModeDirect, SSHAddress: "10.0.1.12:22", AllowedLoginUsers: []string{"ops"},
	}); err != nil {
		t.Fatalf("third agentless direct host failed (nullable UNIQUE check): %v", err)
	}
	if _, err := store.UpsertCertRole(authz.CertRole{
		ID: "r-sre", Subjects: []authz.SubjectSelector{{Group: "sre"}}, Principals: []string{"role:sre", "team:infra"}, MaxTTL: "2h", Extensions: []string{"permit-pty"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, deleted, err := store.DeleteCertRole("r-init"); err != nil || !deleted {
		t.Fatalf("delete cert role failed: deleted=%v err=%v", deleted, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	doc, ok, err := db2.LoadDocument()
	if err != nil || !ok {
		t.Fatalf("reload failed: ok=%v err=%v", ok, err)
	}
	snap2, err := authz.Build(doc)
	if err != nil {
		t.Fatal(err)
	}
	if snap2.HostCount() != 3 {
		t.Fatalf("hosts=%d, want 3", snap2.HostCount())
	}
	h3, ok := snap2.Host("direct-3")
	if !ok || h3.ConnectionMode != authz.ConnModeDirect || h3.SSHAddress != "10.0.1.12:22" {
		t.Fatalf("direct-3 mismatch: %+v", h3)
	}
	dec := snap2.DirectCertPolicy(authz.Subject{UserID: "u-1", Groups: []string{"sre"}}, nil)
	if !dec.Allowed || len(dec.Principals) != 2 || dec.MaxTTL != 2*time.Hour {
		t.Fatalf("persisted cert_role mismatch: %+v", dec)
	}
	if old := snap2.DirectCertPolicy(authz.Subject{UserID: "u-2", Groups: []string{"ops"}}, nil); old.Allowed {
		t.Fatalf("deleted cert_role survived restart: %+v", old)
	}
}

func TestSQLiteLegacyHostsSchemaMigration(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	rawDB, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	hk := genPubLine(t)
	_, err = rawDB.Exec(`
CREATE TABLE policy_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO policy_meta(key, value) VALUES ('scope', 'legacy'), ('admins', '[]'), ('disabled_users', '[]'), ('host_ca_public_keys', '[]');
CREATE TABLE hosts (
	id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	agent_id TEXT NOT NULL UNIQUE,
	client_cert_cn TEXT NOT NULL UNIQUE,
	disabled INTEGER NOT NULL DEFAULT 0,
	doc_json TEXT NOT NULL
);
CREATE TABLE host_labels (
	host_id TEXT NOT NULL,
	k TEXT NOT NULL,
	v TEXT NOT NULL,
	PRIMARY KEY (host_id, k),
	FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
INSERT INTO hosts(id, display_name, agent_id, client_cert_cn, disabled, doc_json)
VALUES ('old-1', 'old-1', 'ag-1', 'ag-1', 0, '{"id":"old-1","display_name":"old-1","allowed_login_users":["ops"],"ssh_host_keys":["` + hk + `"],"agent":{"id":"ag-1","client_cert_cn":"ag-1"}}');
INSERT INTO host_labels(host_id, k, v) VALUES ('old-1', 'env', 'prod');
`)
	if err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	_ = rawDB.Close()

	// Opening with OpenSQLite must migrate hosts to allow nullable agent_id/client_cert_cn
	// without losing existing rows or labels!
	db, err := storage.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	defer db.Close()
	if err := db.UpsertHost(&authz.Host{
		ID: "direct-new", DisplayName: "direct-new", ConnectionMode: authz.ConnModeDirect,
		SSHAddress: "10.0.0.5:22", AllowedLoginUsers: []string{"ops"}, SSHHostKeys: []string{hk},
	}); err != nil {
		t.Fatalf("upsert agentless host after migration failed: %v", err)
	}
	doc, ok, err := db.LoadDocument()
	if err != nil || !ok || len(doc.Hosts) != 2 {
		t.Fatalf("reloaded doc: ok=%v hosts=%d err=%v", ok, len(doc.Hosts), err)
	}
}

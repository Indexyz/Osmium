package e2e

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
)

// Audit events are persisted to the daily files and searchable by admins
// only; the stored lines carry no secrets (E05/E06).
func TestAuditPersistedAndSearchable(t *testing.T) {
	e := newEnv(t)
	e.startAgent("host-123")
	alice := e.signIn("alice")
	admin := e.signIn("root-admin", "admins")

	v, code := alice.create("host-123")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	tm, err := alice.attach(v, e.web.URL)
	if err != nil {
		t.Fatal(err)
	}
	tm.waitActive()
	tm.send("exit\r")
	tm.waitExit()

	var page audit.Page
	q := url.Values{"session_id": {v.ID}}
	if code := getJSON(t, admin.c, e.web.URL+"/api/v1/admin/audit?"+q.Encode(), &page); code != http.StatusOK {
		t.Fatalf("admin search: %d", code)
	}
	var actions []string
	for _, ev := range page.Events {
		actions = append(actions, ev.Action+"="+ev.Result)
		if ev.ID == "" || ev.SessionID != v.ID {
			t.Fatalf("event %+v", ev)
		}
	}
	want := []string{"session.create=ok", "ca.sign=ok", "session.active=ok", "session.end"}
	got := strings.Join(actions, " ")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Fatalf("missing %q in %s", w, got)
		}
	}

	// By user: display name or internal ID, never another user's events.
	for _, u := range []string{"alice (dev)", authn.UserID("dev", "alice")} {
		q = url.Values{"user": {u}}
		if getJSON(t, admin.c, e.web.URL+"/api/v1/admin/audit?"+q.Encode(), &page); len(page.Events) == 0 {
			t.Fatalf("user=%s: no events", u)
		}
		for _, ev := range page.Events {
			if ev.Actor != "user:"+authn.UserID("dev", "alice") || ev.User != "alice (dev)" {
				t.Fatalf("user=%s returned %+v", u, ev)
			}
		}
	}

	// Filters and pagination through the API.
	q = url.Values{"session_id": {v.ID}, "action": {"ca.sign"}}
	if getJSON(t, admin.c, e.web.URL+"/api/v1/admin/audit?"+q.Encode(), &page); len(page.Events) != 1 {
		t.Fatalf("action filter: %+v", page.Events)
	}
	q = url.Values{"session_id": {v.ID}, "limit": {"1"}}
	if getJSON(t, admin.c, e.web.URL+"/api/v1/admin/audit?"+q.Encode(), &page); len(page.Events) != 1 || page.Next == "" {
		t.Fatalf("limit=1: %+v next=%q", page.Events, page.Next)
	}

	// Not for regular users; bad parameters are rejected.
	if code := getJSON(t, alice.c, e.web.URL+"/api/v1/admin/audit", &page); code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", code)
	}
	for _, bad := range []string{"from=yesterday", "limit=0", "limit=5000", "cursor=%21%21", "from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z"} {
		if code := getJSON(t, admin.c, e.web.URL+"/api/v1/admin/audit?"+bad, &page); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, code)
		}
	}

	// The files on disk hold the same events and no secret material.
	files, _ := filepath.Glob(filepath.Join(e.dir, "audit", "*", "*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no audit files written")
	}
	var all strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	s := all.String()
	if !strings.Contains(s, v.ID) {
		t.Fatal("session not in audit files")
	}
	for _, secret := range []string{"PRIVATE KEY", "\"ott\"", "osm_", "ticket\":\"", "csrf"} {
		if strings.Contains(s, secret) {
			t.Fatalf("audit file contains %q", secret)
		}
	}
}

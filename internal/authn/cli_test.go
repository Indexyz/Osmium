package authn

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/indexyz/osmium/internal/authz"
)

func TestCLIPageEscapes(t *testing.T) {
	evil := `"><script>alert(1)</script>`
	body := cliConfirm(evil, `x"y`, cliParams{Port: 4242, State: "s<t", Challenge: "c&d"})
	if strings.Contains(body, "<script>") || strings.Contains(body, `x"y`) || strings.Contains(body, "s<t") || strings.Contains(body, "c&d") {
		t.Fatalf("unescaped value in page:\n%s", body)
	}
	for _, want := range []string{"&lt;script&gt;", `value="x&#34;y"`, `name="port" value="4242"`, `value="c&amp;d"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	if m := cliMessage("<b>"); !strings.Contains(m, "&lt;b&gt;") {
		t.Errorf("message not escaped: %s", m)
	}
}

func TestTokenInventoryAndRevocation(t *testing.T) {
	au, err := New(context.Background(), Config{DevLogin: true, SessionTTL: time.Hour}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	alice := User{ID: UserID("dev", "alice"), Issuer: "dev", Subject: "alice", DisplayName: "Alice", Groups: []string{"ops"}}
	bob := User{ID: UserID("dev", "bob"), Issuer: "dev", Subject: "bob", DisplayName: "Bob", Groups: []string{"ops"}}

	w1 := httptest.NewRecorder()
	au.startSession(w1, alice)
	aliceCookie := w1.Result().Cookies()[0]

	w2 := httptest.NewRecorder()
	au.startSession(w2, bob)
	bobCookie := w2.Result().Cookies()[0]

	aliceTok := "osm_alice_secret_token_value_123456"
	bobTok := "osm_bob_secret_token_value_654321"
	now := time.Now().UTC()
	au.mu.Lock()
	au.cliTokens[key(aliceTok)] = &CLIToken{ID: "ct-alice-1", User: alice, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	au.cliTokens[key(bobTok)] = &CLIToken{ID: "ct-bob-1", User: bob, CreatedAt: now.Add(time.Second), ExpiresAt: now.Add(time.Hour)}
	au.mu.Unlock()

	list := au.ListCLITokens()
	if len(list) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(list))
	}
	rawJSON, _ := json.Marshal(list)
	if strings.Contains(string(rawJSON), "secret_token") || strings.Contains(string(rawJSON), "osm_") {
		t.Fatalf("ListCLITokens leaked raw token: %s", rawJSON)
	}

	if info, ok := au.RevokeCLITokenByID("ct-bob-1"); !ok || info.UserID != bob.ID {
		t.Fatalf("revoke by id failed: %v %+v", ok, info)
	}
	reqBob := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBob.Header.Set("Authorization", "Bearer "+bobTok)
	if _, ok := au.LookupBearer(reqBob); ok {
		t.Fatal("revoked CLI token still accepted")
	}

	webN, cliN := au.RevokeUser(alice.ID)
	if webN != 1 || cliN != 1 {
		t.Fatalf("RevokeUser counts web=%d cli=%d, want 1,1", webN, cliN)
	}
	reqAliceWeb := httptest.NewRequest(http.MethodGet, "/", nil)
	reqAliceWeb.AddCookie(aliceCookie)
	if _, ok := au.Lookup(reqAliceWeb); ok {
		t.Fatal("revoked web session still accepted")
	}
	reqAliceCLI := httptest.NewRequest(http.MethodGet, "/", nil)
	reqAliceCLI.Header.Set("Authorization", "Bearer "+aliceTok)
	if _, ok := au.LookupBearer(reqAliceCLI); ok {
		t.Fatal("revoked alice CLI token still accepted")
	}

	// Bob's web session was unaffected until RevokeMatching matches him.
	reqBobWeb := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBobWeb.AddCookie(bobCookie)
	if _, ok := au.Lookup(reqBobWeb); !ok {
		t.Fatal("bob web session unexpectedly revoked")
	}
	webN, _ = au.RevokeMatching(func(u authz.Subject) bool { return u.Sub == "bob" })
	if webN != 1 {
		t.Fatalf("RevokeMatching web=%d, want 1", webN)
	}
	if _, ok := au.Lookup(reqBobWeb); ok {
		t.Fatal("bob web session survived RevokeMatching")
	}
}

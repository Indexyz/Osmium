package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// startRustFS runs a throwaway RustFS server if the binary is on PATH and
// returns its endpoint and credentials. RustFS speaks the same S3 API as
// MinIO, which minio-go targets first.
func startRustFS(t *testing.T) (endpoint, access, secret string) {
	t.Helper()
	bin, err := exec.LookPath("rustfs")
	if err != nil {
		t.Skip("rustfs not on PATH")
	}
	if testing.Short() {
		t.Skip("short mode")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	access, secret = "osm"+randHex(6), randHex(16)
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, "server", "--address", addr, "--access-key", access, "--secret-key", secret, dir)
	var log strings.Builder
	cmd.Stdout, cmd.Stderr = &log, &log
	cmd.Env = append(os.Environ(), "RUSTFS_OBS_LOGGER_LEVEL=warn")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() || os.Getenv("E2E_LOG") != "" {
			t.Logf("rustfs log:\n%s", log.String())
		}
	})
	c, _ := minio.New(addr, &minio.Options{Creds: credentials.NewStaticV4(access, secret, "")})
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.ListBuckets(ctx)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rustfs not ready: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := c.MakeBucket(context.Background(), "audit", minio.MakeBucketOptions{}); err != nil {
		t.Fatal(err)
	}
	return "http://" + addr, access, secret
}

func TestRustFSStore(t *testing.T) {
	ep, ak, sk := startRustFS(t)
	ctx := context.Background()

	if _, err := NewS3(ctx, S3Config{Endpoint: ep, Bucket: "missing", AccessKeyID: ak, SecretAccessKey: sk}); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing bucket: %v", err)
	}
	if _, err := NewS3(ctx, S3Config{Endpoint: ep, Bucket: "audit", AccessKeyID: ak, SecretAccessKey: "wrong"}); err == nil {
		t.Fatal("wrong secret accepted")
	}
	for _, bad := range []string{"minio:9000", "ftp://h", "http://h/path"} {
		if _, err := NewS3(ctx, S3Config{Endpoint: bad, Bucket: "audit"}); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}

	st, err := NewS3(ctx, S3Config{Endpoint: ep, Bucket: "audit", Prefix: "/osmium/prod/", AccessKeyID: ak, SecretAccessKey: sk})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, "2026-11-13/a.jsonl.gz", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if names, err := st.List(ctx, ""); err != nil || len(names) != 1 || names[0] != "2026-11-13/" {
		t.Fatalf("list root: %v %v", names, err)
	}
	if names, err := st.List(ctx, "2026-11-13/"); err != nil || len(names) != 1 || names[0] != "a.jsonl.gz" {
		t.Fatalf("list day: %v %v", names, err)
	}
	rc, err := st.Get(ctx, "2026-11-13/a.jsonl.gz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "x" {
		t.Fatalf("get %q", b)
	}
	if _, err := st.Get(ctx, "2026-11-13/none.jsonl.gz"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing object: %v", err)
	}
	if err := st.Delete(ctx, []string{"2026-11-13/a.jsonl.gz"}); err != nil {
		t.Fatal(err)
	}
	if names, _ := st.List(ctx, ""); len(names) != 0 {
		t.Fatalf("after delete: %v", names)
	}
}

// Events uploaded by one Server are searchable from another with an empty
// local directory (a replacement node, or a second replica).
func TestRustFSLoggerRoundTrip(t *testing.T) {
	ep, ak, sk := startRustFS(t)
	ctx := context.Background()
	st, err := NewS3(ctx, S3Config{Endpoint: ep, Bucket: "audit", Prefix: "osmium", AccessKeyID: ak, SecretAccessKey: sk})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	l := open(t, Config{Dir: t.TempDir(), ServerID: "node-a", Store: st})
	l.Record(Event{Action: "session.create", Result: "ok", Actor: "user:alice", SessionID: "s1"})
	l.Record(Event{Action: "session.create", Result: "denied", Actor: "user:bob"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l2 := open(t, Config{Dir: t.TempDir(), ServerID: "node-b", Store: st})
	l2.Record(Event{Action: "web.login", Result: "ok", Actor: "user:alice"}) // still local
	q := Query{From: now.Add(-time.Minute), To: now.Add(time.Minute), Limit: 100}
	p, err := l2.Search(ctx, q)
	if err != nil || len(p.Events) != 3 {
		t.Fatalf("all: %+v %v", p.Events, err)
	}
	q.Actor = "user:alice"
	if p, err = l2.Search(ctx, q); err != nil || len(p.Events) != 2 {
		t.Fatalf("alice: %+v %v", p.Events, err)
	}
	q.Limit = 1
	if p, err = l2.Search(ctx, q); err != nil || len(p.Events) != 1 || p.Next == "" {
		t.Fatalf("page: %+v %v", p, err)
	}
	q.Cursor = p.Next
	if p, err = l2.Search(ctx, q); err != nil || len(p.Events) != 1 || p.Events[0].Action != "web.login" {
		t.Fatalf("page 2: %+v %v", p, err)
	}
}

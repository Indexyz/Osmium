package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/indexyz/osmium/internal/config"
)

// withAudit loads the shipped example with its "audit" block replaced.
func withAudit(t *testing.T, audit string) (*config.Server, error) {
	t.Helper()
	b, err := os.ReadFile("../../examples/server.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["audit"] = json.RawMessage(audit)
	out, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return config.LoadServer(path)
}

func TestAuditS3Config(t *testing.T) {
	c, err := withAudit(t, `{"dir":"/x","s3":{"endpoint":"https://rustfs:9000","bucket":"b","access_key_id":"k","secret_access_key_file":"/s"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Audit.S3.SegmentInterval.D() != 5*time.Minute || c.Audit.S3.SegmentMaxBytes != 8<<20 {
		t.Fatalf("defaults: %+v", c.Audit.S3)
	}
	// Environment / IAM credentials: neither key field set.
	if _, err := withAudit(t, `{"dir":"/x","s3":{"endpoint":"https://s3.amazonaws.com","bucket":"b"}}`); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"s3":{"endpoint":"https://h","bucket":"b"}}`,
		`{"dir":"/x","s3":{"bucket":"b"}}`,
		`{"dir":"/x","s3":{"endpoint":"https://h"}}`,
		`{"dir":"/x","s3":{"endpoint":"https://h","bucket":"b","access_key_id":"k"}}`,
		`{"dir":"/x","s3":{"endpoint":"https://h","bucket":"b","secret_access_key_file":"/s"}}`,
		`{"dir":"/x","s3":{"endpoint":"https://h","bucket":"b","segment_interval":"10ms"}}`,
		`{"dir":"/x","s3":{"endpoint":"https://h","bucket":"b","secret_access_key":"inline"}}`,
	} {
		if _, err := withAudit(t, bad); err == nil {
			t.Errorf("accepted %s", bad)
		} else if strings.Contains(err.Error(), "inline") {
			t.Errorf("error echoes config value: %v", err)
		}
	}
}

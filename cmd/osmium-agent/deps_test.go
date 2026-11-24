package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The standalone Agent runs on small edge devices; keep heavy or
// reflection-based packages out of its dependency graph.
func TestAgentDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skip("go list unavailable:", err)
	}
	forbidden := []string{
		"regexp", "text/template", "html/template",
		"github.com/spf13/cobra",
		"golang.org/x/crypto/ssh", "golang.org/x/oauth2", "github.com/coreos/go-oidc",
		"github.com/go-jose/go-jose",
		"modernc.org/sqlite",
		"github.com/indexyz/osmium/internal/server", "github.com/indexyz/osmium/internal/client",
		"github.com/indexyz/osmium/internal/sessions", "github.com/indexyz/osmium/internal/authn",
		"github.com/indexyz/osmium/internal/storage",
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, f := range forbidden {
			if dep == f || strings.HasPrefix(dep, f+"/") {
				t.Errorf("osmium-agent must not depend on %s", dep)
			}
		}
	}
}

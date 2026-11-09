package config_test

import (
	"testing"

	"github.com/indexyz/osmium/internal/authz"
	"github.com/indexyz/osmium/internal/config"
)

// The shipped examples must stay loadable.
func TestExamplesLoad(t *testing.T) {
	if _, err := config.LoadServer("../../examples/server.example.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadAgent("../../examples/agent.example.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := authz.LoadFile("../../examples/policy.example.json"); err != nil {
		t.Fatal(err)
	}
}

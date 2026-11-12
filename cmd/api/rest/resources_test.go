package rest

import (
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
)

// testResources returns an empty resource manager for PFCP connections that
// tests construct directly.
func testResources(t *testing.T) *service.ResourceManager {
	t.Helper()
	manager, err := service.NewResourceManager("", 0)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

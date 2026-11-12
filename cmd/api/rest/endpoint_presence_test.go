package rest

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
)

// R2: PFCP endpoint edits compare LocalAddr().String() with the resolved
// request text. A wildcard address (the Helm/compose default ":8805") never
// compares equal, so re-submitting the SAME address re-binds the busy port.
func TestUnchangedWildcardEndpointEdit(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	probe, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	address := fmt.Sprintf(":%d", port)
	conn, err := core.NewPfcpConnection(address, "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, nil, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	cfg := validEditConfig()
	cfg.PfcpAddress = address
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{core.N4PFCPKeyName: conn}, nil, &cfg, nil, nil, nil)
	router := h.InitRoutes()
	// What `eupf backup restore` posts: the values GET /config returned.
	var shown config.UpfConfig
	if err := json.Unmarshal(getConfig(t, router, "/api/v1/config").Body.Bytes(), &shown); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"pfcp_address":%q,"pfcp_node_id":%q,"pfcp_remote_node":[]}`, shown.PfcpAddress, shown.PfcpNodeId)
	out := postConfig(t, router, "/api/v1/config/pfcp_n4", body)
	t.Logf("socket LocalAddr=%s configured=%s; unchanged pfcp_n4 edit: HTTP %d %s", conn.GetLocalAddr(), address, out.Code, strings.TrimSpace(out.Body.String()))
	if out.Code != http.StatusOK {
		t.Errorf("re-submitting the unchanged PFCP address %q fails with HTTP %d", address, out.Code)
	}
}

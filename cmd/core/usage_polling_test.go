package core

import (
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

type usageOnlyPollMaps struct {
	MapOperationsMock
	farReads int
}

func (m *usageOnlyPollMaps) GetFar(uint32) (ebpf.FarInfo, error) {
	m.farReads++
	return ebpf.FarInfo{Action: 8}, nil
}

func TestUsagePollingDoesNotInspectPublishedFARs(t *testing.T) {
	maps := &usageOnlyPollMaps{}
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	s := NewSession(1, 2, "", "", false)
	s.PutPDR(1, SPDRInfo{PdrID: 1, PdrInfo: ebpf.PdrInfo{FarId: 1}})
	conn.GetAssociation(peer).Sessions[1] = s
	conn.SendReports()
	if maps.farReads != 0 {
		t.Fatalf("usage polling inspected %d published FARs", maps.farReads)
	}
}

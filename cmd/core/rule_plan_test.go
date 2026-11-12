package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type preflightMaps struct {
	MapOperationsMock
	writes int
}

func (m *preflightMaps) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	return &cleanupFailureTx{ForwardingPlaneController: m}, nil
}
func (m *preflightMaps) CheckPDRPlan(uint64, []ebpf.PDRKey) error {
	return &ebpf.PDRPlanError{ID: 5, Err: ebpf.ErrRuleCapacity}
}
func (m *preflightMaps) UpdateFar(id uint32, info ebpf.FarInfo) error {
	m.writes++
	return m.MapOperationsMock.UpdateFar(id, info)
}
func TestPDRKeyCapacityIsValidatedBeforeAnyMapWrite(t *testing.T) {
	maps := &preflightMaps{}
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	req := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	for i := uint16(1); i <= 5; i++ {
		req.CreatePDR = append(req.CreatePDR, ie.NewCreatePDR(ie.NewPDRID(i), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0)), ie.NewFARID(1)))
	}
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionEstablishmentResponse)
	cause, _ := response.Cause.Cause()
	if maps.writes != 0 || cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("key validation followed writes: writes=%d cause=%d", maps.writes, cause)
	}
}

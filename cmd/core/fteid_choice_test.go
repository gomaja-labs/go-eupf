package core

import (
	"errors"
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestChooseIDCannotProduceDifferentInterfaceAddresses(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 4)
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	for i, source := range []uint8{0, 1} {
		request.CreatePDR = append(request.CreatePDR, ie.NewCreatePDR(ie.NewPDRID(uint16(i+1)), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(source), ie.NewFTEID(13, 0, nil, nil, 7)), ie.NewFARID(1)))
	}
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
	if cause != ie.CauseInvalidFTEIDAllocationOption {
		t.Fatalf("one CHOOSE ID produced different interface addresses: cause=%d", cause)
	}
	for i := uint32(1); i <= 4; i++ {
		id, err := conn.ResourceManager.FTEIDM.AllocateTEID(100, i)
		if err != nil || id != i {
			t.Fatalf("rejected CHOOSE leaked TEID %d: %d %v", i, id, err)
		}
	}
}

func TestRestorationRejectsUnavailableLocalFTEIDAddress(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 4)
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewPFCPSEReqFlags(1), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, 17, net.ParseIP("192.0.2.99"), nil, 0)), ie.NewFARID(1)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
	if cause != ie.CauseSessionRestorationResourceUnavailable {
		t.Fatalf("unavailable local F-TEID address accepted: cause=%d", cause)
	}
}

func TestNewPDRCanReferenceExistingUPFAllocatedFTEID(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 4)
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(1)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	initial := reply.(*message.SessionEstablishmentResponse)
	fseid, _ := initial.UPFSEID.FSEID()
	created, _ := initial.CreatedPDR[0].CreatedPDR()
	tunnel, _ := created.FTEID[0].FTEID()
	modification := message.NewSessionModificationRequest(fseid.SEID, 2, ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(10), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, tunnel.TEID, tunnel.IPv4Address, nil, 0)), ie.NewFARID(1)))
	changed, _, err := HandlePfcpSessionModificationRequest(conn, modification, peer)
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := changed.(*message.SessionModificationResponse).Cause.Cause()
	if cause != 1 {
		t.Fatalf("existing UPF F-TEID treated as CP allocation: cause=%d", cause)
	}
}

func TestDefaultFTEIDAllocationRejectsNewCPChoice(t *testing.T) {
	context := NewPDRCreationContext(NewSession(9, 42, "", "", false), nil)
	info := SPDRInfo{PdrID: 1}
	request := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, 17, net.ParseIP("192.0.2.1"), nil, 0)))
	err := context.extractPDR(request, &info)
	var invalid *requestIEError
	if !errors.As(err, &invalid) || invalid.cause != ie.CauseInvalidFTEIDAllocationOption {
		t.Fatalf("CP allocation accepted by default: %v", err)
	}
}

package core

import (
	"errors"
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestInformativeRuleMetadataDoesNotRejectForwarding(t *testing.T) {
	for _, rule := range []*ie.IE{
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewRATType(ie.RATTypeNR), ie.NewPDI(ie.NewSourceInterface(0), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN33GPPAccess))),
		ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewRATType(ie.RATTypeNR)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN6))),
		ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN6))),
		ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementInformation(0)),
	} {
		if err := validateRuleCapability(rule); err != nil {
			t.Errorf("%s: %v", rule.Type, err)
		}
	}
}

func TestBehaviourChangingRuleMetadataIsRejected(t *testing.T) {
	for _, rule := range []*ie.IE{
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGBR(1000, 1000)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(4)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(8)),
		ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementInformation(1)),
	} {
		if err := validateRuleCapability(rule); !errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
			t.Errorf("%s: %v", rule.Type, err)
		}
	}
}

// Open5GS 39a8c771f6d51a91112c28d1a57615dcb239118d:
// src/smf/context.c:2395-2444,2785-2832 and npcf-handler.c:729-775.
// free5GC SMF fd0052a19cb8e0950b5ba17d2a94506803f7fe7b:
// internal/context/datapath.go:679 (SMF-allocated uplink F-TEID).
func TestForwardingEstablishmentsFromCommonSMFShapes(t *testing.T) {
	for _, shape := range []string{"Open5GS_buffering", "Open5GS_forwarding", "free5GC"} {
		t.Run(shape, func(t *testing.T) {
			conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
			conn.ResourceManager, _ = service.NewResourceManager("", 32)
			uplink := ie.NewFTEID(15, 0, nil, nil, 0)
			want := uint8(1)
			if shape == "free5GC" {
				uplink = ie.NewFTEID(1, 100, net.ParseIP("192.0.2.20"), nil, 0)
				want = ie.CauseInvalidFTEIDAllocationOption
			}
			action := uint8(2)
			if shape == "Open5GS_buffering" {
				action = 12
				want = ie.CauseServiceNotSupported
			}
			rules := []*ie.IE{
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(0), uplink, ie.NewNetworkInstanceFQDN("internet"), ie.NewUEIPAddress(2, "192.0.2.10", "", 0, 0), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN33GPPAccess)), ie.NewOuterHeaderRemoval(6, 0), ie.NewFARID(1), ie.NewQERID(1)),
				ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewNetworkInstanceFQDN("internet"), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN6)), ie.NewFARID(2), ie.NewQERID(1)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1), ie.NewNetworkInstanceFQDN("internet"))),
				ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(0, 0), ie.NewMBR(1000, 1000), ie.NewQFI(9)),
			}
			dl := []*ie.IE{ie.NewFARID(2), ie.NewApplyAction(action), ie.NewForwardingParameters(ie.NewDestinationInterface(0), ie.NewNetworkInstanceFQDN("internet"), ie.NewOuterHeaderCreation(0x100, 200, "192.0.2.30", "", 0, 0, 0))}
			if shape == "Open5GS_buffering" {
				dl = append(dl, ie.NewBARID(1))
				rules = append(rules, ie.NewCreateBAR(ie.NewBARID(1)))
			}
			rules = append(rules, ie.NewCreateFAR(dl...))
			if shape != "free5GC" {
				rules = append(rules,
					ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(20), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCPFunction), ie.NewFTEID(7, 0, nil, nil, 0)), ie.NewOuterHeaderRemoval(6, 0), ie.NewFARID(2), ie.NewQERID(1)),
					ie.NewCreatePDR(ie.NewPDRID(4), ie.NewPrecedence(10), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(15, 0, nil, nil, 0), ie.NewNetworkInstanceFQDN("internet"), ie.NewSDFFilter("permit out 58 from ff02::2/128 to assigned", nil, nil, nil, 0)), ie.NewOuterHeaderRemoval(6, 0), ie.NewFARID(3)),
					ie.NewCreateFAR(ie.NewFARID(3), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceCPFunction), ie.NewOuterHeaderCreation(0x100, 300, "192.0.2.40", "", 0, 0, 0))))
			}
			request := message.NewSessionEstablishmentRequest(0, 1, append([]*ie.IE{ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil)}, rules...)...)
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
			if err != nil {
				t.Fatal(err)
			}
			response := reply.(*message.SessionEstablishmentResponse)
			if cause, _ := response.Cause.Cause(); cause != want {
				t.Fatalf("%s establishment Cause %d, want %d", shape, cause, want)
			}
			if want == 1 && len(response.CreatedPDR) != 3 {
				t.Fatalf("UP allocation omitted shared/default/CP tunnel: %d", len(response.CreatedPDR))
			}
		})
	}
}

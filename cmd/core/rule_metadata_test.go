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

func TestForwardingEstablishmentsFromCommonSMFShapes(t *testing.T) {
	for _, shape := range []string{"Open5GS", "free5GC"} {
		t.Run(shape, func(t *testing.T) {
			conn, peer := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})
			conn.ResourceManager, _ = service.NewResourceManager("", 32)
			uplink := []*ie.IE{ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0), ie.NewNetworkInstanceFQDN("internet"), ie.NewUEIPAddress(2, "192.0.2.10", "", 0, 0)}
			downlink := []*ie.IE{ie.NewSourceInterface(1), ie.NewNetworkInstanceFQDN("internet"), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0), ie.NewSDFFilter("permit out ip from any to assigned", nil, nil, nil, 0)}
			forwarding := []*ie.IE{ie.NewDestinationInterface(0), ie.NewNetworkInstanceFQDN("internet"), ie.NewOuterHeaderCreation(0x100, 100, "192.0.2.20", "", 0, 0, 0)}
			if shape == "Open5GS" {
				uplink = append(uplink, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN33GPPAccess))
				downlink = append(downlink, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN6))
				forwarding = append(forwarding, ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN33GPPAccess))
			}
			request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(uplink...), ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1), ie.NewQERID(1)),
				ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100), ie.NewPDI(downlink...), ie.NewFARID(2), ie.NewQERID(1)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1))),
				ie.NewCreateFAR(ie.NewFARID(2), ie.NewApplyAction(2), ie.NewForwardingParameters(forwarding...)),
				ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(0, 0), ie.NewMBR(1000, 1000), ie.NewQFI(9)))
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
			if err != nil {
				t.Fatal(err)
			}
			if cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause(); cause != 1 {
				t.Fatalf("forwarding establishment cause=%d", cause)
			}
		})
	}
}

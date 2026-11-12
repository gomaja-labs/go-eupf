package core

import (
	"net"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestInvalidRulesRejectEstablishment(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule *ie.IE
		kind uint8
		id   uint32
	}{
		{"unsupported-sdf", ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0), ie.NewSDFFilter("permit out 132 from any to any", nil, nil, nil, 0))), ie.RuleIDTypePDR, 7},
		{"unknown-predefined-rule", ie.NewCreatePDR(ie.NewPDRID(8), ie.NewPrecedence(10),
			ie.NewActivatePredefinedRules("unconfigured"), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.11", "", 0, 0))), ie.RuleIDTypePDR, 8},
		{"truncated-outer-header", ie.NewCreateFAR(ie.NewFARID(9), ie.NewApplyAction(2),
			ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess), ie.New(ie.OuterHeaderCreation, []byte{1, 0, 1}))), ie.RuleIDTypeFAR, 9},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			association := NewNodeAssociation("synthetic.example", "127.0.0.2")
			conn.NodeAssociations[association.Addr] = association
			request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(100, net.ParseIP("127.0.0.2"), nil), tt.rule)
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, association.Addr)
			if err != nil {
				t.Fatal(err)
			}
			response := reply.(*message.SessionEstablishmentResponse)
			cause, err := response.Cause.Cause()
			wantCause := ie.CauseRuleCreationModificationFailure
			if tt.name == "unsupported-sdf" {
				wantCause = ie.CauseServiceNotSupported
			}
			if err != nil || cause != wantCause {
				t.Fatalf("cause = %d, %v; want %d", cause, err, wantCause)
			}
			if len(association.Sessions) != 0 {
				t.Fatalf("failed establishment left %d sessions", len(association.Sessions))
			}
			kind, err := response.FailedRuleID.RuleIDType()
			if err != nil || kind != tt.kind {
				t.Fatalf("failed rule kind = %d, %v; want %d", kind, err, tt.kind)
			}
			id, err := response.FailedRuleID.FailedRuleID()
			if err != nil || id != tt.id {
				t.Fatalf("failed rule ID = %d, %v; want %d", id, err, tt.id)
			}
		})
	}
}

func TestInvalidRulesPreserveModification(t *testing.T) {
	for _, tt := range []struct {
		name string
		rule *ie.IE
		kind uint8
		id   uint32
	}{
		{"unsupported-sdf", ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPrecedence(10),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0), ie.NewSDFFilter("permit out 132 from any to any", nil, nil, nil, 0))), ie.RuleIDTypePDR, 7},
		{"truncated-outer-header", ie.NewUpdateFAR(ie.NewFARID(9),
			ie.NewUpdateForwardingParameters(ie.New(ie.OuterHeaderCreation, []byte{1, 0, 1}))), ie.RuleIDTypeFAR, 9},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			association := NewNodeAssociation("synthetic.example", "127.0.0.2")
			conn.NodeAssociations[association.Addr] = association
			session := NewSession(2, 100, "", "", false)
			session.PutPDR(7, SPDRInfo{PdrID: 7, Teid: 10})
			session.NewFar(9, 2, ebpf.FarInfo{Action: 2})
			association.Sessions[2] = session
			wantPDR, wantFAR := session.PDRs[7], session.FARs[9]
			reply, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(2, 1, tt.rule), association.Addr)
			if err != nil {
				t.Fatal(err)
			}
			response := reply.(*message.SessionModificationResponse)
			cause, err := response.Cause.Cause()
			if err != nil || cause != ie.CauseRuleCreationModificationFailure {
				t.Fatalf("cause = %d, %v; want rule failure", cause, err)
			}
			if len(session.PDRs) != 1 || !reflect.DeepEqual(session.PDRs[7], wantPDR) || len(session.FARs) != 1 || session.FARs[9] != wantFAR {
				t.Fatal("rejected request changed existing rules")
			}
			kind, err := response.FailedRuleID.RuleIDType()
			if err != nil || kind != tt.kind {
				t.Fatalf("failed rule kind = %d, %v", kind, err)
			}
			id, err := response.FailedRuleID.FailedRuleID()
			if err != nil || id != tt.id {
				t.Fatalf("failed rule ID = %d, %v", id, err)
			}
		})
	}
}

package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestUnsupportedRuleContentRejected(t *testing.T) {
	for _, test := range []struct {
		name  string
		rule  *ie.IE
		cause uint8
		kind  uint8
		id    uint32
	}{
		{"duration measurement", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 0, 1), ie.NewReportingTriggers(0, 0)), 76, ie.RuleIDTypeURR, 7},
		{"periodic reporting", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(1, 0)), 76, ie.RuleIDTypeURR, 7},
		{"volume quota", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0, 0), ie.NewVolumeQuota(1, 100, 0, 0)), 76, ie.RuleIDTypeURR, 7},
		{"linked URRs", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0, 0), ie.NewLinkedURRID(8)), 76, ie.RuleIDTypeURR, 7},
		{"measurement information", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0, 0), ie.NewMeasurementInformation(1)), 76, ie.RuleIDTypeURR, 7},
		{"guaranteed bitrate", ie.NewCreateQER(ie.NewQERID(7), ie.NewGateStatus(0, 0), ie.NewGBR(100, 100)), 76, ie.RuleIDTypeQER, 7},
		{"application detection", ie.NewCreatePDR(ie.NewPDRID(7), ie.NewPDI(ie.NewUEIPAddress(6, "192.0.2.7", "", 0, 0), ie.NewApplicationID("test-application"))), 76, ie.RuleIDTypePDR, 7},
		{"invalid forwarding policy", ie.NewCreateFAR(ie.NewFARID(7), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1), ie.New(ie.ForwardingPolicy, []byte{1, 'x'}))), 70, ie.RuleIDTypeFAR, 7},
		{"duplication", ie.NewCreateFAR(ie.NewFARID(7), ie.NewApplyAction(18)), 76, ie.RuleIDTypeFAR, 7},
		{"missing volume threshold", ie.NewCreateURR(ie.NewURRID(7), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(2, 0)), 67, ie.RuleIDTypeURR, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, peer := PreparePfcpConnection(t)
			request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), test.rule)
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
			if err != nil {
				t.Fatal(err)
			}
			response := reply.(*message.SessionEstablishmentResponse)
			cause, err := response.Cause.Cause()
			if err != nil || cause != test.cause {
				t.Fatalf("cause=%d err=%v want=%d", cause, err, test.cause)
			}
			kind, kindErr := response.FailedRuleID.RuleIDType()
			id, idErr := response.FailedRuleID.FailedRuleID()
			if kindErr != nil || idErr != nil || kind != test.kind || id != test.id {
				t.Fatalf("failed rule=%d/%d errors=%v/%v", kind, id, kindErr, idErr)
			}
			if len(conn.GetAssociation(peer).Sessions) != 0 {
				t.Fatal("unsupported rule left a session")
			}
		})
	}
}

func TestUnsupportedOuterHeaderFormsHaveServiceCause(t *testing.T) {
	for _, outer := range []*ie.IE{ie.NewOuterHeaderCreation(0x400, 0, "192.0.2.1", "", 2152, 0, 0), ie.NewOuterHeaderCreation(0x200, 100, "", "2001:db8::1", 0, 0, 0)} {
		conn, peer := PreparePfcpConnection(t)
		request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(7), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(0), outer)))
		reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
		if err != nil {
			t.Fatal(err)
		}
		cause, _ := reply.(*message.SessionEstablishmentResponse).Cause.Cause()
		if cause != ie.CauseServiceNotSupported {
			t.Fatalf("unsupported outer header cause=%d", cause)
		}
	}
}

package core

import (
	"net"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRuleIdentityRejectedBeforeMutation(t *testing.T) {
	tests := []struct {
		name string
		ies  []*ie.IE
		kind uint8
		id   uint32
	}{
		{"unknown FAR update", []*ie.IE{ie.NewUpdateFAR(ie.NewFARID(99), ie.NewApplyAction(1))}, ie.RuleIDTypeFAR, 99},
		{"unknown QER update", []*ie.IE{ie.NewUpdateQER(ie.NewQERID(99), ie.NewGateStatus(1, 1))}, ie.RuleIDTypeQER, 99},
		{"unknown URR update", []*ie.IE{ie.NewUpdateURR(ie.NewURRID(99))}, ie.RuleIDTypeURR, 99},
		{"unknown PDR update", []*ie.IE{ie.NewUpdatePDR(ie.NewPDRID(99))}, ie.RuleIDTypePDR, 99},
		{"duplicate create", []*ie.IE{ie.NewCreateFAR(ie.NewFARID(7), ie.NewApplyAction(1)), ie.NewCreateFAR(ie.NewFARID(7), ie.NewApplyAction(1))}, ie.RuleIDTypeFAR, 7},
		{"existing create", []*ie.IE{ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1))}, ie.RuleIDTypeFAR, 1},
		{"multiple updates", []*ie.IE{ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewRemoveFAR(ie.NewFARID(1))}, ie.RuleIDTypeFAR, 1},
		{"unknown FAR reference", []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(9), ie.NewPDI(ie.NewUEIPAddress(2, "192.0.2.9", "", 0, 0)), ie.NewFARID(99))}, ie.RuleIDTypePDR, 9},
		{"unknown QER reference", []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(9), ie.NewPDI(ie.NewUEIPAddress(2, "192.0.2.9", "", 0, 0)), ie.NewQERID(99))}, ie.RuleIDTypePDR, 9},
		{"unknown URR reference", []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(9), ie.NewPDI(ie.NewUEIPAddress(2, "192.0.2.9", "", 0, 0)), ie.NewURRID(99))}, ie.RuleIDTypePDR, 9},
		{"late error preserves CP SEID", []*ie.IE{ie.NewFSEID(999, net.ParseIP("127.0.0.2"), nil), ie.NewRemoveFAR(ie.NewFARID(99))}, ie.RuleIDTypeFAR, 99},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, peer := PreparePfcpConnection(t)
			session := NewSession(2, 42, "", "", false)
			session.NewFar(1, 10, session.GetFar(1).FarInfo)
			conn.GetAssociation(peer).Sessions[2] = session
			before := cloneSession(session)
			response, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(2, 1, tt.ies...), peer)
			if err != nil {
				t.Fatal(err)
			}
			r := response.(*message.SessionModificationResponse)
			cause, err := r.Cause.Cause()
			if err != nil || cause != ie.CauseRuleCreationModificationFailure {
				t.Fatalf("cause=%d err=%v, want rule failure", cause, err)
			}
			failed, err := r.FailedRuleID.FailedRuleID()
			kind, kindErr := r.FailedRuleID.RuleIDType()
			if err != nil || kindErr != nil || kind != tt.kind || failed != tt.id {
				t.Fatalf("failed rule=%+v err=%v", failed, err)
			}
			if !reflect.DeepEqual(session, before) {
				t.Fatalf("rejection changed session: before=%+v after=%+v", before, session)
			}
		})
	}
}

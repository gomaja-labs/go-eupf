package core

import (
	"github.com/gomaja-labs/go-pfcp/ie"
	"testing"
)

func TestMandatoryValidationUsesFirstOccurrence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		rule      *ie.IE
		offending ie.IEType
	}{
		{"PDR", ie.NewCreatePDR(ie.New(ie.PDRID, nil), ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0))), ie.PDRID},
		{"PDI", ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.New(ie.SourceInterface, nil), ie.NewSourceInterface(0))), ie.SourceInterface},
		{"FAR", ie.NewCreateFAR(ie.NewFARID(1), ie.New(ie.ApplyAction, nil), ie.NewApplyAction(1)), ie.ApplyAction},
		{"forwarding", ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.New(ie.DestinationInterface, nil), ie.NewDestinationInterface(0))), ie.DestinationInterface},
		{"update FAR", ie.NewUpdateFAR(ie.New(ie.FARID, nil), ie.NewFARID(1)), ie.FARID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failure := validateRule(tc.rule)
			if failure == nil || failure.offending != tc.offending || failure.cause != ie.CauseMandatoryIEIncorrect {
				t.Fatalf("first incorrect IE ignored: %v", failure)
			}
		})
	}
}

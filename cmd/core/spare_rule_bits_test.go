package core

import (
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRuleCapabilityIgnoresPublishedSpareBits(t *testing.T) {
	sdf := ie.NewSDFFilter("permit out udp from any to assigned", nil, nil, nil, 0)
	sdf.Payload[0] |= 0xc0
	tests := []struct {
		name string
		rule *ie.IE
	}{
		{"SDF", ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.1", "", 0, 0), sdf))},
		{"Apply Action", ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2, 0xe0))},
		{"Measurement and Reporting", ie.NewCreateURR(ie.NewURRID(1), ie.New(ie.MeasurementMethod, []byte{0x82}), ie.NewReportingTriggers(2, 0, 0xfc), ie.NewVolumeThreshold(1, 100, 0, 0))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRuleCapability(test.rule, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := validateSessionCapability(message.NewSessionEstablishmentRequest(0, 1, ie.NewPFCPSEReqFlags(0xf0))); err != nil {
		t.Fatal(err)
	}
}
func TestEmptyMandatoryReportingTriggersRejected(t *testing.T) {
	err := validateRuleCapability(ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0, 0)), nil)
	if err == nil {
		t.Fatal("accepted empty mandatory reporting triggers")
	}
	fields := ruleFailureIEs(err)
	cause, _ := fields[0].Cause()
	if cause != ie.CauseMandatoryIEIncorrect {
		t.Fatalf("empty mandatory reporting triggers cause=%d", cause)
	}
}

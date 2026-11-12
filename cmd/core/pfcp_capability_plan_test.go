package core

import (
	"errors"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
)

type capabilityPlanFixture struct {
	Allowed  *ie.IE
	First    *ie.IE
	Repeated []*ie.IE
	OtherIEs []*ie.IE
}

func TestCapabilityAuditKeepsFieldOrderAndPolicyWhenWarm(t *testing.T) {
	fields := &capabilityPlanFixture{}
	for range 2 {
		if err := rejectUnsupportedFields(fields, "Allowed"); err != nil {
			t.Fatal(err)
		}
		fields.First = ie.NewPDRID(1)
		fields.Repeated = []*ie.IE{ie.NewURRID(9)}
		var failure *requestIEError
		if err := rejectUnsupportedFields(fields, "Allowed"); !errors.As(err, &failure) || failure.offending != ie.PDRID {
			t.Fatal("warm audit omitted the first unsupported field")
		}
		if err := rejectUnsupportedFields(fields, "Allowed", "First"); !errors.As(err, &failure) || failure.offending != ie.URRID {
			t.Fatal("cached audit reused another supported-field policy")
		}
		if err := rejectUnsupportedFields(fields, "Allowed", "First", "Repeated"); err != nil {
			t.Fatal("supported fields were rejected")
		}
		fields.First = nil
		fields.Repeated = nil
		fields.OtherIEs = []*ie.IE{ie.NewPDRID(1)}
	}
}
func TestWarmCapabilityAuditDoesNotAllocateFieldMetadata(t *testing.T) {
	fields := &capabilityPlanFixture{}
	allocations := testing.AllocsPerRun(10, func() {
		if err := rejectUnsupportedFields(fields, "Allowed"); err != nil {
			t.Fatal(err)
		}
	})
	if allocations > 1 {
		t.Fatalf("warm audit allocates field metadata: %.0f allocations", allocations)
	}
}

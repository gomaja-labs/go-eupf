package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestBufferingApplyActionCombinations(t *testing.T) {
	for _, flags := range []uint8{1, 2, 4, 12} {
		if err := validateSupportedAction(ie.NewApplyAction(flags)); err != nil {
			t.Errorf("valid Apply Action %d: %v", flags, err)
		}
	}
	for _, flags := range []uint8{0, 3, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15} {
		if err := validateSupportedAction(ie.NewApplyAction(flags)); err == nil {
			t.Errorf("invalid Apply Action %d accepted", flags)
		}
	}
}
func TestBufferingFeatureParametersAreAdvertised(t *testing.T) {
	conn := newProtocolConnection(t)
	features := conn.featuresOctets
	if len(features) < 8 || features[0]&6 != 6 || features[7]&2 == 0 || features[1]&4 == 0 {
		t.Fatalf("missing DDND, DLBD, UDBC or DBDM: %v", features)
	}
	if features[0]&1 != 0 || features[4]&0x40 != 0 || len(features) > 8 && features[8]&8 != 0 {
		t.Fatalf("unimplemented BUCP, DDDS or EDBNC: %v", features)
	}
}

func TestEstablishmentIgnoresModificationOnlyBARParameters(t *testing.T) {
	session := &Session{}
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewCreateBAR(ie.NewBARID(1), ie.NewDLBufferingDuration(4*time.Minute), ie.NewDLBufferingSuggestedPacketCount(4)))
	if err := stageSessionBAR(session, request); err != nil {
		t.Fatal(err)
	}
	if session.bar == nil || session.bar.durationPresent || session.bar.dlPacketCountPresent {
		t.Fatalf("establishment applied modification-only BAR parameters: %+v", session.bar)
	}
}

package core

import (
	"errors"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 table 7.5.4.1-1 and clause 5.2.4.3.
func TestModificationDROBUIsAccepted(t *testing.T) {
	request := message.NewSessionModificationRequest(11, 1, ie.NewPFCPSMReqFlags(1))
	if err := validateSessionCapability(request); err != nil {
		t.Fatalf("DROBU modification rejected: %v", err)
	}
}

func TestModificationSessionFlagsKeepUnsupportedFlagsRejected(t *testing.T) {
	for _, flags := range []uint8{2, 4, 8, 16, 32, 64, 3} {
		request := message.NewSessionModificationRequest(11, 1, ie.NewPFCPSMReqFlags(flags))
		var failure *requestIEError
		if err := validateSessionCapability(request); !errors.As(err, &failure) || failure.cause != ie.CauseServiceNotSupported || failure.offending != ie.PFCPSMReqFlags {
			t.Fatalf("flags=%d: %v", flags, err)
		}
	}
}

func TestModificationFlagsIgnoreSpareBits(t *testing.T) {
	for _, flags := range []uint8{0, 1, 128, 129} {
		if err := validateSessionCapability(message.NewSessionModificationRequest(11, 1, ie.NewPFCPSMReqFlags(flags))); err != nil {
			t.Fatalf("flags=%d: %v", flags, err)
		}
	}
}

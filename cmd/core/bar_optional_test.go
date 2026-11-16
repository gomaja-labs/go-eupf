package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 table 7.5.9.2-1 and clause 7.6.8.
func TestBARIncorrectOptionalCountKeepsReportInstructions(t *testing.T) {
	for _, provisioned := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "provisioned"}[provisioned], func(t *testing.T) {
			conn, _, session, peer := downlinkFixture(t, true)
			children := []*ie.IE{ie.NewBARID(0)}
			if provisioned {
				children = append(children, ie.NewDLBufferingSuggestedPacketCount(8))
			}
			if err := createBAR(session, ie.NewCreateBAR(children...)); err != nil {
				t.Fatal(err)
			}
			queueDownlinkNotice(t, conn, session, 1, time.Now())
			first := identityRead(t, peer).(*message.SessionReportRequest)
			request := conn.transport.pending[first.Sequence()]
			previous := request.onComplete
			var outcome requestOutcome
			request.onComplete = func(result requestResult) { outcome = result.outcome; previous(result) }
			response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted),
				ie.NewPFCPSRRspFlags(1), ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0),
					ie.NewDLBufferingDuration(4*time.Second), ie.New(ie.DLBufferingSuggestedPacketCount, []byte{0, 0, 3})))
			conn.Handle(protocolWire(t, response), peer.LocalAddr().(*net.UDPAddr))
			if outcome != requestAccepted || session.bar.duration != 4*time.Second || session.bar.dlPacketCountPresent != provisioned {
				t.Fatalf("optional child lost other instructions: outcome=%s BAR=%+v", outcome, session.bar)
			}
			if provisioned && session.bar.dlPacketCount != 8 {
				t.Fatal("discarded count replaced the provisioned value")
			}
			if len(session.downlink.fars) != 0 || len(session.downlink.pending) != 0 {
				t.Fatal("optional child discarded DROBU")
			}
		})
	}
}

func TestBARUnsupportedConditionalPolicyStillRejects(t *testing.T) {
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		t.Fatal(err)
	}
	original := session.bar
	err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0),
		ie.New(ie.ExtendedDLBufferingNotificationPolicy, []byte{1})))
	if err == nil || session.bar != original {
		t.Fatal("unsupported conditional policy applied")
	}
}

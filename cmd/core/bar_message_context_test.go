package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestBARCreateParametersFollowMessageContext(t *testing.T) {
	for _, establishment := range []bool{true, false} {
		name := "Modification"
		if establishment {
			name = "Establishment"
		}
		t.Run(name, func(t *testing.T) {
			create := ie.NewCreateBAR(ie.NewBARID(0),
				ie.NewDownlinkDataNotificationDelay(200*time.Millisecond),
				ie.NewSuggestedBufferingPacketsCount(8),
				ie.NewDLBufferingDuration(4*time.Minute),
				ie.NewDLBufferingSuggestedPacketCount(4))
			var request message.Message = message.NewSessionModificationRequest(1, 1, create)
			if establishment {
				request = message.NewSessionEstablishmentRequest(0, 1, create)
			}
			session := NewSession(1, 2, "", "", false)
			if err := stageSessionBAR(session, request); err != nil {
				t.Fatal(err)
			}
			bar := session.bar
			if bar == nil || bar.id != 0 || !bar.packetCountPresent || bar.packetCount != 8 || bar.notificationDelay != 200*time.Millisecond {
				t.Fatalf("common Create BAR parameters: %+v", bar)
			}
			// TS 29.244 V20.1.0 table 7.5.2.6-1: extended parameters
			// belong to Modification; Establishment ignores them (7.6.10).
			if establishment {
				if bar.durationPresent || bar.dlPacketCountPresent || bar.durationRevision != 0 {
					t.Fatalf("Establishment applied unexpected extended parameters: %+v", bar)
				}
			} else if !bar.durationPresent || bar.duration != 4*time.Minute || !bar.dlPacketCountPresent || bar.dlPacketCount != 4 || bar.durationRevision == 0 {
				t.Fatalf("Modification lost extended parameters: %+v", bar)
			}
		})
	}
}

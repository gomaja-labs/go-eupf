package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type countedActivityController struct {
	ebpf.SessionActivityController
	reads int
}

func (controller *countedActivityController) ConsumeSessionActivity(slot uint32) (bool, error) {
	controller.reads++
	return controller.SessionActivityController.ConsumeSessionActivity(slot)
}
func TestInactivityUnchangedTimerDoesNotPollAfterEachRequest(t *testing.T) {
	for _, local := range []bool{false, true} {
		name := "cp"
		cpTimer, localTimer := 24*time.Hour, time.Duration(0)
		if local {
			name = "local"
			cpTimer, localTimer = 0, 24*time.Hour
		}
		t.Run(name, func(t *testing.T) {
			conn, _, session, plane, peer := inactivityFixture(t, cpTimer, localTimer)
			controller := &countedActivityController{SessionActivityController: plane}
			session.activity.controller = controller
			for i := 0; i < 32; i++ {
				req := message.NewSessionModificationRequest(session.LocalSEID, uint32(i+3), ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewTransportLevelMarking([]byte{byte(0x10 + 16*(i%2)), 0xfc}))))
				conn.Handle(protocolWire(t, req), peer.LocalAddr().(*net.UDPAddr))
				if pipelineCause(t, identityRead(t, peer)) != ie.CauseRequestAccepted {
					t.Fatal("FAR update rejected")
				}
			}
			if controller.reads != 0 {
				t.Fatalf("unchanged timer performed %d foreground observations", controller.reads)
			}
			session.activity.last = time.Now().Add(-2 * time.Second)
			inactivityUpdate(t, conn, session, peer, 100, ie.NewUserPlaneInactivityTimer(time.Second))
			inactivityReport(t, conn, session, peer)
			if controller.reads != 1 {
				t.Fatalf("timer update did not get exactly one immediate observation: %d", controller.reads)
			}
		})
	}
}

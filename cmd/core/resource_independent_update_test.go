package core

import (
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRuleOnlyModificationDoesNotWaitForAddressReservations(t *testing.T) {
	for _, pdrChange := range []bool{false, true} {
		t.Run(map[bool]string{false: "FAR", true: "PDR"}[pdrChange], func(t *testing.T) {
			conn, _, session, _, peer := inactivityFixture(t, 0, 0)
			request := message.NewSessionModificationRequest(session.LocalSEID, 30, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewTransportLevelMarking([]byte{0x10, 0xfc}))))
			if pdrChange {
				request.UpdatePDR = []*ie.IE{ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPrecedence(2))}
			}
			release := sync.OnceFunc(conn.ResourceManager.LockReservations())
			defer release()
			done := make(chan struct{})
			go func() { conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr)); close(done) }()
			if pdrChange {
				select {
				case <-done:
					t.Error("PDR mutation bypassed reservation ownership")
				case <-time.After(20 * time.Millisecond):
				}
			} else {
				select {
				case <-done:
				case <-time.After(100 * time.Millisecond):
					t.Error("FAR-only modification waited for the address/tunnel reservation lock")
				}
			}
			release()
			<-done
			if cause := pipelineCause(t, identityRead(t, peer)); cause != ie.CauseRequestAccepted {
				t.Fatalf("cause=%d", cause)
			}
		})
	}
}

package core

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestInvalidLengthRequestsUseCause68AndPeerSEID(t *testing.T) {
	for _, delta := range []int{-1, 1} {
		for _, session := range []bool{false, true} {
			conn := newProtocolConnection(t)
			var request message.Message = message.NewAssociationSetupRequest(93, ie.NewNodeIDFQDN("cp.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
			if session {
				assoc := NewNodeAssociation("cp.example", "127.0.0.2")
				assoc.Sessions[11] = NewSession(11, 22, "", "", false)
				conn.NodeAssociations[assoc.ID] = assoc
				request = message.NewSessionModificationRequest(11, 93)
			}
			wire := protocolWire(t, request)
			binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)-4+delta))
			response := exchangeProtocolDatagram(t, conn, wire)
			var cause *ie.IE
			switch response := response.(type) {
			case *message.AssociationSetupResponse:
				cause = response.Cause
			case *message.SessionModificationResponse:
				cause = response.Cause
			default:
				t.Fatalf("delta %d response %T", delta, response)
			}
			wantSEID := uint64(0)
			if session {
				wantSEID = 22
			}
			if value, err := cause.Cause(); err != nil || value != ie.CauseInvalidLength || response.Sequence() != 93 || response.SEID() != wantSEID {
				t.Fatalf("delta %d: cause %d, SEID %d, sequence %d: %v", delta, value, response.SEID(), response.Sequence(), err)
			}
		}
	}
}

func TestInvalidBundleLengthPreservesEarlierFrameWithSameSequence(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.2", 0)
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("cp.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(0x10))), peer.LocalAddr().(*net.UDPAddr))
	_ = identityRead(t, peer)
	wire, err := message.MarshalDatagram(message.NewSessionModificationRequest(11, 2), message.NewSessionModificationRequest(11, 2))
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(wire[18:20], 11)
	conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
	causes := map[uint8]int{}
	for range 2 {
		response := identityRead(t, peer).(*message.SessionModificationResponse)
		cause, _ := response.Cause.Cause()
		causes[cause]++
	}
	if causes[ie.CauseInvalidLength] != 1 || causes[ie.CauseSessionContextNotFound] != 1 {
		t.Fatalf("bundle causes %v", causes)
	}
}

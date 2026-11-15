package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestMalformedBundleRespondsToEveryFailedRequest(t *testing.T) {
	// TS 29.244 V20.1.0 clauses 6.5, 7.6.2, 7.6.3 and 7.6.7.
	for _, terminal := range []string{"ie", "length", "version"} {
		t.Run(terminal, func(t *testing.T) {
			conn := newProtocolConnection(t)
			peer := identityPeer(t, "127.0.0.2", 0)
			conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("cp.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(0x10))), peer.LocalAddr().(*net.UDPAddr))
			_ = identityRead(t, peer)
			assoc := conn.associationByID("cp.example")
			assoc.Sessions[11] = NewSession(11, 22, "", "", false)
			var wire []byte
			const count = 32
			for index := range count {
				frame := protocolWire(t, message.NewSessionModificationRequest(11, uint32(index+2)))
				// Consistent message Length, incomplete IE value: each earlier
				// body error must leave the next frame available to the caller.
				frame = binary.BigEndian.AppendUint16(frame, uint16(ie.URRID))
				frame = append(frame, 0, 1)
				binary.BigEndian.PutUint16(frame[2:], uint16(len(frame)-4))
				if index+1 < count {
					frame[0] |= 4
				} else if terminal == "length" {
					binary.BigEndian.PutUint16(frame[2:], uint16(len(frame)-3))
				} else if terminal == "version" {
					frame[0] = frame[0]&0x1f | 2<<5
				}
				wire = append(wire, frame...)
			}
			if _, err := peer.WriteToUDP(wire, conn.udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Fatal(err)
			}
			if err := conn.udpConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65535)
			n, address, err := conn.Receive(buffer)
			if err != nil {
				t.Fatal(err)
			}
			conn.Handle(buffer[:n], address)
			seen := make(map[uint32]bool)
			for range count {
				response := identityRead(t, peer)
				sequence := response.Sequence()
				if sequence < 2 || sequence > count+1 || seen[sequence] {
					t.Fatalf("unexpected or repeated sequence %d", sequence)
				}
				seen[sequence] = true
				if terminal == "version" && sequence == count+1 {
					if response.MessageType() != message.MsgTypeVersionNotSupportedResponse {
						t.Fatal("unsupported version was not answered")
					}
					continue
				}
				decoded, ok := response.(*message.SessionModificationResponse)
				if !ok {
					t.Fatalf("response %T", response)
				}
				cause, err := decoded.Cause.Cause()
				if err != nil || cause != ie.CauseInvalidLength || decoded.SEID() != 22 {
					t.Fatalf("cause=%d SEID=%d error=%v", cause, decoded.SEID(), err)
				}
				if terminal != "length" || sequence != count+1 {
					offending, err := decoded.OffendingIE.OffendingIE()
					if err != nil || offending != ie.URRID {
						t.Fatalf("offending=%d error=%v", offending, err)
					}
				}
			}
		})
	}
}

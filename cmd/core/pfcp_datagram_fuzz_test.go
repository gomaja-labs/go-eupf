package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func FuzzPFCPDatagram(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x40})
	for _, msg := range []message.Message{
		message.NewHeartbeatRequest(1, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))),
		message.NewHeartbeatRequest(2),
		message.NewHeartbeatResponse(3),
		message.NewAssociationSetupRequest(4, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))),
	} {
		wire := make([]byte, msg.MarshalLen())
		if err := msg.MarshalTo(wire); err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	// TS 29.244 V20.1.0 clauses 6.5 and 7.2.1A: exercise framing only
	// after both features have been negotiated, including the work bound.
	for _, count := range []int{2, maxBundleMessages, maxBundleMessages + 1} {
		messages := make([]message.Message, count)
		for i := range messages {
			messages[i] = message.NewSessionDeletionRequest(1, uint32(i+1))
		}
		bundle, err := message.MarshalDatagram(messages...)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(bundle)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65535 {
			t.Skip()
		}
		conn := newProtocolConnection(t)
		conn.NodeAssociations["127.0.0.1"] = NewNodeAssociation("synthetic.example", "127.0.0.1")
		conn.GetAssociation("127.0.0.1").CPFeatures = []byte{0x10}
		conn.Handle(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	})
}

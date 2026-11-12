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
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65535 {
			t.Skip()
		}
		conn := newProtocolConnection(t)
		conn.NodeAssociations["127.0.0.1"] = NewNodeAssociation("synthetic.example", "127.0.0.1")
		conn.Handle(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9})
	})
}

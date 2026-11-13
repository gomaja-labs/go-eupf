package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func FuzzRestorationCollisionLookup(f *testing.F) {
	for _, restoration := range []uint8{0, 1} {
		request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(1, net.ParseIP("192.0.2.1"), nil), ie.NewPFCPSEReqFlags(restoration),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, 1, net.ParseIP("192.0.2.2"), nil, 0))))
		wire, err := request.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire []byte) {
		decoded, err := message.Parse(wire)
		if err != nil {
			return
		}
		request, ok := decoded.(*message.SessionEstablishmentRequest)
		if !ok {
			return
		}
		resources, err := service.NewResourceManager("", 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := resources.FTEIDM.ReserveTEID(2, 1, 1); err != nil {
			t.Fatal(err)
		}
		_ = restorationTEIDCollision(request, resources)
		if !resources.FTEIDM.HasTEID(1) {
			t.Fatal("collision lookup changed the explicit lease")
		}
		if id, err := resources.FTEIDM.AllocateTEID(3, 1); err != nil || id == 1 {
			t.Fatal("collision lookup consumed an automatic index", id, err)
		}
	})
}

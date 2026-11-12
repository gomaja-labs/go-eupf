//go:build linux

package core

import (
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestAllMovingPDRsDetachBeforeNewPrefixIsApplied(t *testing.T) {
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	maps := ebpf.NewBpfObjects()
	if err := maps.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = maps.Close() })
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 0)
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, []byte{127, 0, 0, 1}, nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	for _, id := range []uint16{1, 2} {
		request.CreatePDR = append(request.CreatePDR, ie.NewCreatePDR(ie.NewPDRID(id), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(5, "", "2001:db8::1", 0, 0)), ie.NewFARID(1)))
	}
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	initial := reply.(*message.SessionEstablishmentResponse)
	if cause, _ := initial.Cause.Cause(); cause != 1 {
		t.Fatal(cause)
	}
	fseid, _ := initial.UPFSEID.FSEID()
	update := message.NewSessionModificationRequest(fseid.SEID, 2)
	for _, id := range []uint16{1, 2} {
		update.UpdatePDR = append(update.UpdatePDR, ie.NewUpdatePDR(ie.NewPDRID(id), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(69, "", "2001:db8::1", 0, 128))))
	}
	changed, _, err := HandlePfcpSessionModificationRequest(conn, update, peer)
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := changed.(*message.SessionModificationResponse).Cause.Cause(); cause != 1 {
		t.Fatalf("valid shared-prefix replacement rejected with cause %d", cause)
	}
	for _, pdr := range conn.GetAssociation(peer).Sessions[fseid.SEID].PDRs {
		ones, bits := pdr.PdrInfo.UEIPv6Mask.Size()
		if ones != 128 || bits != 128 {
			t.Fatal("old prefix survived")
		}
	}
}

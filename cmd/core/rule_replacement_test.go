//go:build linux

package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestUpdatedRulesReplaceSlotsAndRebindEveryPDR(t *testing.T) {
	maps := ebpf.NewBpfObjects()
	if err := maps.Load(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = maps.Close() })
	conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 0)
	req := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)),
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(0, 0)))
	for _, addr := range []string{"192.0.2.10", "192.0.2.11"} {
		req.CreatePDR = append(req.CreatePDR, ie.NewCreatePDR(ie.NewPDRID(uint16(len(req.CreatePDR)+1)), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, addr, "", 0, 0)), ie.NewFARID(1), ie.NewQERID(1)))
	}
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
	if err != nil {
		t.Fatal(err)
	}
	accepted := reply.(*message.SessionEstablishmentResponse)
	if cause, _ := accepted.Cause.Cause(); cause != 1 {
		t.Fatal(cause)
	}
	fseid, _ := accepted.UPFSEID.FSEID()
	session := conn.GetAssociation(peer).Sessions[fseid.SEID]
	oldFar, oldQer := session.FARs[1].GlobalId, session.QERs[1].GlobalId
	var anchor ebpf.IpEntrypointQerInfo
	if err := maps.QerMap.Lookup(oldQer, &anchor); err != nil {
		t.Fatal(err)
	}
	anchor.UlStart, anchor.DlStart = 123456, 654321
	if err := maps.QerMap.Put(oldQer, &anchor); err != nil {
		t.Fatal(err)
	}
	update := message.NewSessionModificationRequest(fseid.SEID, 2, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewUpdateQER(ie.NewQERID(1), ie.NewGateStatus(1, 0)))
	result, _, err := HandlePfcpSessionModificationRequest(conn, update, peer)
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := result.(*message.SessionModificationResponse).Cause.Cause(); cause != 1 {
		t.Fatal(cause)
	}
	session = conn.GetAssociation(peer).Sessions[fseid.SEID]
	if session.FARs[1].GlobalId == oldFar {
		t.Error("Update FAR overwrote the reader's slot")
	}
	if session.QERs[1].GlobalId == oldQer {
		t.Error("Update QER overwrote the reader's slot")
	}
	for _, pdr := range session.PDRs {
		bucket, err := maps.LookupDownlinkPDR(pdr.Ipv4)
		if err != nil {
			t.Fatal(err)
		}
		binding := bucket.Entries[0].Pdr
		if binding.FarId != session.FARs[1].GlobalId || binding.QerId[0] != session.QERs[1].GlobalId {
			t.Errorf("unchanged PDR kept old bindings: %+v", binding)
		}
	}
	if err := maps.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	var state, version ebpf.IpEntrypointQerInfo
	if err := maps.QerMap.Lookup(oldQer, &state); err != nil {
		t.Fatal(err)
	}
	if err := maps.QerMap.Lookup(session.QERs[1].GlobalId, &version); err != nil {
		t.Fatal(err)
	}
	if state.UlStart != 123456 || state.DlStart != 654321 || version.PolicerId != oldQer {
		t.Fatalf("replacement lost live policer: state=%+v version=%+v", state, version)
	}
	deleted, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(fseid.SEID, 3), peer)
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := deleted.(*message.SessionDeletionResponse).Cause.Cause(); cause != 1 {
		t.Fatal(cause)
	}
	if err := maps.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	if next, err := maps.GetNextQER(); err != nil || next != oldQer {
		t.Fatalf("policer anchor leaked: next=%d error=%v", next, err)
	}

}

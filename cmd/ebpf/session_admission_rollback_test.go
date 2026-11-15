//go:build linux

package ebpf_test

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRecoveredCreationRollbackReclaimsAdmission(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		t.Run(fmt.Sprintf("buffered=%t", buffered), func(t *testing.T) { testRecoveredCreationRollback(t, buffered) })
	}
}
func testRecoveredCreationRollback(t *testing.T, buffered bool) {
	plane := ebpf.NewTransientUndoPlane(t)
	previous := config.Conf
	config.Conf = config.UpfConfig{MaxSessions: 1}
	t.Cleanup(func() { config.Conf = previous })
	resources, err := service.NewResourceManager("", 1)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", plane, resources, nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if buffered {
		buffering, err := core.NewPacketBuffering(plane.BpfObjects, core.BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := buffering.Close(); err != nil {
				t.Error(err)
			}
		})
		if err := conn.SetPacketBuffering(buffering); err != nil {
			t.Fatal(err)
		}
		<-buffering.Start(context.Background())
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP{127, 0, 0, 25}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	exchange := func(request message.Message) message.Message {
		t.Helper()
		wire := make([]byte, request.MarshalLen())
		err := request.MarshalTo(wire)
		if err != nil {
			t.Fatal(err)
		}
		conn.Handle(wire, peer.LocalAddr().(*net.UDPAddr))
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 65535)
		n, _, err := peer.ReadFromUDP(data)
		if err != nil {
			t.Fatal(err)
		}
		response, err := message.Parse(data[:n])
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	setup := exchange(message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("rollback.example"), ie.NewRecoveryTimeStamp(time.Unix(1800000000, 0)))).(*message.AssociationSetupResponse)
	if cause, err := setup.Cause.Cause(); err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("setup: %d %v", cause, err)
	}
	request := func(sequence uint32) *message.SessionEstablishmentRequest {
		action := uint8(1)
		if buffered {
			action = 4
		}
		return message.NewSessionEstablishmentRequest(0, sequence, ie.NewNodeIDFQDN("rollback.example"), ie.NewFSEID(uint64(sequence), net.IP{127, 0, 0, 25}, nil),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(action)),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(1)),
			ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "198.51.100.2", "", 0, 0)), ie.NewFARID(1)))
	}
	failed := exchange(request(2)).(*message.SessionEstablishmentResponse)
	if cause, _ := failed.Cause.Cause(); cause == ie.CauseRequestAccepted {
		t.Fatal("faulted publication was accepted")
	}
	select {
	case <-plane.Faulted:
	default:
		t.Fatal("real rollback did not hit the transient undo fault")
	}
	select {
	case <-plane.Repaired:
	case <-time.After(2 * time.Second):
		t.Fatal("grace worker did not repair the real map undo")
	}
	indexBits := bits.Len32(1)
	period := int64(1)<<(32-indexBits) - 1
	onlyTEID := uint32(1+resources.RecoveryTimestamp.Unix()%period)<<indexBits + 1
	deadline := time.Now().Add(2 * time.Second)
	for resources.FTEIDM.HasTEID(onlyTEID) {
		if time.Now().After(deadline) {
			t.Fatal("real rollback did not reclaim its TEID")
		}
		time.Sleep(time.Millisecond)
	}
	deadline = time.Now().Add(2 * time.Second)
	for sequence := uint32(3); ; sequence++ {
		reply := exchange(request(sequence)).(*message.SessionEstablishmentResponse)
		cause, _ := reply.Cause.Cause()
		if cause == ie.CauseRequestAccepted {
			break
		}
		if cause != ie.CauseNoResourcesAvailable || time.Now().After(deadline) {
			t.Fatalf("real rollback repaired and TEID reclaimed, but admission leaked: cause=%d", cause)
		}
		time.Sleep(time.Millisecond)
	}
}

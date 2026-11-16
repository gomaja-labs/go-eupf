//go:build linux

package core

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 tables 7.5.2.6-1, 7.5.4.11-1 and clause 7.6.8.
func TestBARIncorrectOptionalCountKeepsRequestInstructions(t *testing.T) {
	for _, kind := range []string{"establishment", "modification-create", "modification-update"} {
		t.Run(kind, func(t *testing.T) {
			plane := ebpf.NewBpfObjects()
			plane.SetBufferCapacity(16, 8)
			if err := plane.Load(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := plane.Close(); err != nil {
					t.Error(err)
				}
			})
			conn := sessionLimitConnection(t, 16, nil, plane)
			buffering, err := NewPacketBuffering(plane, BufferingOptions{Packets: 8, PerSession: 4, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
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
			peer := identityPeer(t, "127.0.0.25", 8805)
			identitySetup(t, conn, peer, "buffer.example")
			request := sessionLimitRequest("buffer.example", 2, 1)
			invalid := ie.New(ie.DLBufferingSuggestedPacketCount, []byte{0, 0, 3})
			children := []*ie.IE{ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(7), ie.NewDLBufferingDuration(4 * time.Second), invalid}
			if kind == "establishment" {
				request.CreateBAR = ie.NewCreateBAR(children...)
			}
			if kind == "modification-update" {
				request.CreateBAR = ie.NewCreateBAR(ie.NewBARID(0))
			}
			conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
			response := identityRead(t, peer).(*message.SessionEstablishmentResponse)
			if cause := pipelineCause(t, response); cause != ie.CauseRequestAccepted {
				t.Fatalf("optional count rejected establishment: cause=%d", cause)
			}
			fseid, err := response.UPFSEID.FSEID()
			if err != nil {
				t.Fatal(err)
			}
			if kind != "establishment" {
				var bar *ie.IE
				if kind == "modification-create" {
					bar = ie.NewCreateBAR(children...)
				} else {
					bar = ie.NewUpdateBARWithinSessionModificationRequest(children...)
				}
				conn.Handle(protocolWire(t, message.NewSessionModificationRequest(fseid.SEID, 3, bar)), peer.LocalAddr().(*net.UDPAddr))
				if cause := pipelineCause(t, identityRead(t, peer)); cause != ie.CauseRequestAccepted {
					t.Fatalf("optional count rejected modification: cause=%d", cause)
				}
			}
			session := conn.associationByID("buffer.example").Sessions[fseid.SEID]
			if session.bar == nil || session.bar.packetCount != 7 || session.bar.dlPacketCountPresent {
				t.Fatalf("optional discard lost other instructions: %+v", session.bar)
			}
			if kind != "establishment" && session.bar.duration != 4*time.Second {
				t.Fatalf("valid duration lost: %+v", session.bar)
			}
		})
	}
}

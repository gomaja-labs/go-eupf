package core

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestReplacementAndRestartAnswerBeforeRuleCleanup(t *testing.T) {
	for _, mode := range []string{"setup", "restart", "selective"} {
		t.Run(mode, func(t *testing.T) {
			conn := newProtocolConnection(t)
			maps := &releaseCleanupMaps{}
			conn.mapOperations = maps
			resources, err := service.NewResourceManager("192.0.2.0/24", 256)
			if err != nil {
				t.Fatal(err)
			}
			conn.ResourceManager = resources
			cp := identityPeer(t, "127.0.0.25", 0)
			identitySetup(t, conn, cp, "cleanup.example")
			assoc := conn.associationByID("cleanup.example")
			for id := uint64(11); id < 141; id++ {
				s := NewSession(id, id+100, "", "", false)
				s.CPFSEIDIPv4 = net.ParseIP("127.0.0.25")
				s.NewFar(1, uint32(id), ebpf.FarInfo{Action: 1})
				assoc.Sessions[id] = s
				assoc.sessionEntities[id] = "127.0.0.25"
				conn.indexSession(assoc, s, 1)
				if err := resources.FTEIDM.ReserveTEID(id, 1, uint32(id)); err != nil {
					t.Fatal(err)
				}
			}
			var request message.Message
			if mode == "restart" {
				assoc.recoveries["127.0.0.25"] = time.Unix(100, 0)
				request = message.NewHeartbeatRequest(2, ie.NewRecoveryTimeStamp(time.Unix(101, 0)))
			} else {
				ies := []*ie.IE{ie.NewNodeIDFQDN(assoc.ID), ie.NewRecoveryTimeStamp(time.Unix(100, 0))}
				if mode == "selective" {
					assoc.sessionEntities[140] = "127.0.0.26"
					ies = append(ies, ie.NewPFCPSessionRetentionInformation(ie.NewCPPFCPEntityIPAddress(net.ParseIP("127.0.0.26"), nil)))
				}
				request = message.NewAssociationSetupRequest(2, ies...)
			}
			conn.Handle(protocolWire(t, request), cp.LocalAddr().(*net.UDPAddr))
			response := identityRead(t, cp)
			if request.MessageType() != message.MsgTypeHeartbeatRequest && pipelineCause(t, response) != ie.CauseRequestAccepted {
				t.Fatal("replacement rejected")
			}
			if len(maps.attempts) != 0 {
				t.Fatalf("%d rule deletions ran before response", len(maps.attempts))
			}
			if err := resources.FTEIDM.ReserveTEID(999, 1, 11); !errors.Is(err, service.ErrResourceCollision) {
				t.Fatal("pending cleanup released TEID early")
			}
			conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 3)), cp.LocalAddr().(*net.UDPAddr))
			if cause := pipelineCause(t, identityRead(t, cp)); cause != ie.CauseSessionContextNotFound {
				t.Fatalf("invalidated session cause %d, want 65", cause)
			}
			// Admission uses the replacement immediately, independently of cleanup.
			pipelineEstablish(t, conn, cp, assoc.ID, 700, "127.0.0.25", 1, 4)
			current := conn.associationByID(assoc.ID)
			if mode == "selective" && current.Sessions[140] == nil {
				t.Fatal("selectively retained session missing")
			}
			conn.serviceHeartbeats(time.Now())
			if len(maps.attempts) != 64 {
				t.Fatalf("first batch %d want 64", len(maps.attempts))
			}
			if err := resources.FTEIDM.ReserveTEID(999, 1, 139); err == nil { // may have been in the first unordered batch
				resources.FTEIDM.ReleaseTEID(999)
			}
			for range 3 {
				conn.serviceHeartbeats(time.Now())
			}
			if err := resources.FTEIDM.ReserveTEID(999, 1, 11); err != nil {
				t.Fatalf("completed cleanup retained TEID: %v", err)
			}
		})
	}
}

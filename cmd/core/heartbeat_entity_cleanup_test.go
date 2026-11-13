package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// A CP PFCP entity restarts; the UPF detects it from a newer Recovery Time
// Stamp in that entity's Heartbeat Request (TS 23.007 V19.2.0 clause 19A,
// TS 23.527 V20.0.0 clause 4.4.2.1) and invalidates its sessions. The restarted
// entity then sends a new Session Establishment Request that happens to reuse
// sequence number 5 and the same content as one before the restart (TS 29.244
// V20.1.0 clause 6.4 only requires uniqueness among outstanding requests).
// That new request must execute; it must never receive the replay outcome of
// the invalidated session. observeEntityRecovery calls forgetEntityTransactions
// precisely to drop that entity's replay outcomes and pending requests.
func TestHeartbeatRestartForgetsEntityReplaysForEveryNodeIDType(t *testing.T) {
	for _, node := range []string{"127.0.0.25", "2001:db8::25", "smf.example"} {
		for _, nat := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nat=%t", node, nat), func(t *testing.T) {
				pipelineQuiet(t)
				conn := identityConnection(t)
				cp := identityPeer(t, "127.0.0.25", 8805)
				cpAddr := cp.LocalAddr().(*net.UDPAddr)
				identitySetup(t, conn, cp, node)
				assoc := conn.associationByID(node)
				entity := "127.0.0.25"
				if nat {
					entity = "127.0.0.27"
				}
				entityPeer := cp
				if nat {
					entityPeer = identityPeer(t, entity, 8805)
				}
				other := identityPeer(t, "127.0.0.26", 8805)
				otherID := identityEstablish(t, conn, other, node, "127.0.0.26")
				if err := conn.sendAssociationRequest(message.NewSessionReportRequest(0, 0, ie.NewReportType(0, 0, 0, 1)), assoc.ID, false, otherID); err != nil {
					t.Fatal(err)
				}
				otherReport := identityRead(t, other)
				var otherKey requestKey
				var otherEntry *responseIndex
				conn.transport.mu.Lock()
				for key, entry := range conn.transport.responses {
					if entry.entity == "127.0.0.26" {
						otherKey = key
						otherEntry = entry
						break
					}
				}
				conn.transport.mu.Unlock()
				if otherEntry == nil {
					t.Fatal("other entity replay missing before restart")
				}
				establishment := protocolWire(t, message.NewSessionEstablishmentRequest(0, 5,
					newIeNodeID(node), ie.NewFSEID(1, net.ParseIP(entity).To4(), nil),
					ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(1)),
					ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1))))
				conn.Handle(establishment, cpAddr)
				first := identityRead(t, cp).(*message.SessionEstablishmentResponse)
				if pipelineCause(t, first) != ie.CauseRequestAccepted {
					t.Fatal("establishment rejected")
				}
				before, _ := first.UPFSEID.FSEID()
				// One outstanding Session Report to the same CP entity.
				if err := conn.sendAssociationRequest(message.NewSessionReportRequest(0, 0, ie.NewReportType(0, 0, 0, 1)), assoc.ID, false, before.SEID); err != nil {
					t.Fatal(err)
				}
				_ = identityRead(t, entityPeer)
				for i, stamp := range []int64{1800000000, 1800000100} {
					heartbeat := message.NewHeartbeatRequest(uint32(20+i), ie.NewRecoveryTimeStamp(time.Unix(stamp, 0)))
					if nat {
						heartbeat.SourceIPAddress = ie.NewSourceIPAddress(net.ParseIP(entity), nil, 0)
					}
					conn.Handle(protocolWire(t, heartbeat), cpAddr)
					if _, ok := identityRead(t, cp).(*message.HeartbeatResponse); !ok {
						t.Fatal("no heartbeat response")
					}
				}
				if conn.associationByID(node).Sessions[before.SEID] != nil {
					t.Fatal("restart was not detected")
				}
				conn.transport.mu.Lock()
				pendingReports, cached := 0, len(conn.transport.responses)
				for _, req := range conn.transport.pending {
					if req.typ == message.MsgTypeSessionReportRequest && req.entity == entity {
						pendingReports++
					}
				}
				if conn.transport.responses[otherKey] != otherEntry {
					t.Error("restart dropped other entity replay")
				}
				pending := conn.transport.pending[otherReport.Sequence()]
				if pending == nil || pending.entity != "127.0.0.26" {
					t.Error("restart canceled other entity request")
				}
				conn.transport.mu.Unlock()
				if assoc.Sessions[otherID] == nil {
					t.Error("restart invalidated other entity session")
				}
				// The restarted entity's new request (same sequence and bytes).
				conn.Handle(establishment, cpAddr)
				second := identityRead(t, cp).(*message.SessionEstablishmentResponse)
				after, _ := second.UPFSEID.FSEID()
				t.Logf("node=%s retired_up_seid=%d up_seid_returned_after_restart=%d replay_entries_after_restart=%d pending_reports_to_restarted_entity=%d active_sessions=%d",
					node, before.SEID, after.SEID, cached, pendingReports, len(conn.associationByID(node).Sessions))
				if pendingReports != 0 {
					t.Errorf("Session Report to the restarted CP entity is still pending and will be retransmitted")
				}
				if after.SEID == before.SEID {
					// The CP now holds an UP F-SEID whose context is being deleted.
					conn.Handle(protocolWire(t, message.NewSessionModificationRequest(after.SEID, 6)), cpAddr)
					cause := pipelineCause(t, identityRead(t, cp))
					t.Errorf("restarted CP received the invalidated session's cached outcome (UP SEID %d); its next Modification gets cause %d", after.SEID, cause)
				}
			})
		}
	}
}

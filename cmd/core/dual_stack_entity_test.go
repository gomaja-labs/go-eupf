package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// One CP PFCP entity with a dual-stack CP F-SEID (TS 29.244 V20.1.0 clause
// 8.2.37) runs PFCP over IPv6. Its Heartbeat Request (source = its IPv6
// address, TS 23.007 V19.2.0 clause 19A) announces a restart.
func TestDualStackFSEIDRestartFromIPv6Heartbeat(t *testing.T) {
	probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	_ = probe.Close()
	for _, tc := range []struct {
		node string
		v4   net.IP
	}{{"::1", nil}, {"::1", net.ParseIP("127.0.0.25").To4()}, {"127.0.0.25", net.ParseIP("127.0.0.25").To4()}, {"smf6.example", net.ParseIP("127.0.0.25").To4()}} {
		node := tc.node
		t.Run(node+"/dual-stack="+map[bool]string{true: "yes", false: "no(control)"}[tc.v4 != nil], func(t *testing.T) {
			pipelineQuiet(t)
			conn, err := NewPfcpConnection("[::1]:0", "::1", "127.0.0.1", "127.0.0.1", &MapOperationsMock{}, emptyResources(t), nil, nil, DefaultProfile{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(conn.Close)
			resources, err := service.NewResourceManager("", 16)
			if err != nil {
				t.Fatal(err)
			}
			conn.ResourceManager = resources
			cp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cp.Close() })
			cpAddr := cp.LocalAddr().(*net.UDPAddr)
			identitySetup(t, conn, cp, node)
			establishment := protocolWire(t, message.NewSessionEstablishmentRequest(0, 5,
				newIeNodeID(node), ie.NewFSEID(1, tc.v4, net.IPv6loopback),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(1)),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1))))
			conn.Handle(establishment, cpAddr)
			first := identityRead(t, cp).(*message.SessionEstablishmentResponse)
			if pipelineCause(t, first) != ie.CauseRequestAccepted {
				t.Fatal("establishment rejected")
			}
			before, _ := first.UPFSEID.FSEID()
			for i, stamp := range []int64{1800000000, 1800000100} {
				conn.Handle(protocolWire(t, message.NewHeartbeatRequest(uint32(20+i), ie.NewRecoveryTimeStamp(time.Unix(stamp, 0)))), cpAddr)
				if _, ok := identityRead(t, cp).(*message.HeartbeatResponse); !ok {
					t.Fatal("no heartbeat response")
				}
			}
			conn.stateMu.RLock()
			assoc := conn.associationByID(node)
			live := assoc.Sessions[before.SEID] != nil
			entity := assoc.sessionEntities[before.SEID]
			recorded := assoc.recoveries[cpAddr.IP.String()]
			conn.stateMu.RUnlock()
			conn.Handle(establishment, cpAddr)
			second := identityRead(t, cp).(*message.SessionEstablishmentResponse)
			after, _ := second.UPFSEID.FSEID()
			t.Logf("node=%s heartbeat_source=%s session_entity=%s restart_recorded=%s session_still_active=%t up_seid_before=%d up_seid_for_restarted_cp=%d", node, cpAddr.IP, entity, recorded.UTC().Format(time.RFC3339), live, before.SEID, after.SEID)
			if live {
				t.Errorf("node=%s: restart of the CP entity (heartbeat from its F-SEID IPv6 address) left its session active", node)
			}
			if after.SEID == before.SEID {
				t.Errorf("node=%s: restarted CP got the pre-restart replay outcome (UP SEID %d)", node, after.SEID)
			}
		})
	}
}

func TestDualStackFSEIDRestartFromHeartbeatResponse(t *testing.T) {
	for _, node := range []string{"127.0.0.25", "::1", "dual.example"} {
		t.Run(node, func(t *testing.T) {
			pipelineQuiet(t)
			conn := sessionLimitConnection(t, 1, nil, nil)
			cp := identityPeer(t, "127.0.0.25", 0)
			identitySetup(t, conn, cp, node)
			request := sessionLimitRequest(node, 5, 1)
			request.CPFSEID = ie.NewFSEID(1, net.ParseIP("127.0.0.25"), net.IPv6loopback)
			response := sessionLimitExchange(t, conn, cp, request).(*message.SessionEstablishmentResponse)
			if pipelineCause(t, response) != ie.CauseRequestAccepted {
				t.Fatal("establishment rejected")
			}
			seid, err := response.UPFSEID.FSEID()
			if err != nil {
				t.Fatal(err)
			}
			conn.stateMu.Lock()
			assoc := conn.associationByID(node)
			conn.observeRecovery(node, time.Unix(1800000000, 0))
			heartbeat := message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), nil)
			_, err = conn.prepareRequestContext(heartbeat, cp.LocalAddr().(*net.UDPAddr), false, conn.socket(), assoc.Addr, assoc, 0)
			conn.stateMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			conn.Handle(protocolWire(t, message.NewHeartbeatResponse(heartbeat.Sequence(), ie.NewRecoveryTimeStamp(time.Unix(1800000100, 0)))), cp.LocalAddr().(*net.UDPAddr))
			conn.stateMu.RLock()
			survived := assoc.Sessions[seid.SEID] != nil
			conn.stateMu.RUnlock()
			if survived {
				t.Fatal("heartbeat response left its dual-stack entity's session active")
			}
		})
	}
}

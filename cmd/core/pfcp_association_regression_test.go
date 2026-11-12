package core

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func associationSetup(t *testing.T, conn *PfcpConnection, addr string, seq uint32, extra ...*ie.IE) *message.AssociationSetupResponse {
	t.Helper()
	ies := []*ie.IE{ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))}
	ies = append(ies, extra...)
	response, _, err := HandlePfcpAssociationSetupRequest(conn, message.NewAssociationSetupRequest(seq, ies...), addr)
	if err != nil {
		t.Fatal(err)
	}
	return response.(*message.AssociationSetupResponse)
}
func TestAssociationReplacementAndRetention(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "delete", true: "retain"}[retain], func(t *testing.T) {
			conn := newProtocolConnection(t)
			associationSetup(t, conn, "127.0.0.1", 1)
			old := conn.GetAssociation("127.0.0.1")
			old.Sessions[3] = NewSession(3, 4, "", "", false)
			var extra []*ie.IE
			if retain {
				extra = append(extra, ie.NewPFCPSessionRetentionInformation())
			}
			reply := associationSetup(t, conn, "127.0.0.2", 2, extra...)
			fresh := conn.GetAssociation("127.0.0.2")
			if fresh == nil || fresh == old || conn.GetAssociation("127.0.0.1") != nil {
				t.Fatal("same Node ID did not replace association at new address")
			}
			if got := len(fresh.Sessions); (retain && got != 1) || (!retain && got != 0) {
				t.Fatalf("retained session count=%d", got)
			}
			if retain && !reply.PFCPASRspFlags.HasPSREI() {
				t.Fatal("retention response missing PSREI")
			}
		})
	}
}
func TestAssociationReleaseAlwaysAccepted(t *testing.T) {
	conn := newProtocolConnection(t)
	response, _, err := HandlePfcpAssociationReleaseRequest(conn, message.NewAssociationReleaseRequest(8, ie.NewNodeIDFQDN("synthetic.example")), "127.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	reply := response.(*message.AssociationReleaseResponse)
	cause, _ := reply.Cause.Cause()
	if cause != ie.CauseRequestAccepted {
		t.Fatalf("release cause=%d", cause)
	}
	node, _ := reply.NodeID.NodeID()
	if nodeIDText(node) != "127.0.0.1" {
		t.Fatal("release response must identify local node")
	}
}
func TestHeartbeatRestartAndStaleTimestamp(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	heartbeat := func(seconds int64) message.Message {
		t.Helper()
		reply, _, err := HandlePfcpHeartbeatRequest(conn, message.NewHeartbeatRequest(3, ie.NewRecoveryTimeStamp(time.Unix(seconds, 0))), assoc.Addr)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	heartbeat(1700000000)
	assoc.Sessions[3] = NewSession(3, 4, "", "", false)
	heartbeat(1700000010)
	if len(assoc.Sessions) != 0 {
		t.Fatal("restart retained stale sessions")
	}
	assoc.Sessions[5] = NewSession(5, 6, "", "", false)
	if heartbeat(1700000000) != nil || len(assoc.Sessions) != 1 {
		t.Fatal("stale heartbeat was not discarded without changing sessions")
	}
}
func TestAssociationTrafficConcurrentReaders(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := transactionPeer(t)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(uint32(i+1), ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))), peer.LocalAddr().(*net.UDPAddr))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = conn.GetSessionCount()
			_ = conn.GetAssiciationCount()
		}
	}()
	wg.Wait()
}

func TestAssociationSnapshotIsIndependent(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	session := NewSession(3, 4, "", "", false)
	session.PDRs[1] = SPDRInfo{Ipv4: net.IPv4(192, 0, 2, 1), PdrInfo: ebpf.PdrInfo{SdfFilter: []ebpf.SdfFilter{{SrcAddress: ebpf.IpWMask{Ip: net.IPv4(192, 0, 2, 2)}}}}}
	conn.GetAssociation("127.0.0.1").Sessions[3] = session
	copy := conn.AssociationSnapshots()["synthetic.example"]
	pdr := copy.Sessions[3].PDRs[1]
	pdr.Ipv4[0]++
	pdr.PdrInfo.SdfFilter[0].SrcAddress.Ip[0]++
	delete(copy.Sessions, 3)
	original := session.PDRs[1]
	if !original.Ipv4.Equal(net.IPv4(192, 0, 2, 1)) || !original.PdrInfo.SdfFilter[0].SrcAddress.Ip.Equal(net.IPv4(192, 0, 2, 2)) {
		t.Fatal("snapshot aliases live IP/filter storage")
	}
	if conn.GetSessionCount() != 1 {
		t.Fatal("snapshot aliases live session index")
	}
}

type associationCleanupMaps struct {
	MapOperationsMock
	deletedURRs []uint32
}

func (maps *associationCleanupMaps) DeleteUrr(id uint32) (ebpf.UrrInfo, error) {
	maps.deletedURRs = append(maps.deletedURRs, id)
	return ebpf.UrrInfo{}, nil
}
func TestAssociationCleanupRemovesUsageRules(t *testing.T) {
	conn := newProtocolConnection(t)
	maps := &associationCleanupMaps{}
	conn.mapOperations = maps
	associationSetup(t, conn, "127.0.0.1", 1)
	session := NewSession(3, 4, "", "", false)
	session.URRs[1] = SUrrInfo{GlobalId: 9}
	conn.GetAssociation("127.0.0.1").Sessions[3] = session
	conn.DeleteAssociation("127.0.0.1")
	conn.serviceHeartbeats(time.Now())
	if len(maps.deletedURRs) != 1 || maps.deletedURRs[0] != 9 {
		t.Fatalf("removed URR IDs=%v", maps.deletedURRs)
	}
}
func TestAssociationReleaseUsesNodeID(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	reply, _, err := HandlePfcpAssociationReleaseRequest(conn, message.NewAssociationReleaseRequest(2, ie.NewNodeIDFQDN("other.example")), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cause, _ := reply.(*message.AssociationReleaseResponse).Cause.Cause()
	if cause != ie.CauseRequestAccepted || conn.GetAssiciationCount() != 1 {
		t.Fatal("release of an unknown Node ID destroyed a different association")
	}
}
func TestPartialRetentionUsesSessionControlEntity(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	peer := transactionPeer(t)
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeSessionEstablishmentRequest: func(conn *PfcpConnection, msg message.Message, addr string) (message.Message, bool, error) {
		conn.GetAssociation(addr).Sessions[3] = NewSession(3, 4, "", "", false)
		return message.NewSessionEstablishmentResponse(4, msg.Sequence(), ie.NewNodeIDFQDN("upf.example"), ie.NewCause(ie.CauseRequestAccepted), ie.NewFSEID(3, net.ParseIP("127.0.0.1"), nil)), false, nil
	}}
	request := message.NewSessionEstablishmentRequest(0, 2, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(4, net.ParseIP("192.0.2.10"), nil), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0))), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	_ = readTransaction(t, peer)
	response := associationSetup(t, conn, "127.0.0.1", 3, ie.NewPFCPSessionRetentionInformation(ie.NewCPPFCPEntityIPAddress(net.ParseIP("192.0.2.10"), nil)))
	if conn.GetSessionCount() != 1 || !response.PFCPASRspFlags.HasPSREI() {
		t.Fatal("retention ignored the CP F-SEID's PFCP entity address")
	}
}

func TestHeartbeatSourceEntityRestartIsSelective(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	assoc := conn.GetAssociation("127.0.0.1")
	assoc.Sessions[3] = NewSession(3, 4, "", "", false)
	assoc.sessionEntities[3] = "192.0.2.10"
	conn.addressReference(assoc, "192.0.2.10", 1)
	assoc.Sessions[5] = NewSession(5, 6, "", "", false)
	assoc.sessionEntities[5] = "192.0.2.11"
	conn.addressReference(assoc, "192.0.2.11", 1)
	for _, stamp := range []int64{1700000000, 1700000010} {
		_, _, err := HandlePfcpHeartbeatRequest(conn, message.NewHeartbeatRequest(7, ie.NewRecoveryTimeStamp(time.Unix(stamp, 0)), ie.NewSourceIPAddress(net.ParseIP("192.0.2.10"), nil, 0)), assoc.Addr)
		if err != nil {
			t.Fatal(err)
		}
	}
	if assoc.Sessions[3] != nil || assoc.Sessions[5] == nil {
		t.Fatal("NAT Source IP heartbeat restart did not remove only the affected entity's sessions")
	}
	if !assoc.RecoveryTimestamp.IsZero() {
		t.Fatal("entity timestamp was attributed to the transport source")
	}
}

func TestDifferentNodeCoexistsAtOccupiedPeerAddress(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	old := conn.GetAssociation("127.0.0.1")
	old.Sessions[3] = NewSession(3, 4, "", "", false)
	reply, _, _ := HandlePfcpAssociationSetupRequest(conn, message.NewAssociationSetupRequest(2, ie.NewNodeIDFQDN("different.example"), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp)), old.Addr)
	cause, _ := reply.(*message.AssociationSetupResponse).Cause.Cause()
	if cause != ie.CauseRequestAccepted || conn.associationByID(old.ID) != old || len(old.Sessions) != 1 || conn.GetAssiciationCount() != 2 {
		t.Fatal("a different Node ID did not coexist without changing another node's sessions")
	}
}

func (maps *associationCleanupMaps) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	return &mapTransactionMock{ForwardingPlaneController: maps}, nil
}

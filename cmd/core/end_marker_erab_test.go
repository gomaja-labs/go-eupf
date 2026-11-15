package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 clause 5.17.3 (EPS to 5GS): one PDR and one QER per
// E-RAB, all associated with one per-PDU-session forwarding FAR.
// TS 29.281 V19.2.0 clause 7.3.2.3: End Markers on that 5GS forwarding
// tunnel carry the QFI of one QoS flow mapped to the same E-RAB.
func TestGeneratedMarkerCoversEveryERAB(t *testing.T) {
	remote := net.IPv4(127, 0, 0, 30)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: remote, Port: 2152})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	conn := newProtocolConnection(t)
	conn.ResourceManager, _ = service.NewResourceManager("", 32)
	associationSetup(t, conn, "127.0.0.1", 1)
	req := message.NewSessionEstablishmentRequest(0, 2, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(77, net.IPv4(127, 0, 0, 1), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DstInterfaceAccess),
			ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN3ForDataForwarding), ie.NewOuterHeaderCreation(0x100, 200, remote.String(), "", 0, 0, 0))),
		ie.NewCreateQER(ie.NewQERID(1), ie.NewGateStatus(0, 0), ie.NewQFI(5)),
		ie.NewCreateQER(ie.NewQERID(2), ie.NewGateStatus(0, 0), ie.NewQFI(9)),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1), ie.NewQERID(1)),
		ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(2), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0)),
			ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1), ie.NewQERID(2)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	established := reply.(*message.SessionEstablishmentResponse)
	if cause, _ := established.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("establishment cause %d", cause)
	}
	fseid, err := established.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	mod := message.NewSessionModificationRequest(fseid.SEID, 3, ie.NewUpdateFAR(ie.NewFARID(1),
		ie.NewUpdateForwardingParameters(ie.NewOuterHeaderCreation(0x100, 201, remote.String(), "", 0, 0, 0), ie.NewPFCPSMReqFlags(2))))
	reply, _, err = HandlePfcpSessionModificationRequest(conn, mod, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := reply.(*message.SessionModificationResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("modification cause %d", cause)
	}
	qfis := map[byte]int{}
	count := 0
	buf := make([]byte, 64)
	for {
		if err := peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n == 16 && buf[1] == 254 && binary.BigEndian.Uint32(buf[4:8]) == 200 && buf[11] == 0x85 {
			qfis[buf[14]&0x3f]++
			count++
		}
	}
	if count != 2 || qfis[5] != 1 || qfis[9] != 1 {
		t.Fatalf("End Markers on the shared forwarding tunnel carried QFIs %v; each E-RAB (QFI 5, QFI 9) needs one", qfis)
	}
}

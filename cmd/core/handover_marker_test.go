package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 clauses 5.17.3, 5.6.3 and 8.2.64.
func TestHandoverContainerDeletionSurvivesPDRTransactions(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.ResourceManager, _ = service.NewResourceManager("", 32)
	associationSetup(t, conn, "127.0.0.1", 1)
	req := message.NewSessionEstablishmentRequest(0, 2, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(77, net.IPv4(127, 0, 0, 1), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1), ie.NewOuterHeaderCreation(0x100, 200, "127.0.0.30", "", 0, 0, 0))),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0), ie.NewQFI(9)), ie.NewOuterHeaderRemoval(0, 0xff), ie.NewFARID(1)))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionEstablishmentResponse)
	if cause, _ := response.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatal(cause)
	}
	seid, err := response.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	session := conn.GetAssociation("127.0.0.1").Sessions[seid.SEID]
	if session.PDRs[1].PdrInfo.GtpExtensionHeaderDeletion != 1 {
		t.Fatal("deletion instruction or spare-bit handling lost")
	}
	for index, removal := range []*ie.IE{nil, ie.NewOuterHeaderRemoval(6, 0), ie.NewOuterHeaderRemoval(0, 1), ie.New(ie.OuterHeaderRemoval, nil)} {
		fields := []*ie.IE{ie.NewPDRID(1)}
		if removal != nil {
			fields = append(fields, removal)
		}
		updates := []*ie.IE{ie.NewUpdatePDR(fields...)}
		if index == 3 {
			updates = append(updates, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
		}
		reply, _, err = HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(seid.SEID, uint32(index+3), updates...), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if cause, _ := reply.(*message.SessionModificationResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
			t.Fatal(cause)
		}
		session = conn.GetAssociation("127.0.0.1").Sessions[seid.SEID]
		want := uint8(0)
		if index == 0 || index == 2 {
			want = 1
		}
		if session.PDRs[1].PdrInfo.GtpExtensionHeaderDeletion != want {
			t.Fatalf("update %d lost deletion semantics", index)
		}
	}
}

func TestGeneratedHandoverMarkerCarriesOneMappedFlow(t *testing.T) {
	conn := newProtocolConnection(t)
	old, next := NewSession(1, 2, "", "", false), NewSession(1, 2, "", "", false)
	old.NewFar(1, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1})
	f := old.FARs[1]
	f.InterfaceType, f.InterfaceTypePresent = ie.TGPPInterfaceTypeN3ForDataForwarding, true
	old.FARs[1] = f
	next.NewFar(1, 2, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 201, RemoteIP: 1})
	fid := uint32(1)
	old.PutPDR(1, SPDRInfo{FARID: &fid, QERIDs: []uint32{1}, PdrID: 1})
	old.NewQer(1, 1, ebpf.QerInfo{Qfi: 9, QFIPresent: true, RQI: 1})
	req := message.NewSessionModificationRequest(1, 1, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(2))))
	batch, err := conn.prepareEndMarkers(req, old, next)
	if err != nil {
		t.Fatal(err)
	}
	if batch == nil {
		t.Fatal("missing handover marker")
	}
	defer batch.release()
	// Decode actual UDP output independently of the marker's Go representation.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 31), Port: 2152})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	packet := batch.packets[0]
	packet.destination = peer.LocalAddr().(*net.UDPAddr).IP
	if err := sendEndMarker(packet); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 64)
	n, from, err := peer.ReadFromUDP(wire)
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 || wire[0] != 0x34 || wire[1] != 254 || wire[11] != 0x85 || wire[12] != 1 || wire[13] != 0 || wire[14] != 9 || wire[15] != 0 {
		t.Fatal("generated marker lacks mapped DL container")
	}
	if from.Port != int(gtpTunnelSourcePort(200)) {
		t.Fatal("wrong old tunnel source port")
	}
}

func TestHandoverMarkerMappingDistinguishesZeroAndAbsentQFI(t *testing.T) {
	for _, tc := range []struct {
		name                                            string
		label                                           uint8
		present, deletion, inactive, wantQFI, wantError bool
	}{
		{name: "zero QFI", label: ie.TGPPInterfaceTypeN3ForDataForwarding, present: true, wantQFI: true},
		{name: "absent QFI", label: ie.TGPPInterfaceTypeN9DataForwarding, wantError: true},
		{name: "EPS output", label: ie.TGPPInterfaceTypeN3ForDataForwarding, deletion: true},
		{name: "ordinary old tunnel", label: ie.TGPPInterfaceTypeN33GPPAccess, present: true},
		{name: "inactive forwarding tunnel", label: ie.TGPPInterfaceTypeN9DataForwarding, inactive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSession(1, 2, "", "", false)
			fid := uint32(1)
			f := SFarInfo{InterfaceType: tc.label, InterfaceTypePresent: true}
			if !tc.inactive {
				p := SPDRInfo{PdrID: 1, FARID: &fid, QERIDs: []uint32{1}}
				if tc.deletion {
					p.PdrInfo.GtpExtensionHeaderDeletion = 1
				}
				s.PutPDR(1, p)
			}
			s.NewQer(1, 1, ebpf.QerInfo{QFIPresent: tc.present, Qfi: 0})
			qfi, present, active, err := handoverMarkerQFI(s, fid, f)
			if (err != nil) != tc.wantError || qfi != 0 || present != tc.wantQFI || active == tc.inactive {
				t.Fatalf("qfi=%d present=%t active=%t err=%v", qfi, present, active, err)
			}
			if tc.wantError {
				fields := ruleFailureIEs(err)
				cause, _ := fields[0].Cause()
				if cause != ie.CauseConditionalIEMissing {
					t.Fatalf("cause %d", cause)
				}
			}
		})
	}
}

// TS 29.244 V20.1.0 table 8.2.64-1 NOTE 7 distinguishes unknown
// descriptions from assigned header formats outside this implementation.
func TestUnknownOuterRemovalUsesMandatoryIEIncorrect(t *testing.T) {
	for _, description := range []uint8{9, 255} {
		fields := ruleFailureIEs(validateOuterRemoval(ie.NewOuterHeaderRemoval(description, 0)))
		cause, err := fields[0].Cause()
		if err != nil || cause != ie.CauseMandatoryIEIncorrect {
			t.Fatalf("description %d: cause=%d err=%v", description, cause, err)
		}
	}
	for _, description := range []uint8{1, 2, 3, 4, 5, 7, 8} {
		fields := ruleFailureIEs(validateOuterRemoval(ie.NewOuterHeaderRemoval(description, 0)))
		cause, err := fields[0].Cause()
		if err != nil || cause != ie.CauseServiceNotSupported {
			t.Fatalf("assigned unsupported description %d: cause=%d err=%v", description, cause, err)
		}
	}
}

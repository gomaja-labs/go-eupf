package core

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 table 7.5.4.3-1 and clause 5.3.2;
// TS 29.281 V19.2.0 clauses 4.4.2.6, 4.4.3.6 and 7.3.2.
func TestEndMarkerOnChangedDownstreamFTEID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags byte
		teid  uint32
		want  bool
	}{
		{"requested", 2, 201, true}, {"unchanged", 2, 200, false}, {"not requested", 0, 201, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			remote := net.IPv4(127, 0, 0, 30)
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: remote, Port: 2152})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			conn := newProtocolConnection(t)
			associationSetup(t, conn, "127.0.0.1", 1)
			assocID := "127.0.0.1"
			s := NewSession(2, 42, "", "", false)
			s.NewFar(9, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: binary.LittleEndian.Uint32(remote.To4())})
			conn.GetAssociation(assocID).Sessions[2] = s
			parameters := []*ie.IE{ie.NewOuterHeaderCreation(0x100, tc.teid, remote.String(), "", 0, 0, 0)}
			if tc.flags != 0 {
				parameters = append(parameters, ie.NewPFCPSMReqFlags(tc.flags))
			}
			request := message.NewSessionModificationRequest(2, 1, ie.NewUpdateFAR(ie.NewFARID(9), ie.NewUpdateForwardingParameters(parameters...)))
			reply, _, err := HandlePfcpSessionModificationRequest(conn, request, assocID)
			if err != nil {
				t.Fatal(err)
			}
			cause, err := reply.(*message.SessionModificationResponse).Cause.Cause()
			if err != nil || cause != ie.CauseRequestAccepted {
				t.Fatalf("cause=%d err=%v", cause, err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, from, err := peer.ReadFromUDP(buf)
			if !tc.want {
				if err == nil {
					t.Fatal("unexpected End Marker")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n != 8 || buf[0] != 0x30 || buf[1] != 254 || binary.BigEndian.Uint16(buf[2:4]) != 0 || binary.BigEndian.Uint32(buf[4:8]) != 200 {
				t.Fatalf("invalid End Marker length=%d", n)
			}
			if from.Port != 49352 || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("incorrect tunnel source=%s", from)
			}
		})
	}
}

func TestEndMarkerReservationsAreBoundedAndReturnedOnce(t *testing.T) {
	s := &endMarkerSender{slots: make(chan struct{}, maxPendingEndMarkers)}
	b, err := s.reserve(make([]endMarker, maxPendingEndMarkers))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.reserve([]endMarker{{}}); err == nil {
		t.Fatal("unbounded End Marker admission")
	}
	b.release()
	b.release()
	if len(s.slots) != 0 {
		t.Fatal("reservation leak")
	}
	b, err = s.reserve(make([]endMarker, maxPendingEndMarkers+1))
	if err == nil || b != nil || len(s.slots) != 0 {
		t.Fatal("partial reservation was retained")
	}
}

func TestEndMarkerSharesSourcePortWithEchoProbe(t *testing.T) {
	local := net.IPv4(127, 0, 0, 1)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 31), Port: 2152})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	manager := NewGtpPathManager(net.JoinHostPort(local.String(), "49352"), time.Hour)
	defer manager.Stop()
	result := make(chan error, 1)
	go func() { _, err := manager.sendEcho(peer.LocalAddr().String(), 7); result <- err }()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	n, source, err := peer.ReadFromUDP(data)
	if err != nil || n < 8 || data[1] != 1 {
		t.Fatalf("Echo request n=%d err=%v", n, err)
	}
	echo := append([]byte(nil), data[:n]...)
	if err := sendEndMarker(endMarker{local, peer.LocalAddr().(*net.UDPAddr).IP, 200}); err != nil {
		t.Fatal(err)
	}
	n, _, err = peer.ReadFromUDP(data)
	if err != nil || n != 8 || data[1] != 254 {
		t.Fatalf("End Marker n=%d err=%v", n, err)
	}
	echo[1] = 2
	if _, err := peer.WriteToUDP(echo, source); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestEndMarkerShutdownReturnsQueuedReservations(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	s := &endMarkerSender{slots: make(chan struct{}, maxPendingEndMarkers), jobs: make(chan *endMarkerBatch, maxPendingEndMarkers), stop: make(chan struct{}), done: make(chan struct{})}
	s.send = func(endMarker) error { close(entered); <-release; return nil }
	first, err := s.reserve(make([]endMarker, 2))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.reserve(make([]endMarker, 2))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.submit(); err != nil {
		t.Fatal(err)
	}
	if err := second.submit(); err != nil {
		t.Fatal(err)
	}
	go s.run()
	<-entered
	closed := make(chan struct{})
	go func() { s.close(); close(closed) }()
	// Closing is published before releasing the active send.
	<-s.stop
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("sender shutdown blocked")
	}
	if len(s.slots) != 0 {
		t.Fatalf("shutdown retained %d reservations", len(s.slots))
	}
	if _, err := s.reserve([]endMarker{{}}); err == nil {
		t.Fatal("closed sender admitted a marker")
	}
}

func TestEndMarkerCapabilityAndInterfaceRestrictions(t *testing.T) {
	conn := newProtocolConnection(t)
	if len(conn.featuresOctets) < 2 || conn.featuresOctets[1]&1 == 0 {
		t.Fatal("EMPU not advertised")
	}
	for _, typ := range []uint8{ie.TGPPInterfaceTypeN19, ie.TGPPInterfaceTypeN19mb, ie.TGPPInterfaceTypeN3ForDataForwarding, ie.TGPPInterfaceTypeN9DataForwarding} {
		old, next := NewSession(1, 2, "", "", false), NewSession(1, 2, "", "", false)
		old.NewFar(1, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1})
		f := old.FARs[1]
		f.InterfaceType, f.InterfaceTypePresent = typ, true
		old.FARs[1] = f
		next.NewFar(1, 2, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 201, RemoteIP: 1})
		request := message.NewSessionModificationRequest(1, 1, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(2))))
		batch, err := conn.prepareEndMarkers(request, old, next)
		if batch != nil {
			batch.release()
			t.Fatalf("interface %d created a container-free End Marker", typ)
		}
		if typ == ie.TGPPInterfaceTypeN19 || typ == ie.TGPPInterfaceTypeN19mb {
			if err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatalf("data forwarding interface %d was silently accepted", typ)
		}
	}
}

func TestEndMarkerRetainsTunnelInterfaceThroughRuleTransactions(t *testing.T) {
	conn := newProtocolConnection(t)
	associationSetup(t, conn, "127.0.0.1", 1)
	request := message.NewSessionEstablishmentRequest(0, 2,
		ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(77, net.IPv4(127, 0, 0, 1), nil),
		ie.NewCreateFAR(ie.NewFARID(9), ie.NewApplyAction(2), ie.NewForwardingParameters(
			ie.NewDestinationInterface(ie.DstInterfaceAccess), ie.NewTGPPInterfaceType(ie.TGPPInterfaceTypeN3ForDataForwarding), ie.NewOuterHeaderCreation(0x100, 200, "127.0.0.30", "", 0, 0, 0))))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	established := reply.(*message.SessionEstablishmentResponse)
	if cause, _ := established.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatal(cause)
	}
	fseid, err := established.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	assoc := conn.GetAssociation("127.0.0.1")
	original := assoc.Sessions[fseid.SEID].FARs[9]
	if !original.InterfaceTypePresent || original.InterfaceType != ie.TGPPInterfaceTypeN3ForDataForwarding {
		t.Fatal("creation discarded the tunnel interface")
	}
	result, _, err := HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(fseid.SEID, 3,
		ie.NewUpdateFAR(ie.NewFARID(9), ie.NewUpdateForwardingParameters(ie.NewOuterHeaderCreation(0x100, 201, "127.0.0.30", "", 0, 0, 0), ie.NewPFCPSMReqFlags(2)))), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := result.(*message.SessionModificationResponse).Cause.Cause(); cause != ie.CauseServiceNotSupported {
		t.Fatalf("unsupported data-forwarding switch cause=%d", cause)
	}
	if got := assoc.Sessions[fseid.SEID].FARs[9]; got != original {
		t.Fatal("rejected marker switch changed the FAR")
	}
	result, _, err = HandlePfcpSessionModificationRequest(conn, message.NewSessionModificationRequest(fseid.SEID, 4,
		ie.NewUpdateFAR(ie.NewFARID(9), ie.NewUpdateForwardingParameters(ie.New(ie.TGPPInterfaceType, nil)))), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cause, _ := result.(*message.SessionModificationResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatal(cause)
	}
	if assoc.Sessions[fseid.SEID].FARs[9].InterfaceTypePresent {
		t.Fatal("null interface label was not removed")
	}
}

func TestEndMarkerUsesEveryOldTunnelSource(t *testing.T) {
	for _, tc := range []struct {
		name            string
		native, relayed bool
		want            map[string]bool
	}{
		{"native", true, false, map[string]bool{"127.0.0.1": true}},
		{"N9 relay", false, true, map[string]bool{"127.0.0.9": true}},
		{"shared FAR", true, true, map[string]bool{"127.0.0.1": true, "127.0.0.9": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			conn.n9Address = net.IPv4(127, 0, 0, 9)
			old, next := NewSession(1, 2, "", "", false), NewSession(1, 2, "", "", false)
			fid := uint32(9)
			old.NewFar(fid, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1, DestinationInterface: ie.DstInterfaceAccess, DestinationInterfacePresent: true})
			next.NewFar(fid, 2, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 201, RemoteIP: 1})
			if tc.native {
				old.PutPDR(1, SPDRInfo{PdrID: 1, FARID: &fid, SourceInterface: ie.SrcInterfaceCore})
			}
			if tc.relayed {
				old.PutPDR(2, SPDRInfo{PdrID: 2, FARID: &fid, Teid: 10, SourceInterface: ie.SrcInterfaceCore})
			}
			request := message.NewSessionModificationRequest(1, 1, ie.NewUpdateFAR(ie.NewFARID(fid), ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(2))))
			batch, err := conn.prepareEndMarkers(request, old, next)
			if err != nil {
				t.Fatal(err)
			}
			if batch == nil {
				t.Fatal("missing markers")
			}
			defer batch.release()
			got := make(map[string]bool)
			for _, packet := range batch.packets {
				got[packet.source.String()] = true
			}
			if len(batch.packets) != len(tc.want) || len(got) != len(tc.want) {
				t.Fatalf("marker sources=%v want=%v", got, tc.want)
			}
			for address := range tc.want {
				if !got[address] {
					t.Fatalf("marker sources=%v missing %s", got, address)
				}
			}
		})
	}
}

func TestSpareTunnelInterfaceDoesNotReplaceKnownRole(t *testing.T) {
	// TS 29.244 V20.1.0 table 8.2.118-1 and clause 7.6.8.
	for _, value := range []uint8{31, 32, 63} {
		far := SFarInfo{InterfaceType: ie.TGPPInterfaceTypeN19, InterfaceTypePresent: true}
		if err := retainFarInterfaceType(ie.NewTGPPInterfaceType(value), &far); err != nil {
			t.Fatal(err)
		}
		want := value
		if value >= 32 {
			want = ie.TGPPInterfaceTypeN19
		}
		if !far.InterfaceTypePresent || far.InterfaceType != want {
			t.Fatalf("interface %d replaced role with %d; want %d", value, far.InterfaceType, want)
		}
	}
}

type tunnelSourceMaps struct {
	MapOperationsMock
	n3, n9 net.IP
	err    error
}

func (m *tunnelSourceMaps) TunnelSourceAddresses() (net.IP, net.IP, error) {
	return m.n3, m.n9, m.err
}

// TS 29.281 V19.2.0 clause 4.4.3.6: advertised F-TEID addresses
// need not be local and must never select an End Marker's source.
func TestEndMarkerSourcesFollowProgrammedAddresses(t *testing.T) {
	for _, endpoint := range []string{N4PFCPKeyName, SxaPFCPKeyName, SxbPFCPKeyName} {
		t.Run(endpoint, func(t *testing.T) {
			conn := newProtocolConnection(t)
			conn.n3Address, conn.n9Address = net.ParseIP("198.51.100.10"), net.ParseIP("198.51.100.11")
			maps := &tunnelSourceMaps{n3: net.ParseIP("127.0.0.1"), n9: net.ParseIP("127.0.0.9")}
			conn.mapOperations = maps
			old, next := NewSession(1, 2, "", "", false), NewSession(1, 2, "", "", false)
			old.NewFar(1, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1})
			next.NewFar(1, 2, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 201, RemoteIP: 1})
			id := uint32(1)
			old.PutPDR(1, SPDRInfo{FARID: &id})
			old.PutPDR(2, SPDRInfo{FARID: &id, Teid: 100})
			request := message.NewSessionModificationRequest(1, 1, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(2))))
			for _, address := range []string{"127.0.0.1", "127.0.0.2"} {
				maps.n3 = net.ParseIP(address) // Same shared configuration changed by REST.
				batch, err := conn.prepareEndMarkers(request, old, next)
				if err != nil || batch == nil {
					t.Fatalf("prepare: batch=%v err=%v", batch, err)
				}
				batch.release()
				got := map[string]bool{}
				for _, packet := range batch.packets {
					got[packet.source.String()] = true
				}
				if len(batch.packets) != 2 || !got[address] || !got["127.0.0.9"] {
					t.Fatalf("sources=%v; want local %s and 127.0.0.9", got, address)
				}
			}
		})
	}
}

func TestEndMarkerSourceReadFailureRejectsPathSwitch(t *testing.T) {
	conn := newProtocolConnection(t)
	sentinel := errors.New("dataplane read failed")
	conn.mapOperations = &tunnelSourceMaps{err: sentinel}
	old, next := NewSession(1, 2, "", "", false), NewSession(1, 2, "", "", false)
	old.NewFar(1, 1, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, RemoteIP: 1})
	next.NewFar(1, 2, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 201, RemoteIP: 1})
	request := message.NewSessionModificationRequest(1, 1, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewPFCPSMReqFlags(2))))
	batch, err := conn.prepareEndMarkers(request, old, next)
	if batch != nil || !errors.Is(err, sentinel) {
		t.Fatalf("source failure admitted path switch: batch=%v err=%v", batch, err)
	}
}

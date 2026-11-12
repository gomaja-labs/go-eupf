package core

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func newProtocolConnection(t *testing.T) *PfcpConnection {
	t.Helper()
	old := config.Conf
	config.Conf = config.UpfConfig{}
	t.Cleanup(func() { config.Conf = old })
	conn, err := NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", &MapOperationsMock{}, nil, nil, nil, DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}

func protocolWire(t *testing.T, msg message.Message) []byte {
	t.Helper()
	b := make([]byte, msg.MarshalLen())
	if err := msg.MarshalTo(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// Drive the same socket receive and dispatch functions as PfcpConnection.Run.
func exchangeProtocolDatagram(t *testing.T, conn *PfcpConnection, wire []byte) message.Message {
	t.Helper()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := client.WriteToUDP(wire, conn.udpConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if err := conn.udpConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, peer, err := conn.Receive(buffer)
	if err != nil {
		t.Fatal(err)
	}
	conn.Handle(buffer[:n], peer)
	if err := client.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, _, err = client.ReadFromUDP(buffer)
	if err != nil {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			return nil
		}
		t.Fatal(err)
	}
	reply, err := message.Parse(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestProtocolDecodeErrors(t *testing.T) {
	setup := func(children ...*ie.IE) []byte {
		return protocolWire(t, message.NewAssociationSetupRequest(0x123456, children...))
	}
	node := ie.NewNodeIDFQDN("synthetic.example")
	stamp := ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))
	unsupported := setup(node, stamp)
	unsupported[0] = 0x40
	badIE := setup(node, stamp)
	badIE = append(badIE, 0, byte(ie.NodeID), 0, 8, 0)
	badIE[2], badIE[3] = byte((len(badIE)-4)>>8), byte(len(badIE)-4)
	tests := []struct {
		name      string
		wire      []byte
		response  uint8
		cause     uint8
		offending ie.IEType
	}{
		// TS 29.244 V20.1.0 clauses 7.6.2, 7.6.3, 7.6.4, 7.6.6-7.6.8.
		{"unsupported-version", unsupported, message.MsgTypeVersionNotSupportedResponse, 0, 0},
		{"one-octet-unsupported-version", []byte{0x40}, message.MsgTypeVersionNotSupportedResponse, 0, 0},
		{"incomplete-header", []byte{0x20, 5, 0, 4}, 0, 0, 0},
		{"unknown-type", []byte{0x20, 200, 0, 4, 0, 0, 1, 0}, 0, 0, 0},
		{"missing-node", setup(stamp), message.MsgTypeAssociationSetupResponse, ie.CauseMandatoryIEMissing, ie.NodeID},
		{"missing-timestamp", setup(node), message.MsgTypeAssociationSetupResponse, ie.CauseMandatoryIEMissing, ie.RecoveryTimeStamp},
		{"incorrect-node", setup(ie.New(ie.NodeID, []byte{15, 0}), stamp), message.MsgTypeAssociationSetupResponse, ie.CauseMandatoryIEIncorrect, ie.NodeID},
		{"incorrect-timestamp", setup(node, ie.New(ie.RecoveryTimeStamp, []byte{1})), message.MsgTypeAssociationSetupResponse, ie.CauseMandatoryIEIncorrect, ie.RecoveryTimeStamp},
		{"truncated-ie", badIE, message.MsgTypeAssociationSetupResponse, ie.CauseInvalidLength, ie.NodeID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			reply := exchangeProtocolDatagram(t, conn, tt.wire)
			if tt.response == 0 {
				if reply != nil {
					t.Fatalf("unexpected response %T", reply)
				}
				return
			}
			if reply == nil || reply.MessageType() != tt.response {
				t.Fatalf("response = %T, want type %d", reply, tt.response)
			}
			if len(tt.wire) >= 8 && reply.Sequence() != 0x123456 {
				t.Fatalf("sequence %x", reply.Sequence())
			}
			if tt.cause == 0 {
				return
			}
			response := reply.(*message.AssociationSetupResponse)
			cause, err := response.Cause.Cause()
			if err != nil || cause != tt.cause {
				t.Fatalf("cause %d: %v", cause, err)
			}
			var offendingIE *ie.IE
			for _, child := range response.OtherIEs {
				if child.Type == ie.OffendingIE {
					offendingIE = child
					break
				}
			}
			offending, err := offendingIE.OffendingIE()
			if err != nil || offending != tt.offending {
				t.Fatalf("offending %d: %v", offending, err)
			}
			if _, err := response.NodeID.NodeID(); err != nil {
				t.Fatalf("response Node ID: %v", err)
			}
			if _, err := response.RecoveryTimeStamp.RecoveryTimeStamp(); err != nil {
				t.Fatalf("response timestamp: %v", err)
			}
			if len(conn.NodeAssociations) != 0 {
				t.Fatal("invalid request created association")
			}
		})
	}
}

func TestProtocolResponseEncodeFailure(t *testing.T) {
	conn := newProtocolConnection(t)
	conn.pfcpHandlerMap = PfcpHandlerMap{message.MsgTypeAssociationUpdateRequest: func(_ *PfcpConnection, request message.Message, _ string) (message.Message, bool, error) {
		return message.NewAssociationUpdateResponse(request.Sequence(), ie.NewNodeIDFQDN(""), ie.NewCause(ie.CauseRequestAccepted)), false, nil
	}}
	request := message.NewAssociationUpdateRequest(37, ie.NewNodeIDFQDN("synthetic.example"))
	reply := exchangeProtocolDatagram(t, conn, protocolWire(t, request))
	response, ok := reply.(*message.AssociationUpdateResponse)
	if !ok {
		t.Fatalf("response %T", reply)
	}
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseSystemFailure {
		t.Fatalf("cause %d: %v", cause, err)
	}
	if response.Sequence() != 37 {
		t.Fatalf("sequence %d", response.Sequence())
	}
	if _, err := response.NodeID.NodeID(); err != nil {
		t.Fatal(err)
	}
}

func TestProtocolNullRuleReferences(t *testing.T) {
	for _, name := range []string{"absent", "null-urr", "null-qer", "null-removes-entire-list"} {
		t.Run(name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			association := NewNodeAssociation("synthetic.example", "127.0.0.1")
			session := NewSession(11, 22, "", "", false)
			session.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 10, PdrInfo: ebpf.PdrInfo{Urr1Id: 21, Urr2Id: 22, QerId: 31}})
			session.NewUrr(2, 42, ebpf.UrrInfo{})
			association.Sessions[11] = session
			conn.NodeAssociations["127.0.0.1"] = association
			children := []*ie.IE{ie.NewPDRID(1)}
			switch name {
			case "null-urr":
				children = append(children, ie.New(ie.URRID, nil))
			case "null-qer":
				children = append(children, ie.New(ie.QERID, nil))
			case "null-removes-entire-list":
				children = append(children, ie.New(ie.URRID, nil), ie.NewURRID(2))
			}
			// TS 29.244 V20.1.0 clauses 5.6.3 and 8.1.2: null removes, absence preserves.
			reply := exchangeProtocolDatagram(t, conn, protocolWire(t, message.NewSessionModificationRequest(11, 81, ie.NewUpdatePDR(children...))))
			response, ok := reply.(*message.SessionModificationResponse)
			if !ok {
				t.Fatalf("response %T", reply)
			}
			cause, err := response.Cause.Cause()
			if err != nil || cause != ie.CauseRequestAccepted {
				t.Fatalf("cause %d: %v", cause, err)
			}
			got := session.PDRs[1].PdrInfo
			wantUrr1, wantUrr2, wantQer := uint32(21), uint32(22), uint32(31)
			if name == "null-urr" || name == "null-removes-entire-list" {
				wantUrr1, wantUrr2 = 0, 0
			}
			if name == "null-qer" {
				wantQer = 0
			}
			if got.Urr1Id != wantUrr1 || got.Urr2Id != wantUrr2 || got.QerId != wantQer {
				t.Fatalf("references = (%d,%d,%d), want (%d,%d,%d)", got.Urr1Id, got.Urr2Id, got.QerId, wantUrr1, wantUrr2, wantQer)
			}
			if session.PDRs[1].Teid != 10 || response.SEID() != 22 {
				t.Fatalf("session changed or wrong peer SEID %d", response.SEID())
			}
		})
	}
}

func TestProtocolFirstOccurrenceWins(t *testing.T) {
	conn := newProtocolConnection(t)
	setup := message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("first.example"), ie.NewNodeIDFQDN("last.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))
	reply := exchangeProtocolDatagram(t, conn, protocolWire(t, setup))
	if reply == nil {
		t.Fatal("no association response")
	}
	association := conn.NodeAssociations["127.0.0.1"]
	if association == nil || association.ID != "first.example" {
		t.Fatalf("association %+v", association)
	}
	request := message.NewSessionEstablishmentRequest(0, 2,
		ie.NewNodeIDFQDN("first.example"), ie.NewFSEID(22, net.IPv4(127, 0, 0, 1), nil),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewFARID(99), ie.NewApplyAction(1)),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewFARID(1), ie.NewFARID(99),
			ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewFTEID(1, 10, net.IPv4(127, 0, 0, 1), nil, 0))),
	)
	// TS 29.244 V20.1.0 clause 7.6.10: extra singular occurrences stay ignored.
	reply = exchangeProtocolDatagram(t, conn, protocolWire(t, request))
	response, ok := reply.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Fatalf("response %T", reply)
	}
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("cause %d: %v", cause, err)
	}
	if len(association.Sessions) != 1 {
		t.Fatalf("sessions %d", len(association.Sessions))
	}
	for _, session := range association.Sessions {
		if len(session.FARs) != 1 {
			t.Fatalf("FAR count %d", len(session.FARs))
		}
		if _, ok := session.FARs[1]; !ok {
			t.Fatal("first FAR ID lost")
		}
		if session.PDRs[1].SourceInterface != ie.SrcInterfaceAccess {
			t.Fatal("last source interface used")
		}
	}
}

func TestProtocolMandatoryRuleChildren(t *testing.T) {
	tests := []struct {
		name      string
		rule      *ie.IE
		cause     uint8
		offending ie.IEType
	}{
		{"create-pdr-id", ie.NewCreatePDR(), 66, ie.PDRID},
		{"create-pdr-precedence", ie.NewCreatePDR(ie.NewPDRID(1)), 66, ie.Precedence},
		{"create-pdr-pdi", ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1)), 66, ie.PDI},
		{"create-pdr-source", ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI()), 66, ie.SourceInterface},
		{"update-pdr-id", ie.NewUpdatePDR(), 66, ie.PDRID},
		{"remove-pdr-id", ie.NewRemovePDR(), 66, ie.PDRID},
		{"create-far-id", ie.NewCreateFAR(), 66, ie.FARID},
		{"create-far-action", ie.NewCreateFAR(ie.NewFARID(1)), 66, ie.ApplyAction},
		{"create-far-forwarding", ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2)), 67, ie.ForwardingParameters},
		{"create-bar-id", ie.NewCreateBAR(), 66, ie.BARID},
		{"update-bar-id", ie.NewUpdateBARWithinSessionModificationRequest(), 66, ie.BARID},
		{"remove-bar-id", ie.NewRemoveBAR(), 66, ie.BARID},
		{"create-far-destination", ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters()), 66, ie.DestinationInterface},
		{"update-far-id", ie.NewUpdateFAR(), 66, ie.FARID},
		{"remove-far-id", ie.NewRemoveFAR(), 66, ie.FARID},
		{"create-qer-id", ie.NewCreateQER(), 66, ie.QERID},
		{"create-qer-gate", ie.NewCreateQER(ie.NewQERID(1)), 66, ie.GateStatus},
		{"update-qer-id", ie.NewUpdateQER(), 66, ie.QERID},
		{"remove-qer-id", ie.NewRemoveQER(), 66, ie.QERID},
		{"create-urr-id", ie.NewCreateURR(), 66, ie.URRID},
		{"create-urr-method", ie.NewCreateURR(ie.NewURRID(1)), 66, ie.MeasurementMethod},
		{"create-urr-triggers", ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0)), 66, ie.ReportingTriggers},
		{"update-urr-id", ie.NewUpdateURR(), 66, ie.URRID},
		{"remove-urr-id", ie.NewRemoveURR(), 66, ie.URRID},
		{"truncated-group-child", ie.New(ie.UpdatePDR, []byte{0, byte(ie.PDRID), 0, 2, 0}), 68, ie.PDRID},
		{"short-pdr-id", ie.NewUpdatePDR(ie.New(ie.PDRID, []byte{1})), 69, ie.PDRID},
		{"invalid-action", ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(0)), 69, ie.ApplyAction},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			reply := exchangeProtocolDatagram(t, conn, protocolWire(t, message.NewSessionModificationRequest(11, 45, tt.rule)))
			response, ok := reply.(*message.SessionModificationResponse)
			if !ok {
				t.Fatalf("response %T", reply)
			}
			cause, err := response.Cause.Cause()
			if err != nil || cause != tt.cause {
				t.Fatalf("cause %d: %v", cause, err)
			}
			offending, err := response.OffendingIE.OffendingIE()
			if err != nil || offending != tt.offending {
				t.Fatalf("offending %d: %v", offending, err)
			}
			if response.SEID() != 0 || response.Sequence() != 45 || len(conn.NodeAssociations) != 0 {
				t.Fatal("invalid rejection header or mutated association")
			}
		})
	}
}

func TestProtocolRequestEncodeFailure(t *testing.T) {
	conn := newProtocolConnection(t)
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	}()
	err = conn.SendMessage(message.NewAssociationUpdateRequest(1, ie.NewNodeIDFQDN("")), peer.LocalAddr().(*net.UDPAddr))
	var encode *ie.EncodeError
	if !errors.As(err, &encode) || !errors.Is(err, ie.ErrInvalidValue) {
		t.Fatalf("encoding error %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	_, _, err = peer.ReadFromUDP(buffer)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("unencodable request sent: %v", err)
	}
}

func TestProtocolFallbackResponseTypes(t *testing.T) {
	types := []uint8{message.MsgTypeAssociationSetupResponse, message.MsgTypeAssociationUpdateResponse, message.MsgTypeAssociationReleaseResponse, message.MsgTypeSessionEstablishmentResponse, message.MsgTypeSessionModificationResponse, message.MsgTypeSessionDeletionResponse}
	for _, typ := range types {
		t.Run(fmt.Sprint(typ), func(t *testing.T) {
			conn := newProtocolConnection(t)
			peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := peer.Close(); err != nil {
					t.Error(err)
				}
			}()
			invalid := ie.NewNodeIDFQDN("")
			response := conn.errorResponse(typ, 22, 37, ie.CauseRequestAccepted, invalid)
			err = conn.SendMessage(response, peer.LocalAddr().(*net.UDPAddr))
			var encode *ie.EncodeError
			if !errors.As(err, &encode) {
				t.Fatalf("original encoding failure lost: %v", err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65535)
			n, _, err := peer.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := message.Parse(buffer[:n])
			if err != nil {
				t.Fatal(err)
			}
			if decoded.MessageType() != typ || decoded.Sequence() != 37 {
				t.Fatalf("wrong fallback type or sequence: %T %d", decoded, decoded.Sequence())
			}
			var cause, node, stamp *ie.IE
			switch value := decoded.(type) {
			case *message.AssociationSetupResponse:
				cause, node, stamp = value.Cause, value.NodeID, value.RecoveryTimeStamp
			case *message.AssociationUpdateResponse:
				cause, node = value.Cause, value.NodeID
			case *message.AssociationReleaseResponse:
				cause, node = value.Cause, value.NodeID
			case *message.SessionEstablishmentResponse:
				cause, node = value.Cause, value.NodeID
			case *message.SessionModificationResponse:
				cause = value.Cause
			case *message.SessionDeletionResponse:
				cause = value.Cause
			}
			code, err := cause.Cause()
			if err != nil || code != ie.CauseSystemFailure {
				t.Fatalf("fallback cause %d: %v", code, err)
			}
			if typ < 50 || typ == 51 {
				if _, err := node.NodeID(); err != nil {
					t.Fatal(err)
				}
			}
			if typ == 6 {
				if _, err := stamp.RecoveryTimeStamp(); err != nil {
					t.Fatal(err)
				}
			}
			if typ >= 50 && decoded.SEID() != 22 {
				t.Fatalf("peer SEID %d", decoded.SEID())
			}
		})
	}
}

func FuzzProtocolValidation(f *testing.F) {
	for _, msg := range []message.Message{
		message.NewHeartbeatRequest(1),
		message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))),
		message.NewSessionEstablishmentRequest(0, 1),
		message.NewSessionModificationRequest(11, 1, ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0)))),
	} {
		b := make([]byte, msg.MarshalLen())
		if err := msg.MarshalTo(b); err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(_ *testing.T, wire []byte) {
		messages, _ := message.ParseDatagram(wire)
		for _, msg := range messages {
			if msg.IsRequest() {
				_ = validateIncomingRequest(msg)
			}
		}
	})
}

func TestProtocolNullOptionalRuleValues(t *testing.T) {
	for _, name := range []string{"qer", "urr", "far"} {
		t.Run(name, func(t *testing.T) {
			conn := newProtocolConnection(t)
			association := NewNodeAssociation("synthetic.example", "127.0.0.1")
			session := NewSession(11, 22, "", "", false)
			session.NewQer(1, 31, ebpf.QerInfo{GateStatusUL: 1, GateStatusDL: 1, MaxBitrateUL: 1000, MaxBitrateDL: 2000, Qfi: 3})
			session.NewUrr(1, 41, ebpf.UrrInfo{VolumeThreshold: 1000, TimeThreshold: 10})
			session.NewFar(1, 51, ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 10, RemoteIP: 42, TransportLevelMarking: 255})
			association.Sessions[11] = session
			conn.NodeAssociations["127.0.0.1"] = association
			var rule *ie.IE
			switch name {
			case "qer":
				rule = ie.NewUpdateQER(ie.NewQERID(1), ie.New(ie.GateStatus, nil), ie.New(ie.MBR, nil), ie.New(ie.QFI, nil))
			case "urr":
				rule = ie.NewUpdateURR(ie.NewURRID(1), ie.New(ie.VolumeThreshold, nil), ie.New(ie.TimeThreshold, nil))
			case "far":
				rule = ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.New(ie.OuterHeaderCreation, nil), ie.New(ie.TransportLevelMarking, nil)))
			}
			reply := exchangeProtocolDatagram(t, conn, protocolWire(t, message.NewSessionModificationRequest(11, 90, rule)))
			response, ok := reply.(*message.SessionModificationResponse)
			if !ok {
				t.Fatalf("response %T", reply)
			}
			cause, err := response.Cause.Cause()
			if err != nil || cause != ie.CauseRequestAccepted {
				t.Fatalf("cause %d: %v", cause, err)
			}
			switch name {
			case "qer":
				info := session.QERs[1].QerInfo
				if info.GateStatusUL != 0 || info.GateStatusDL != 0 || info.MaxBitrateUL != 0 || info.MaxBitrateDL != 0 || info.Qfi != 0 {
					t.Fatalf("QER values retained: %+v", info)
				}
			case "urr":
				info := session.URRs[1].UrrInfo
				if info.VolumeThreshold != 0 || info.TimeThreshold != 0 {
					t.Fatalf("URR values retained: %+v", info)
				}
			case "far":
				info := session.FARs[1].FarInfo
				if info.OuterHeaderCreation != 0 || info.Teid != 0 || info.RemoteIP != 0 || info.TransportLevelMarking != 0 || info.Action != 2 {
					t.Fatalf("FAR values retained or action changed: %+v", info)
				}
			}
		})
	}
}

func TestProtocolExtendablePDRID(t *testing.T) {
	conn := newProtocolConnection(t)
	association := NewNodeAssociation("synthetic.example", "127.0.0.1")
	session := NewSession(11, 22, "", "", false)
	session.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 10})
	association.Sessions[11] = session
	conn.NodeAssociations["127.0.0.1"] = association
	// TS 29.244 V20.1.0 Table 8.1.2-1 marks PDR ID extendable: ignore trailing unknown octets.
	request := message.NewSessionModificationRequest(11, 91, ie.NewUpdatePDR(ie.New(ie.PDRID, []byte{0, 1, 2})))
	reply := exchangeProtocolDatagram(t, conn, protocolWire(t, request))
	response, ok := reply.(*message.SessionModificationResponse)
	if !ok {
		t.Fatalf("response %T", reply)
	}
	cause, err := response.Cause.Cause()
	if err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("cause %d: %v", cause, err)
	}
	if session.PDRs[1].Teid != 10 || response.SEID() != 22 || response.Sequence() != 91 {
		t.Fatal("extended ID changed rule or response header")
	}
}

package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestOriginatingProceduresReceiveOneTerminalResult(t *testing.T) {
	for _, procedure := range []string{"heartbeat", "report", "setup", "sxa_setup", "sxb_setup", "update"} {
		for _, outcome := range []string{"accepted", "rejected", "invalid_length", "invalid_ie", "missing_ie", "timeout", "canceled"} {
			t.Run(procedure+"/"+outcome, func(t *testing.T) {
				conn := newProtocolConnection(t)
				peer := identityPeer(t, "127.0.0.2", 8805)
				address := peer.LocalAddr().(*net.UDPAddr)
				assoc := NewNodeAssociation("cp.example", "127.0.0.2")
				assoc.endpoint = address.String()
				session := NewSession(11, 77, "", "", false)
				session.CPFSEIDIPv4 = net.ParseIP("127.0.0.2")
				assoc.Sessions[11] = session
				conn.NodeAssociations[assoc.ID] = assoc
				conn.heartbeatTimeout = time.Millisecond
				conn.requestTimeout = time.Millisecond
				conn.setupEvery = time.Second
				conn.SetRemoteNodes([]AssociationConnector{&DefaultAssociationConnector{address: "127.0.0.2"}})
				var request message.Message
				switch procedure {
				case "heartbeat":
					assoc.heartbeatInFlight = true
					request = message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
				case "report":
					request = message.NewSessionReportRequest(77, 0, ie.NewReportType(0, 0, 0, 1))
				case "setup", "sxa_setup", "sxb_setup":
					delete(conn.NodeAssociations, assoc.ID)
					ies := buildDefaultSetupRequestIEs(conn.profile, conn.nodeId, conn.RecoveryTimestamp, conn.featuresOctets)
					var err error
					if procedure == "sxa_setup" {
						ies, err = buildSxaSetupRequestIEs(conn.profile, conn.nodeId, conn.RecoveryTimestamp, "192.0.2.1", "192.0.2.2", []byte{0, 0})
					}
					if procedure == "sxb_setup" {
						ies, err = buildSxbSetupRequestIEs(conn.profile, conn.nodeId, conn.RecoveryTimestamp, "192.0.2.1", []byte{0, 0})
					}
					if err != nil {
						t.Fatal(err)
					}
					request = message.NewAssociationSetupRequest(0, ies...)
				case "update":
					request = message.NewAssociationUpdateRequest(0, ie.NewNodeIDFQDN(conn.nodeId), ie.NewPFCPAssociationReleaseRequest(1, 0))
				}
				send := func() error {
					if procedure == "report" {
						return conn.sendAssociationRequest(request, assoc.ID, false, 11)
					}
					return conn.SendMessage(request, address)
				}
				if err := send(); err != nil {
					t.Fatal(err)
				}
				_ = identityRead(t, peer)
				pending := conn.transport.pending[request.Sequence()]
				original := pending.onComplete
				var result requestResult
				calls := 0
				pending.onComplete = func(value requestResult) { calls++; result = value; original(value) }
				cause := ie.CauseRequestAccepted
				if outcome == "rejected" {
					cause = ie.CauseNoResourcesAvailable
				}
				var response message.Message
				switch procedure {
				case "heartbeat":
					response = message.NewHeartbeatResponse(request.Sequence(), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp))
				case "report":
					response = message.NewSessionReportResponse(11, request.Sequence(), ie.NewCause(cause))
				case "setup", "sxa_setup", "sxb_setup":
					response = message.NewAssociationSetupResponse(request.Sequence(), ie.NewNodeIDFQDN("cp.example"), ie.NewCause(cause), ie.NewRecoveryTimeStamp(conn.RecoveryTimestamp), ie.NewCPFunctionFeatures(0x10))
				case "update":
					response = message.NewAssociationUpdateResponse(request.Sequence(), ie.NewNodeIDFQDN("cp.example"), ie.NewCause(cause))
				}
				if procedure == "heartbeat" && outcome == "rejected" {
					response = message.NewVersionNotSupportedResponse(request.Sequence())
				}
				wire := protocolWire(t, response)
				want := requestAccepted
				switch outcome {
				case "rejected":
					want = requestRejected
				case "invalid_length":
					binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)-3))
					want = requestInvalid
				case "invalid_ie":
					wire = append(wire, 0, 56, 0, 8, 0)
					binary.BigEndian.PutUint16(wire[2:4], uint16(len(wire)-4))
					want = requestInvalid
				case "missing_ie":
					switch value := response.(type) {
					case *message.HeartbeatResponse:
						value.RecoveryTimeStamp = nil
					case *message.SessionReportResponse:
						value.Cause = nil
					case *message.AssociationSetupResponse:
						value.Cause = nil
					case *message.AssociationUpdateResponse:
						value.Cause = nil
					}
					wire = protocolWire(t, response)
					want = requestInvalid
				case "timeout":
					want = requestTimeout
				case "canceled":
					want = requestCanceled
				}
				switch outcome {
				case "timeout":
					conn.serviceTransactions(time.Now().Add(time.Second))
				case "canceled":
					conn.Close()
				default:
					conn.Handle(wire, address)
				}
				if calls != 1 || result.outcome != want || len(conn.transport.pending) != 0 {
					t.Fatalf("completion calls %d outcome %s want %s, pending %d", calls, result.outcome, want, len(conn.transport.pending))
				}
				if want == requestAccepted && result.err != nil || want != requestAccepted && result.err == nil {
					t.Fatalf("terminal error %v for %s", result.err, want)
				}
				if outcome != "canceled" {
					conn.Handle(wire, address)
					conn.serviceTransactions(time.Now().Add(time.Minute))
					if calls != 1 {
						t.Fatal("late response or maintenance completed the procedure twice")
					}
				}
				conn.stateMu.Lock()
				conn.completeRequestLocked(pending, requestResult{outcome: requestAccepted})
				conn.stateMu.Unlock()
				if calls != 1 {
					t.Fatal("duplicate terminal delivery")
				}
				switch procedure {
				case "heartbeat":
					if assoc.heartbeatInFlight {
						t.Fatal("completed probe remained in flight")
					}
				case "setup", "sxa_setup", "sxb_setup":
					if want != requestAccepted && outcome != "canceled" && !time.Now().Before(conn.setupRetryAt["127.0.0.2"]) {
						t.Fatal("failed setup did not delay the next attempt")
					}
					if want == requestAccepted && procedure != "setup" && (&ie.IE{Type: ie.UPFunctionFeatures, Payload: conn.associationByID("cp.example").UPFeatures}).HasBUNDL() {
						t.Fatal("setup used UP features it did not advertise")
					}
				case "update":
					if outcome != "canceled" && conn.GetAssiciationCount() != 1 {
						t.Fatal("Update completion removed the association")
					}
				}
			})
		}
	}
}

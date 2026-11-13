package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
)

// Run privileged on Linux with -benchtime=1024x. Allocation counts cover the
// UPF's decode/handler/encode path; client construction and validation are timed
// out. Each operation starts with 16384 sessions, a /16 and 65535 TEIDs.
func BenchmarkPFCPRequests(b *testing.B) {
	for _, operation := range []string{"establishment", "modification", "deletion"} {
		b.Run(operation, func(b *testing.B) {
			b.StopTimer()
			level := zerolog.GlobalLevel()
			zerolog.SetGlobalLevel(zerolog.ErrorLevel)
			b.Cleanup(func() { zerolog.SetGlobalLevel(level) })
			if b.N > 16384 {
				b.Fatal("use -benchtime=1024x (maximum 16384 iterations)")
			}
			previous := config.Conf
			config.Conf = config.UpfConfig{PfcpMaxReplayEntries: 65536}
			b.Cleanup(func() { config.Conf = previous })
			plane := ebpf.NewBpfObjects()
			if err := ebpf.IncreaseResourceLimits(); err != nil {
				b.Fatal(err)
			}
			if err := plane.ResizeAllMaps(65535, 131070, 131070, 196605); err != nil {
				b.Fatal(err)
			}
			if err := plane.Load(); err != nil {
				b.Fatal(err)
			}
			resources, err := service.NewResourceManager("10.60.0.0/16", 65535)
			if err != nil {
				b.Fatal(err)
			}
			conn, err := NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", plane, resources, nil, nil, DefaultProfile{})
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				resources.BeginShutdown()
				conn.Close()
				if err := plane.Close(); err != nil {
					b.Error(err)
				}
			})
			cp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				b.Fatal(err)
			}
			defer cp.Close()
			buffer := make([]byte, 65535)
			sequence := uint32(0)
			encode := func(request message.Message) []byte {
				sequence++
				request.SetSequenceNumber(sequence)
				wire := make([]byte, request.MarshalLen())
				if err := request.MarshalTo(wire); err != nil {
					b.Fatal(err)
				}
				return wire
			}
			read := func() message.Message {
				if err := cp.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					b.Fatal(err)
				}
				n, _, err := cp.ReadFromUDP(buffer)
				if err != nil {
					b.Fatal(err)
				}
				reply, err := message.Parse(buffer[:n])
				if err != nil {
					b.Fatal(err)
				}
				var cause *ie.IE
				switch msg := reply.(type) {
				case *message.AssociationSetupResponse:
					cause = msg.Cause
				case *message.SessionEstablishmentResponse:
					cause = msg.Cause
				case *message.SessionModificationResponse:
					cause = msg.Cause
				case *message.SessionDeletionResponse:
					cause = msg.Cause
				default:
					b.Fatalf("unexpected reply %T", reply)
				}
				if value, err := cause.Cause(); err != nil || value != ie.CauseRequestAccepted {
					b.Fatalf("cause %d: %v", value, err)
				}
				return reply
			}
			exchange := func(request message.Message) message.Message {
				conn.Handle(encode(request), cp.LocalAddr().(*net.UDPAddr))
				return read()
			}
			exchange(message.NewAssociationSetupRequest(0, ie.NewNodeIDFQDN("bench.example"), ie.NewRecoveryTimeStamp(time.Now())))
			establishment := func(index int) message.Message {
				return message.NewSessionEstablishmentRequest(0, 0, ie.NewNodeIDFQDN("bench.example"), ie.NewFSEID(uint64(index+1000), net.ParseIP("127.0.0.1"), nil),
					ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0), ie.NewUEIPAddress(2, fmt.Sprintf("10.60.%d.%d", index/250, index%250+1), "", 0, 0)), ie.NewOuterHeaderRemoval(0, 0), ie.NewFARID(1)),
					ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(1))))
			}
			for i := 0; i < 16384; i++ {
				exchange(establishment(i))
			}
			requests := make([][]byte, b.N)
			for i := range requests {
				var request message.Message
				if operation == "establishment" {
					request = establishment(i + 16384)
				} else {
					response := exchange(establishment(i + 16384)).(*message.SessionEstablishmentResponse)
					fields, err := response.UPFSEID.FSEID()
					if err != nil {
						b.Fatal(err)
					}
					if operation == "deletion" {
						request = message.NewSessionDeletionRequest(fields.SEID, 0)
					} else {
						request = message.NewSessionModificationRequest(fields.SEID, 0, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewUpdateForwardingParameters(ie.NewTransportLevelMarking([]byte{0x10, 0xfc}))))
					}
				}
				requests[i] = encode(request)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for _, wire := range requests {
				b.StartTimer()
				conn.Handle(wire, cp.LocalAddr().(*net.UDPAddr))
				b.StopTimer()
				read()
			}
		})
	}
}

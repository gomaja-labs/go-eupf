package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
)

func pipelineQuiet(t *testing.T) {
	previous := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(previous) })
}

func pipelineRead(t *testing.T, c *net.UDPConn, wait time.Duration) message.Message {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 65535)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	m, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pipelineDrain(c *net.UDPConn) int {
	buf := make([]byte, 65535)
	n := 0
	for {
		_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if _, _, err := c.ReadFromUDP(buf); err != nil {
			return n
		}
		n++
	}
}

func pipelineCause(t *testing.T, m message.Message) uint8 {
	t.Helper()
	var c *ie.IE
	switch r := m.(type) {
	case *message.SessionEstablishmentResponse:
		c = r.Cause
	case *message.SessionModificationResponse:
		c = r.Cause
	case *message.SessionDeletionResponse:
		c = r.Cause
	case *message.AssociationSetupResponse:
		c = r.Cause
	case *message.AssociationUpdateResponse:
		c = r.Cause
	case *message.AssociationReleaseResponse:
		c = r.Cause
	default:
		t.Fatalf("unexpected response %T", m)
	}
	v, err := c.Cause()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pipelineSetup(t *testing.T, conn *PfcpConnection, cp *net.UDPConn, node *ie.IE, seq uint32) {
	t.Helper()
	conn.Handle(protocolWire(t, message.NewAssociationSetupRequest(seq, node, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0)))), cp.LocalAddr().(*net.UDPAddr))
	reply := pipelineRead(t, cp, time.Second)
	if reply == nil || pipelineCause(t, reply) != ie.CauseRequestAccepted {
		t.Fatalf("association setup failed: %v", reply)
	}
}

func pipelineEstablish(t *testing.T, conn *PfcpConnection, from *net.UDPConn, node string, cpSEID uint64, entity string, teid uint32, seq uint32) uint64 {
	t.Helper()
	request := message.NewSessionEstablishmentRequest(0, seq,
		newIeNodeID(node), ie.NewFSEID(cpSEID, net.ParseIP(entity).To4(), nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(1)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
	conn.Handle(protocolWire(t, request), from.LocalAddr().(*net.UDPAddr))
	response, ok := pipelineRead(t, from, time.Second).(*message.SessionEstablishmentResponse)
	if !ok || pipelineCause(t, response) != ie.CauseRequestAccepted {
		t.Fatalf("establishment for CP F-SEID %d@%s failed", cpSEID, entity)
	}
	fseid, err := response.UPFSEID.FSEID()
	if err != nil {
		t.Fatal(err)
	}
	return fseid.SEID
}

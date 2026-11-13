package core

import (
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRejectedModificationKeepsAllSessionState(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	session := NewSession(2, 42, "", "", false)
	session.NewFar(1, 10, ebpf.FarInfo{Action: 2})
	conn.GetAssociation(peer).Sessions[2] = session
	before := cloneSession(session)
	request := message.NewSessionModificationRequest(2, 1,
		ie.NewRemoveFAR(ie.NewFARID(1)),
		ie.NewCreatePDR(ie.NewPDRID(9), ie.NewPDI(ie.NewUEIPAddress(6, "192.0.2.9", "", 0, 0), ie.NewTrafficEndpointID(1))))
	response, _, err := HandlePfcpSessionModificationRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	cause, err := response.(*message.SessionModificationResponse).Cause.Cause()
	if err != nil || cause == ie.CauseRequestAccepted {
		t.Fatalf("cause=%d err=%v", cause, err)
	}
	if got := conn.GetAssociation(peer).Sessions[2]; !reflect.DeepEqual(got, before) {
		t.Fatalf("rejection changed live session: before=%+v after=%+v", before, got)
	}
}

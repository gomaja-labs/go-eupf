package core

import (
	"errors"
	"syscall"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type cleanupFailureMaps struct{ MapOperationsMock }

func (m *cleanupFailureMaps) DeleteFar(uint32) error { return errors.New("injected deletion failure") }
func (m *cleanupFailureMaps) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	return &cleanupFailureTx{ForwardingPlaneController: m}, nil
}

type cleanupFailureTx struct{ ebpf.ForwardingPlaneController }

func (t *cleanupFailureTx) Commit() error   { return nil }
func (t *cleanupFailureTx) Rollback() error { return nil }
func TestAssociationCleanupKeepsOwnershipWhenMapDeletionFails(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithMock(t, &cleanupFailureMaps{}, config.UpfConfig{})
	s := NewSession(2, 42, "", "", false)
	s.NewFar(1, 1, ebpf.FarInfo{Action: 2})
	conn.GetAssociation(peer).Sessions[2] = s
	conn.DeleteAssociation(peer)
	if conn.GetAssociation(peer) == nil || conn.GetAssociation(peer).Sessions[2] == nil {
		t.Fatal("failed cleanup discarded ownership of a live map slot")
	}
}

type deletionSystemFailure struct{ MapOperationsMock }

func (m *deletionSystemFailure) DeleteFar(uint32) error { return syscall.EIO }
func (m *deletionSystemFailure) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	return &cleanupFailureTx{ForwardingPlaneController: m}, nil
}
func TestDeletionReportsSystemFailureWithoutLosingSession(t *testing.T) {
	conn, peer := PreparePfcpConnectionWithMock(t, &deletionSystemFailure{}, config.UpfConfig{})
	s := NewSession(2, 42, "", "", false)
	s.NewFar(7, 1, ebpf.FarInfo{Action: 2})
	conn.GetAssociation(peer).Sessions[2] = s
	reply, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(2, 1), peer)
	if err != nil {
		t.Fatal(err)
	}
	response := reply.(*message.SessionDeletionResponse)
	cause, _ := response.Cause.Cause()
	if cause != ie.CauseSystemFailure || response.SEID() != 42 {
		t.Fatalf("deletion failure cause=%d SEID=%d", cause, response.SEID())
	}
	if conn.GetAssociation(peer).Sessions[2] != s {
		t.Fatal("failed deletion replaced live session")
	}
}

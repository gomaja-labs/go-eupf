package core

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func sessionLimitConnection(t *testing.T, maximum uint32, resources *service.ResourceManager, plane ebpf.ForwardingPlaneController) *PfcpConnection {
	t.Helper()
	old := config.Conf
	config.Conf = config.UpfConfig{MaxSessions: maximum}
	t.Cleanup(func() { config.Conf = old })
	if resources == nil {
		var err error
		resources, err = service.NewResourceManager("", 16)
		if err != nil {
			t.Fatal(err)
		}
	}
	if plane == nil {
		plane = &MapOperationsMock{}
	}
	conn, err := NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", plane, resources, nil, nil, DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	return conn
}

func sessionLimitRequest(node string, sequence uint32, far uint32) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(0, sequence, ie.NewNodeIDFQDN(node), ie.NewFSEID(uint64(sequence+1000), net.ParseIP("127.0.0.25"), nil),
		ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(far)),
		ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
}

func sessionLimitExchange(t *testing.T, conn *PfcpConnection, peer *net.UDPConn, request message.Message) message.Message {
	t.Helper()
	conn.Handle(protocolWire(t, request), peer.LocalAddr().(*net.UDPAddr))
	return identityRead(t, peer)
}

func TestSessionLimitIsSharedAcrossEndpointsAndFreesOnlyKnownSessions(t *testing.T) {
	pipelineQuiet(t)
	first := sessionLimitConnection(t, 2, nil, nil)
	second := sessionLimitConnection(t, 2, first.ResourceManager, first.mapOperations)
	a, b := identityPeer(t, "127.0.0.25", 0), identityPeer(t, "127.0.0.26", 0)
	identitySetup(t, first, a, "a.example")
	identitySetup(t, second, b, "b.example")
	initial := sessionLimitExchange(t, first, a, sessionLimitRequest("a.example", 2, 1)).(*message.SessionEstablishmentResponse)
	if pipelineCause(t, initial) != 1 {
		t.Fatal("first session rejected")
	}
	seid, _ := initial.UPFSEID.FSEID()
	if pipelineCause(t, sessionLimitExchange(t, second, b, sessionLimitRequest("b.example", 2, 1))) != 1 {
		t.Fatal("second session rejected")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, first, a, sessionLimitRequest("a.example", 3, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("shared capacity exceeded: cause %d", cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, first, a, message.NewSessionDeletionRequest(seid.SEID, 4))); cause != 1 {
		t.Fatal(cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, first, a, sessionLimitRequest("a.example", 5, 1))); cause != 1 {
		t.Fatalf("deleted slot unavailable: %d", cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, first, a, message.NewSessionDeletionRequest(seid.SEID, 6))); cause != ie.CauseSessionContextNotFound {
		t.Fatal(cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, second, b, sessionLimitRequest("b.example", 7, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("unknown deletion freed a slot: %d", cause)
	}
}

func TestRestorationCollisionKeepsItsCauseAtSessionCapacity(t *testing.T) {
	pipelineQuiet(t)
	conn := sessionLimitConnection(t, 1, nil, nil)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	first := sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1)).(*message.SessionEstablishmentResponse)
	created, _ := first.CreatedPDR[0].CreatedPDR()
	tunnel, _ := created.FTEID[0].FTEID()
	request := sessionLimitRequest("limit.example", 3, 1)
	request.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
	request.CreatePDR = []*ie.IE{ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(1, tunnel.TEID, conn.n3Address, nil, 0)), ie.NewFARID(1))}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, request)); cause != ie.CauseSessionRestorationResourceUnavailable {
		t.Fatalf("collision cause at capacity %d", cause)
	}
}

func TestRejectedEstablishmentReturnsItsSessionSlot(t *testing.T) {
	pipelineQuiet(t)
	conn := sessionLimitConnection(t, 1, nil, nil)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 999))); cause == 1 {
		t.Fatal("invalid rule accepted")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 3, 1))); cause != 1 {
		t.Fatalf("rejected request leaked capacity: %d", cause)
	}
}

func TestSessionSlotWaitsForRuleRetirement(t *testing.T) {
	pipelineQuiet(t)
	plane := &delayedUsagePlane{holdRetirement: true}
	conn := sessionLimitConnection(t, 1, nil, plane)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	response := sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1)).(*message.SessionEstablishmentResponse)
	if pipelineCause(t, response) != 1 {
		t.Fatal("establishment rejected")
	}
	seid, _ := response.UPFSEID.FSEID()
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, message.NewSessionDeletionRequest(seid.SEID, 3))); cause != 1 {
		t.Fatal(cause)
	}
	retirement := plane.transaction.reclaim
	if retirement == nil {
		t.Fatal("no retirement callback")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 4, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("slot freed before retirement: %d", cause)
	}
	if err := retirement(); err != nil {
		t.Fatal(err)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 5, 1))); cause != 1 {
		t.Fatalf("retired slot unavailable: %d", cause)
	}
}

func TestEmptySessionStillConsumesAdmissionCapacity(t *testing.T) {
	pipelineQuiet(t)
	conn := sessionLimitConnection(t, 1, nil, nil)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	response := sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1)).(*message.SessionEstablishmentResponse)
	seid, _ := response.UPFSEID.FSEID()
	removal := message.NewSessionModificationRequest(seid.SEID, 3, ie.NewRemovePDR(ie.NewPDRID(1)), ie.NewRemoveFAR(ie.NewFARID(1)))
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, removal)); cause != 1 {
		t.Fatal(cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 4, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("empty context bypassed maximum: %d", cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, message.NewSessionDeletionRequest(seid.SEID, 5))); cause != 1 {
		t.Fatal("empty deletion failed", cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 6, 1))); cause != 1 {
		t.Fatal("empty deletion leaked admission", cause)
	}
}

func TestRestartedContextsKeepTheirSessionSlotsUntilCleanup(t *testing.T) {
	pipelineQuiet(t)
	conn := sessionLimitConnection(t, 1, nil, nil)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1))); cause != 1 {
		t.Fatal(cause)
	}
	for i, stamp := range []int64{1800000000, 1800000100} {
		response := sessionLimitExchange(t, conn, peer, message.NewHeartbeatRequest(uint32(i+3), ie.NewRecoveryTimeStamp(time.Unix(stamp, 0))))
		if response.MessageType() != message.MsgTypeHeartbeatResponse {
			t.Fatal("no heartbeat")
		}
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 5, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("detached context bypassed capacity: %d", cause)
	}
	conn.serviceHeartbeats(time.Now())
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 6, 1))); cause != 1 {
		t.Fatalf("cleanup did not release slot: %d", cause)
	}
}

type sessionFailurePlane struct {
	MapOperationsMock
	commitError, rollbackError error
	holdRollback               bool
	transaction                *sessionFailureTransaction
}
type sessionFailureTransaction struct {
	ebpf.ForwardingPlaneController
	plane   *sessionFailurePlane
	reclaim func() error
}

func (plane *sessionFailurePlane) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	transaction := &sessionFailureTransaction{ForwardingPlaneController: plane, plane: plane}
	plane.transaction = transaction
	return transaction, nil
}
func (tx *sessionFailureTransaction) RetireResources(reclaim func() error) { tx.reclaim = reclaim }
func (tx *sessionFailureTransaction) UsageCompletion() <-chan error        { return nil }
func (tx *sessionFailureTransaction) Commit() error {
	// Complete before the terminal result to exercise both latch orderings.
	if tx.reclaim != nil {
		if err := tx.reclaim(); err != nil {
			return err
		}
	}
	return tx.plane.commitError
}
func (tx *sessionFailureTransaction) Rollback() error {
	if tx.reclaim != nil && !tx.plane.holdRollback {
		if err := tx.reclaim(); err != nil {
			return err
		}
	}
	return tx.plane.rollbackError
}

func TestRejectedPublicationWaitsForRollbackReclamation(t *testing.T) {
	pipelineQuiet(t)
	plane := &sessionFailurePlane{commitError: errors.New("synthetic commit failure"), holdRollback: true}
	conn := sessionLimitConnection(t, 1, nil, plane)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1))); cause == 1 {
		t.Fatal("failed publication accepted")
	}
	retirement := plane.transaction.reclaim
	if retirement == nil {
		t.Fatal("no rollback retirement")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 3, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("rollback returned capacity before retirement: %d", cause)
	}
	if err := retirement(); err != nil {
		t.Fatal(err)
	}
	plane.commitError = nil
	plane.holdRollback = false
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 4, 1))); cause != 1 {
		t.Fatalf("rollback leaked admission: %d", cause)
	}
}

func TestFailedDeletionKeepsItsSessionSlot(t *testing.T) {
	pipelineQuiet(t)
	plane := &sessionFailurePlane{}
	conn := sessionLimitConnection(t, 1, nil, plane)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	first := sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1)).(*message.SessionEstablishmentResponse)
	seid, _ := first.UPFSEID.FSEID()
	plane.commitError = errors.New("synthetic commit failure")
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, message.NewSessionDeletionRequest(seid.SEID, 3))); cause == 1 {
		t.Fatal("failed deletion accepted")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 4, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("failed deletion freed live capacity: %d", cause)
	}
	plane.commitError = nil
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, message.NewSessionDeletionRequest(seid.SEID, 5))); cause != 1 {
		t.Fatal("successful deletion rejected", cause)
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 6, 1))); cause != 1 {
		t.Fatal("successful deletion leaked capacity", cause)
	}
}

func TestRollbackFailureKeepsItsSessionSlot(t *testing.T) {
	pipelineQuiet(t)
	plane := &sessionFailurePlane{commitError: errors.New("synthetic commit failure"), rollbackError: errors.New("synthetic rollback failure")}
	conn := sessionLimitConnection(t, 1, nil, plane)
	peer := identityPeer(t, "127.0.0.25", 0)
	identitySetup(t, conn, peer, "limit.example")
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 2, 1))); cause == 1 {
		t.Fatal("failed publication accepted")
	}
	if cause := pipelineCause(t, sessionLimitExchange(t, conn, peer, sessionLimitRequest("limit.example", 3, 1))); cause != ie.CauseNoResourcesAvailable {
		t.Fatalf("failed rollback freed capacity: %d", cause)
	}
}

func TestSessionReleaseRequiresTransactionAndReclamation(t *testing.T) {
	for _, early := range []bool{false, true} {
		var releases atomic.Int32
		completion := &sessionRetirement{release: func() { releases.Add(1) }}
		if early {
			completion.retired()
		} else {
			completion.allow()
		}
		if releases.Load() != 0 {
			t.Fatal("only one completion event freed the slot")
		}
		if early {
			completion.allow()
		} else {
			completion.retired()
		}
		completion.allow()
		completion.retired()
		if releases.Load() != 1 {
			t.Fatal("completion was not idempotent")
		}
	}
	var releases atomic.Int32
	completion := &sessionRetirement{release: func() { releases.Add(1) }}
	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Go(func() {
			if i%2 == 0 {
				completion.allow()
			} else {
				completion.retired()
			}
		})
	}
	group.Wait()
	if releases.Load() != 1 {
		t.Fatal("concurrent completion freed capacity more than once")
	}
}

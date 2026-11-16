package core

import (
	"net"
	"testing"
	"time"

	"errors"

	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type delayedUsagePlane struct {
	MapOperationsMock
	transaction      *delayedUsageTransaction
	holdRetirement   bool
	completeOnCommit bool
}
type delayedUsageTransaction struct {
	ebpf.ForwardingPlaneController
	callbacks        []func(ebpf.UrrInfo)
	ready            chan error
	reclaim          func() error
	holdRetirement   bool
	completeOnCommit bool
}

func (plane *delayedUsagePlane) BeginRuleTransaction(uint64) (ebpf.RuleTransaction, error) {
	tx := &delayedUsageTransaction{ForwardingPlaneController: plane, ready: make(chan error, 1), holdRetirement: plane.holdRetirement, completeOnCommit: plane.completeOnCommit}
	plane.transaction = tx
	return tx, nil
}
func (tx *delayedUsageTransaction) DeferUsage(_ uint32, callback func(ebpf.UrrInfo)) error {
	tx.callbacks = append(tx.callbacks, callback)
	return nil
}
func (tx *delayedUsageTransaction) RetireResources(reclaim func() error) { tx.reclaim = reclaim }
func (tx *delayedUsageTransaction) UsageCompletion() <-chan error {
	if len(tx.callbacks) == 0 {
		return nil
	}
	return tx.ready
}
func (tx *delayedUsageTransaction) Commit() error {
	if tx.completeOnCommit && len(tx.callbacks) > 0 {
		go func() {
			for _, callback := range tx.callbacks {
				callback(ebpf.UrrInfo{UplinkVolume: 40, DownlinkVolume: 20})
			}
			var err error
			if tx.reclaim != nil {
				err = tx.reclaim()
			}
			tx.ready <- err
		}()
	}
	if len(tx.callbacks) == 0 && tx.reclaim != nil && !tx.holdRetirement {
		return tx.reclaim()
	}
	return nil
}
func (tx *delayedUsageTransaction) Rollback() error { return nil }
func (tx *delayedUsageTransaction) finish(t *testing.T) {
	t.Helper()
	for _, callback := range tx.callbacks {
		callback(ebpf.UrrInfo{UplinkVolume: 40, DownlinkVolume: 20})
	}
	if tx.reclaim != nil {
		if err := tx.reclaim(); err != nil {
			t.Fatal(err)
		}
	}
	tx.ready <- nil
}

func TestDeletionWaitDoesNotBlockOtherRequestsOrExecuteRetransmission(t *testing.T) {
	conn := newProtocolConnection(t)
	plane := &delayedUsagePlane{}
	conn.mapOperations = plane
	cp := identityPeer(t, "127.0.0.31", 0)
	identitySetup(t, conn, cp, "async.example")
	assoc := conn.associationByID("async.example")
	session := NewSession(11, 77, "", "", false)
	session.NewUrr(9, 1, ebpf.UrrInfo{UplinkVolume: 3})
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.31")
	assoc.Sessions[11] = session
	request := protocolWire(t, message.NewSessionDeletionRequest(11, 2))
	conn.Handle(request, cp.LocalAddr().(*net.UDPAddr))
	tx := plane.transaction
	if assoc.Sessions[11] != nil {
		t.Fatal("session deletion was postponed until grace")
	}
	conn.Handle(request, cp.LocalAddr().(*net.UDPAddr))
	if plane.transaction != tx {
		t.Fatal("waiting deletion executed twice")
	}
	if reply := pipelineRead(t, cp, 10*time.Millisecond); reply != nil {
		t.Fatal("deletion replied before final counters were available")
	}
	conn.Handle(protocolWire(t, message.NewHeartbeatRequest(3, ie.NewRecoveryTimeStamp(time.Now()))), cp.LocalAddr().(*net.UDPAddr))
	if reply := identityRead(t, cp); reply.Sequence() != 3 {
		t.Fatal("heartbeat blocked behind deletion")
	}
	conn.Handle(protocolWire(t, message.NewSessionDeletionRequest(11, 4)), cp.LocalAddr().(*net.UDPAddr))
	if cause := pipelineCause(t, identityRead(t, cp)); cause != ie.CauseSessionContextNotFound {
		t.Fatalf("later request did not see committed deletion: cause %d", cause)
	}
	tx.finish(t)
	reply := identityRead(t, cp).(*message.SessionDeletionResponse)
	if reply.Sequence() != 2 || len(reply.UsageReport) != 1 {
		t.Fatalf("final deletion response sequence %d reports %d", reply.Sequence(), len(reply.UsageReport))
	}
	fields, _ := reply.UsageReport[0].UsageReportWithinSessionDeletionResponse()
	volume, _ := fields.VolumeMeasurement.VolumeMeasurement()
	if volume.TotalVolume != 57 {
		t.Fatalf("final usage %d, want 57", volume.TotalVolume)
	}
	if extra := pipelineRead(t, cp, 10*time.Millisecond); extra != nil {
		t.Fatal("retransmission received a second unsolicited response")
	}
	conn.Handle(request, cp.LocalAddr().(*net.UDPAddr))
	if replay := identityRead(t, cp); replay.Sequence() != 2 {
		t.Fatal("completed deletion outcome was not replayed")
	}
}

func TestModificationCommitsBeforeFinalUsageWait(t *testing.T) {
	conn := newProtocolConnection(t)
	plane := &delayedUsagePlane{}
	conn.mapOperations = plane
	cp := identityPeer(t, "127.0.0.32", 0)
	identitySetup(t, conn, cp, "async.example")
	assoc := conn.associationByID("async.example")
	session := NewSession(11, 77, "", "", false)
	session.NewUrr(9, 1, ebpf.UrrInfo{})
	session.NewFar(1, 1, ebpf.FarInfo{Action: 1})
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.32")
	assoc.Sessions[11] = session
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 2, ie.NewRemoveURR(ie.NewURRID(9)))), cp.LocalAddr().(*net.UDPAddr))
	tx := plane.transaction
	if _, exists := assoc.Sessions[11].URRs[9]; exists {
		t.Fatal("URR removal waited for grace")
	}
	conn.Handle(protocolWire(t, message.NewSessionModificationRequest(11, 3, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(2)))), cp.LocalAddr().(*net.UDPAddr))
	if reply := identityRead(t, cp); reply.Sequence() != 3 {
		t.Fatal("later modification blocked")
	}
	tx.finish(t)
	reply := identityRead(t, cp).(*message.SessionModificationResponse)
	if reply.Sequence() != 2 || len(reply.UsageReport) != 1 {
		t.Fatal("removed URR final usage omitted from Modification Response")
	}
	if assoc.Sessions[11].FARs[1].FarInfo.Action != 2 {
		t.Fatal("usage completion undid a later modification")
	}
}

func TestDeletionWithoutUsageRetainsIdentifiersUntilBackgroundGrace(t *testing.T) {
	conn := newProtocolConnection(t)
	resources, _ := service.NewResourceManager("", 1)
	conn.ResourceManager = resources
	plane := &delayedUsagePlane{holdRetirement: true}
	conn.mapOperations = plane
	cp := identityPeer(t, "127.0.0.37", 0)
	identitySetup(t, conn, cp, "async.example")
	assoc := conn.associationByID("async.example")
	session := NewSession(11, 77, "", "", false)
	session.CPFSEIDIPv4 = net.ParseIP("127.0.0.37")
	session.PutPDR(1, SPDRInfo{PdrID: 1, Teid: 1, PdrInfo: ebpf.PdrInfo{SessionID: 11, PdrID: 1}})
	assoc.Sessions[11] = session
	if err := resources.FTEIDM.ReserveTEID(11, 1, 1); err != nil {
		t.Fatal(err)
	}
	conn.Handle(protocolWire(t, message.NewSessionDeletionRequest(11, 2)), cp.LocalAddr().(*net.UDPAddr))
	reply := identityRead(t, cp).(*message.SessionDeletionResponse)
	if cause, _ := reply.Cause.Cause(); cause != 1 {
		t.Fatal("deletion did not respond before reclamation")
	}
	if err := resources.FTEIDM.ReserveTEID(12, 1, 1); !errors.Is(err, service.ErrResourceCollision) {
		t.Fatal("deletion freed a still-retiring TEID")
	}
	plane.transaction.finish(t)
	if err := resources.FTEIDM.ReserveTEID(12, 1, 1); err != nil {
		t.Fatal("grace did not release the TEID")
	}
}

func TestFinalUsageMayCompleteDuringResponseConstruction(t *testing.T) {
	for _, deletion := range []bool{false, true} {
		t.Run(map[bool]string{false: "modification", true: "deletion"}[deletion], func(t *testing.T) {
			conn := newProtocolConnection(t)
			conn.mapOperations = &delayedUsagePlane{completeOnCommit: true}
			cp := identityPeer(t, "127.0.0.42", 0)
			identitySetup(t, conn, cp, "async.example")
			assoc := conn.associationByID("async.example")
			for sequence := uint32(2); sequence < 18; sequence++ {
				session := NewSession(uint64(sequence), 77, "", "", false)
				session.CPFSEIDIPv4 = net.ParseIP("127.0.0.42")
				var removes []*ie.IE
				for id := uint32(1); id <= 32; id++ {
					session.NewUrr(id, id, ebpf.UrrInfo{})
					removes = append(removes, ie.NewRemoveURR(ie.NewURRID(id)))
				}
				assoc.Sessions[session.LocalSEID] = session
				var request message.Message = message.NewSessionModificationRequest(session.LocalSEID, sequence, removes...)
				if deletion {
					request = message.NewSessionDeletionRequest(session.LocalSEID, sequence)
				}
				conn.Handle(protocolWire(t, request), cp.LocalAddr().(*net.UDPAddr))
				reply := identityRead(t, cp)
				var reports []*ie.IE
				switch response := reply.(type) {
				case *message.SessionModificationResponse:
					reports = response.UsageReport
				case *message.SessionDeletionResponse:
					reports = response.UsageReport
				default:
					t.Fatalf("unexpected response %T", reply)
				}
				if len(reports) != 32 {
					t.Fatalf("final reports=%d, want 32", len(reports))
				}
			}
		})
	}
}

func (*delayedUsageTransaction) CheckRuleCapacity(ebpf.RuleCounts) (uint8, error) { return 0, nil }

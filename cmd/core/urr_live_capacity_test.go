//go:build linux

package core

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestURRReplacementAtLiveLimit(t *testing.T) {
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	type step struct {
		name string
		mod  func(seid uint64) *message.SessionModificationRequest
	}
	for _, s := range []step{
		{"control_update_far", func(seid uint64) *message.SessionModificationRequest {
			return message.NewSessionModificationRequest(seid, 2, ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(1)))
		}},
		{"remove_and_create_urr", func(seid uint64) *message.SessionModificationRequest {
			return message.NewSessionModificationRequest(seid, 2,
				ie.NewRemoveURR(ie.NewURRID(1)),
				ie.NewCreateURR(ie.NewURRID(3), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0, 0), ie.NewVolumeThreshold(1, 1000000, 0, 0)),
				ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewURRID(3)))
		}},
		{"stopped_usage_dissociation", func(seid uint64) *message.SessionModificationRequest {
			// URR 1 loses its last PDR; clause 5.2.2.3.1 retains it reset.
			return message.NewSessionModificationRequest(seid, 2, ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewURRID(2)))
		}},
	} {
		t.Run(s.name, func(t *testing.T) {
			maps := ebpf.NewBpfObjects()
			maps.SetUrrMapSize(2)
			if err := maps.Load(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = maps.Close() })
			conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{})
			conn.ResourceManager, _ = service.NewResourceManager("", 0)
			req := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil),
				ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)),
				ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0, 0), ie.NewVolumeThreshold(1, 1000000, 0, 0)),
				ie.NewCreateURR(ie.NewURRID(2), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0, 0), ie.NewVolumeThreshold(1, 1000000, 0, 0)),
				ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.10", "", 0, 0)), ie.NewFARID(1), ie.NewURRID(1)),
				ie.NewCreatePDR(ie.NewPDRID(2), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.11", "", 0, 0)), ie.NewFARID(1), ie.NewURRID(2)))
			reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
			if err != nil {
				t.Fatal(err)
			}
			accepted := reply.(*message.SessionEstablishmentResponse)
			if cause, _ := accepted.Cause.Cause(); cause != ie.CauseRequestAccepted {
				t.Fatalf("establishment cause %d", cause)
			}
			fseid, _ := accepted.UPFSEID.FSEID()
			result, _, err := HandlePfcpSessionModificationRequest(conn, s.mod(fseid.SEID), peer)
			if err != nil {
				t.Fatal(err)
			}
			if deferred, ok := result.(*usageResponse); ok {
				result = deferred.Message
			}
			cause, _ := result.(*message.SessionModificationResponse).Cause.Cause()
			session := conn.GetAssociation(peer).Sessions[fseid.SEID]
			t.Logf("%s: live_urr_limit=2 urrs_after=%d cause=%d", s.name, len(session.URRs), cause)
			if cause != ie.CauseRequestAccepted {
				t.Errorf("%s at live URR limit: cause %d, live URR count would stay at 2", s.name, cause)
			}
		})
	}
}

// Hold the final counter callback after unpublication, before physical slot
// reclamation, to separate committed live capacity from retirement headroom.
type heldUsagePlane struct {
	*ebpf.BpfObjects
	entered, resume chan struct{}
	once            sync.Once
}

type heldUsageTransaction struct {
	ebpf.RuleTransaction
	plane *heldUsagePlane
}

func (plane *heldUsagePlane) BeginRuleTransaction(seid uint64) (ebpf.RuleTransaction, error) {
	tx, err := plane.BpfObjects.BeginRuleTransaction(seid)
	if err != nil {
		return nil, err
	}
	return &heldUsageTransaction{RuleTransaction: tx, plane: plane}, nil
}
func (tx *heldUsageTransaction) DeferUsage(id uint32, report func(ebpf.UrrInfo)) error {
	return tx.RuleTransaction.(interface {
		DeferUsage(uint32, func(ebpf.UrrInfo)) error
	}).DeferUsage(id, func(info ebpf.UrrInfo) {
		tx.plane.once.Do(func() { close(tx.plane.entered) })
		<-tx.plane.resume
		report(info)
	})
}
func (tx *heldUsageTransaction) RetireResources(reclaim func() error) {
	tx.RuleTransaction.(interface{ RetireResources(func() error) }).RetireResources(reclaim)
}
func (tx *heldUsageTransaction) UsageCompletion() <-chan error {
	return tx.RuleTransaction.(interface{ UsageCompletion() <-chan error }).UsageCompletion()
}

func TestSessionDeletionReturnsLiveURRCapacityBeforeReclamation(t *testing.T) {
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	maps := ebpf.NewBpfObjects()
	maps.SetUrrMapSize(1)
	if err := maps.Load(); err != nil {
		t.Fatal(err)
	}
	plane := &heldUsagePlane{BpfObjects: maps, entered: make(chan struct{}), resume: make(chan struct{})}
	t.Cleanup(func() { close(plane.resume); _ = maps.Close() })
	conn, peer := PreparePfcpConnectionWithMock(t, plane, config.UpfConfig{})
	conn.ResourceManager, _ = service.NewResourceManager("", 0)
	establish := func(seid uint64) *message.SessionEstablishmentResponse {
		t.Helper()
		reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, message.NewSessionEstablishmentRequest(0, uint32(seid),
			ie.NewNodeIDFQDN("test"), ie.NewFSEID(seid, net.ParseIP(peer), nil),
			ie.NewCreateURR(ie.NewURRID(1), ie.NewMeasurementMethod(0, 1, 0))), peer)
		if err != nil {
			t.Fatal(err)
		}
		return reply.(*message.SessionEstablishmentResponse)
	}
	first := establish(42)
	if cause, _ := first.Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("first cause=%d", cause)
	}
	fseid, _ := first.UPFSEID.FSEID()
	reply, _, err := HandlePfcpSessionDeletionRequest(conn, message.NewSessionDeletionRequest(fseid.SEID, 2), peer)
	if err != nil {
		t.Fatal(err)
	}
	if deferred, ok := reply.(*usageResponse); ok {
		reply = deferred.Message
	}
	if cause, _ := reply.(*message.SessionDeletionResponse).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("deletion cause=%d", cause)
	}
	select {
	case <-plane.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("counter retirement did not start")
	}
	if cause, _ := establish(43).Cause.Cause(); cause != ie.CauseRequestAccepted {
		t.Fatalf("replacement before reclamation cause=%d", cause)
	}
}

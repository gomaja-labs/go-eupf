//go:build linux

package core

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type observedRulePlane struct {
	*ebpf.BpfObjects
	writes int
}
type observedRuleTransaction struct {
	ebpf.RuleTransaction
	plane *observedRulePlane
}

func (plane *observedRulePlane) BeginRuleTransaction(seid uint64) (ebpf.RuleTransaction, error) {
	tx, err := plane.BpfObjects.BeginRuleTransaction(seid)
	if err != nil {
		return nil, err
	}
	return &observedRuleTransaction{RuleTransaction: tx, plane: plane}, nil
}
func (tx *observedRuleTransaction) UpdateFar(id uint32, info ebpf.FarInfo) error {
	tx.plane.writes++
	return tx.RuleTransaction.UpdateFar(id, info)
}
func (tx *observedRuleTransaction) UpdateQer(id uint32, info ebpf.QerInfo) error {
	tx.plane.writes++
	return tx.RuleTransaction.UpdateQer(id, info)
}
func (tx *observedRuleTransaction) UpdateUrr(id uint32, info ebpf.UrrInfo) error {
	tx.plane.writes++
	return tx.RuleTransaction.UpdateUrr(id, info)
}
func (tx *observedRuleTransaction) DeferUsage(id uint32, report func(ebpf.UrrInfo)) error {
	return tx.RuleTransaction.(interface {
		DeferUsage(uint32, func(ebpf.UrrInfo)) error
	}).DeferUsage(id, report)
}
func (tx *observedRuleTransaction) RetireResources(reclaim func() error) {
	tx.RuleTransaction.(interface{ RetireResources(func() error) }).RetireResources(reclaim)
}
func (tx *observedRuleTransaction) UsageCompletion() <-chan error {
	return tx.RuleTransaction.(interface{ UsageCompletion() <-chan error }).UsageCompletion()
}

func snapshotCapacityMaps(t *testing.T, maps *ebpf.BpfObjects) []map[string]string {
	t.Helper()
	var snapshots []map[string]string
	for _, m := range []*cilium.Map{maps.FarMap, maps.QerMap, maps.UrrMap, maps.PdrMapDownlinkIp4, maps.PdrMapTeidIp4, maps.PdrMapDownlinkIp6, maps.PdrBuckets, maps.BufferBindings} {
		snapshot := make(map[string]string)
		iterator := m.Iterate()
		var key, value []byte
		for iterator.Next(&key, &value) {
			snapshot[string(key)] = string(value)
		}
		if err := iterator.Err(); err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

func capacityCreateRule(kind uint8, id uint32) *ie.IE {
	switch kind {
	case ie.RuleIDTypeFAR:
		return ie.NewCreateFAR(ie.NewFARID(id), ie.NewApplyAction(1))
	case ie.RuleIDTypeQER:
		return ie.NewCreateQER(ie.NewQERID(id), ie.NewGateStatus(0, 0))
	default:
		return ie.NewCreateURR(ie.NewURRID(id), ie.NewMeasurementMethod(0, 1, 0), ie.NewReportingTriggers(0x02, 0, 0), ie.NewVolumeThreshold(1, 1000000, 0, 0))
	}
}
func capacityRemoveRule(kind uint8, id uint32) *ie.IE {
	switch kind {
	case ie.RuleIDTypeFAR:
		return ie.NewRemoveFAR(ie.NewFARID(id))
	case ie.RuleIDTypeQER:
		return ie.NewRemoveQER(ie.NewQERID(id))
	default:
		return ie.NewRemoveURR(ie.NewURRID(id))
	}
}
func capacityEstablishment(sequence uint32, rules ...*ie.IE) *message.SessionEstablishmentRequest {
	ies := []*ie.IE{ie.NewNodeIDFQDN("capacity.example"), ie.NewFSEID(uint64(sequence), net.ParseIP("127.0.0.25"), nil)}
	return message.NewSessionEstablishmentRequest(0, sequence, append(ies, rules...)...)
}

func TestLiveRuleShortageRejectsBeforePublication(t *testing.T) {
	pipelineQuiet(t)
	if err := ebpf.IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		name string
		kind uint8
	}{{"FAR", ie.RuleIDTypeFAR}, {"QER", ie.RuleIDTypeQER}, {"URR", ie.RuleIDTypeURR}} {
		for _, modification := range []bool{false, true} {
			procedure := "establishment"
			if modification {
				procedure = "modification"
			}
			t.Run(family.name+"/"+procedure, func(t *testing.T) {
				maps := ebpf.NewBpfObjects()
				maps.SetFarMapSize(2)
				maps.SetQerMapSize(2)
				maps.SetUrrMapSize(2)
				if err := maps.Load(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = maps.Close() })
				plane := &observedRulePlane{BpfObjects: maps}
				conn := sessionLimitConnection(t, 16, nil, plane)
				peer := identityPeer(t, "127.0.0.25", 8805)
				identitySetup(t, conn, peer, "capacity.example")
				initialRules := []*ie.IE{capacityCreateRule(family.kind, 1), capacityCreateRule(family.kind, 2)}
				if family.kind != ie.RuleIDTypeFAR {
					initialRules = append(initialRules, capacityCreateRule(ie.RuleIDTypeFAR, 1))
				}
				initialRules = append(initialRules, ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(6, "192.0.2.1", "", 0, 0)), ie.NewFARID(1)))
				first := sessionLimitExchange(t, conn, peer, capacityEstablishment(2, initialRules...)).(*message.SessionEstablishmentResponse)
				if pipelineCause(t, first) != ie.CauseRequestAccepted {
					t.Fatalf("initial session rejected: cause=%d", pipelineCause(t, first))
				}
				fseid, _ := first.UPFSEID.FSEID()
				assoc := conn.associationByID("capacity.example")
				beforeSession := cloneSession(assoc.Sessions[fseid.SEID])
				beforeOriginal := assoc.Sessions[fseid.SEID]
				before := snapshotCapacityMaps(t, maps)
				plane.writes = 0
				// Put the larger ID first to check deterministic selection of a created
				// rule, independently of map iteration order and request ordering.
				rules := []*ie.IE{capacityCreateRule(family.kind, 9), capacityCreateRule(family.kind, 7)}
				// A PDR change would allocate a TEID and reach the dataplane if admission
				// happened after the operation pool. Its reservation must be rolled back.
				if !modification && family.kind != ie.RuleIDTypeFAR {
					rules = append(rules, capacityCreateRule(ie.RuleIDTypeFAR, 1))
				}
				farID := uint32(1)
				if !modification && family.kind == ie.RuleIDTypeFAR {
					farID = 7
				}
				rules = append(rules, ie.NewCreatePDR(ie.NewPDRID(3), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0), ie.NewFTEID(5, 0, nil, nil, 0)), ie.NewFARID(farID)))
				var request message.Message = capacityEstablishment(3, rules...)
				if modification {
					request = message.NewSessionModificationRequest(fseid.SEID, 3, rules...)
				}
				reply := sessionLimitExchange(t, conn, peer, request)
				var cause, failed *ie.IE
				switch response := reply.(type) {
				case *message.SessionEstablishmentResponse:
					cause, failed = response.Cause, response.FailedRuleID
				case *message.SessionModificationResponse:
					cause, failed = response.Cause, response.FailedRuleID
				default:
					t.Fatalf("unexpected response %T", reply)
				}
				expected := ruleFailureIEs(&ruleFailure{family.kind, 7, ebpf.ErrRuleCapacity})
				if got, _ := cause.Cause(); got != ie.CauseNoResourcesAvailable {
					t.Errorf("cause=%d want 75", got)
				}
				if failed == nil || !bytes.Equal(failed.Payload, expected[1].Payload) {
					t.Error("Failed Rule ID differs from physical capacity failure")
				}
				if plane.writes != 0 {
					t.Errorf("refused rules reached map writes: %d", plane.writes)
				}
				if !reflect.DeepEqual(before, snapshotCapacityMaps(t, maps)) {
					t.Error("rejection changed rule maps")
				}
				current := assoc.Sessions[fseid.SEID]
				if len(assoc.Sessions) != 1 || current != beforeOriginal {
					t.Fatal("rejection replaced live session")
				}
				afterSession := cloneSession(current)
				if !reflect.DeepEqual(beforeSession.PDRs, afterSession.PDRs) ||
					!reflect.DeepEqual(beforeSession.FARs, afterSession.FARs) ||
					!reflect.DeepEqual(beforeSession.QERs, afterSession.QERs) ||
					!reflect.DeepEqual(beforeSession.URRs, afterSession.URRs) {
					t.Error("rejection changed live session rules")
				}
				// A later net-zero replacement must fit, even with Create before Remove.
				replacement := message.NewSessionModificationRequest(fseid.SEID, 4, capacityCreateRule(family.kind, 7), capacityRemoveRule(family.kind, 1))
				if got := pipelineCause(t, sessionLimitExchange(t, conn, peer, replacement)); got != ie.CauseRequestAccepted {
					t.Fatalf("net-zero replacement cause=%d", got)
				}
			})
		}
	}
}

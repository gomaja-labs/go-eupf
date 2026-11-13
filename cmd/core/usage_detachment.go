package core

import (
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func usageReferences(session *Session) map[uint32]bool {
	refs := make(map[uint32]bool)
	for _, pdr := range session.PDRs {
		for _, id := range pdr.URRIDs {
			refs[id] = true
		}
	}
	return refs
}

// TS 29.244 V20.1.0 clause 5.2.2.3.1: dissociation from the last
// PDR stops measurement and retains a reset URR. Read/reset happens after the
// PDR operations, after the reclamation grace period, under the same map journal.
func (conn *PfcpConnection) planStoppedUsage(pool *OperationPool, session *Session, previous map[uint32]bool, reports *[]*ie.IE) {
	current := usageReferences(session)
	maps := conn.mapOperations
	for id := range previous {
		if current[id] {
			continue
		}
		if _, exists := session.URRs[id]; !exists {
			continue
		}
		old := session.URRs[id]
		replacement := uint32(0)
		emit := func(counters ebpf.UrrInfo) {
			up := counters.UplinkVolume - old.UrrInfo.UplinkVolume + old.UnreportedUplink
			down := counters.DownlinkVolume - old.UrrInfo.DownlinkVolume + old.UnreportedDownlink
			if up != 0 || down != 0 || replacement != 0 {
				*reports = append(*reports, ie.NewUsageReportWithinSessionModificationResponse(ie.NewURRID(id), conn.profile.URSEQN(old.ReportSeqNumber), ie.NewUsageReportTrigger(0, 1<<3, 0), ie.NewEndTime(time.Now()), ie.NewVolumeMeasurement(7, up+down, up, down, 0, 0, 0)))
			}
		}
		pool.AddRule(ie.RuleIDTypeURR, id, Operation{
			Reserve: func() error {
				proxy, ok := maps.(*sessionMapProxy)
				if !ok || !proxy.asynchronousUsage() {
					return nil
				}
				var err error
				replacement, err = maps.GetNextURR()
				if err != nil {
					return err
				}
				urr := old
				urr.GlobalId = replacement
				urr.ReportSeqNumber++
				urr.UrrInfo.UplinkVolume, urr.UrrInfo.DownlinkVolume = 0, 0
				urr.UnreportedUplink, urr.UnreportedDownlink = 0, 0
				session.URRs[id] = urr
				return nil
			},
			Apply: func() error {
				if replacement == 0 {
					return nil
				}
				return maps.UpdateUrr(replacement, session.URRs[id].UrrInfo)
			},
			Retire: func() error {
				if replacement != 0 {
					return deferUsage(maps, old.GlobalId, emit)
				}
				counters, err := maps.GetUrr(old.GlobalId)
				if err != nil {
					return err
				}
				if err := maps.ResetUrr(old.GlobalId); err != nil {
					return err
				}
				emit(counters)
				urr := old
				if counters.UplinkVolume != old.UrrInfo.UplinkVolume || counters.DownlinkVolume != old.UrrInfo.DownlinkVolume || old.UnreportedUplink+old.UnreportedDownlink > 0 {
					urr.ReportSeqNumber++
				}
				urr.UrrInfo.UplinkVolume, urr.UrrInfo.DownlinkVolume = 0, 0
				urr.UnreportedUplink, urr.UnreportedDownlink = 0, 0
				session.URRs[id] = urr
				return nil
			},
		})
	}
}

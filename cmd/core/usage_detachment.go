package core

import (
	"time"

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
// PDR operations, under the same data-plane admission gate and map journal.
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
		pool.AddRule(ie.RuleIDTypeURR, id, Operation{Apply: func() error {
			urr := session.URRs[id]
			counters, err := maps.GetUrr(urr.GlobalId)
			if err != nil {
				return err
			}
			if err := maps.ResetUrr(urr.GlobalId); err != nil {
				return err
			}
			up, down := counters.UplinkVolume-urr.UrrInfo.UplinkVolume, counters.DownlinkVolume-urr.UrrInfo.DownlinkVolume
			if up != 0 || down != 0 {
				*reports = append(*reports, ie.NewUsageReportWithinSessionModificationResponse(ie.NewURRID(id), conn.profile.URSEQN(urr.ReportSeqNumber), ie.NewUsageReportTrigger(0, 1<<3, 0), ie.NewEndTime(time.Now()), ie.NewVolumeMeasurement(7, up+down, up, down, 0, 0, 0)))
				urr.ReportSeqNumber++
			}
			urr.UrrInfo.UplinkVolume, urr.UrrInfo.DownlinkVolume = 0, 0
			urr.UrrInfo.VolumeReported = false
			session.URRs[id] = urr
			return nil
		}})
	}
}

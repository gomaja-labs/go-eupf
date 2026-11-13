package core

import (
	"fmt"
	"maps"
	"math"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// bufferingActionRule is replaced as a whole during session planning. Sharing an old
// value with a rejected candidate therefore cannot change the active session.
// TS 29.244 V20.1.0 clause 5.2.4.1 permits at most one BAR per session.
type bufferingActionRule struct {
	id                   uint8
	revision             uint64
	notificationDelay    time.Duration
	packetCount          uint16
	packetCountPresent   bool
	durationRevision     uint64
	duration             time.Duration
	durationPresent      bool
	dlPacketCount        uint16
	dlPacketCountPresent bool
}

func bufferingRuleID(value *ie.IE) (uint8, error) {
	if err := requireIEs(requiredIE{ie.BARID, value}); err != nil {
		return 0, err
	}
	id, err := value.BARID()
	if err != nil {
		return 0, invalidRequestIE(ie.BARID, err)
	}
	return id, nil
}

// BAR state is immutable after publication. Null optional IEs remove a
// provisioned parameter; absence preserves it (TS 29.244 V20.1.0 clause 5.6.3).
func applyBARParameters(bar *bufferingActionRule, delay, count, duration, dlCount *ie.IE) error {
	if delay != nil {
		bar.notificationDelay = 0
		if !isNullIE(delay) {
			value, err := delay.DownlinkDataNotificationDelay()
			if err != nil {
				return invalidRequestIE(ie.DownlinkDataNotificationDelay, err)
			}
			bar.notificationDelay = value
		}
	}
	if count != nil {
		bar.packetCount, bar.packetCountPresent = 0, !isNullIE(count)
		if bar.packetCountPresent {
			value, err := count.SuggestedBufferingPacketsCount()
			if err != nil {
				return invalidRequestIE(ie.SuggestedBufferingPacketsCount, err)
			}
			bar.packetCount = uint16(value)
		}
	}
	if duration != nil {
		bar.duration, bar.durationPresent = 0, !isNullIE(duration)
		if bar.durationPresent {
			value, err := duration.DLBufferingDuration()
			if err != nil {
				return invalidRequestIE(ie.DLBufferingDuration, err)
			}
			bar.duration = value
		}
	}
	if dlCount != nil {
		bar.dlPacketCount, bar.dlPacketCountPresent = 0, !isNullIE(dlCount)
		if bar.dlPacketCountPresent {
			value, err := dlCount.DLBufferingSuggestedPacketCount()
			if err != nil {
				return invalidRequestIE(ie.DLBufferingSuggestedPacketCount, err)
			}
			bar.dlPacketCount = value
		}
	}
	return nil
}

func rejectBufferingParameters(values ...*ie.IE) error {
	for _, value := range values {
		if value != nil && !isNullIE(value) {
			return unsupportedRuleIE(value.Type)
		}
	}
	return nil
}

func storeBAR(session *Session, bar *bufferingActionRule, durationUpdated bool) error {
	if session.barRevision == math.MaxUint64 {
		return &requestIEError{ie.CauseSystemFailure, ie.BARID, fmt.Errorf("BAR revision exhausted")}
	}
	session.barRevision++
	bar.revision = session.barRevision
	if durationUpdated {
		bar.durationRevision = bar.revision
	}
	session.bar = bar
	return nil
}

// stageSessionBAR applies to a private candidate only. The capability gate
// continues rejecting BAR until the packet buffering runtime is enabled.
// TS 29.244 V20.1.0 tables 7.5.2.6-1, 7.5.4.11-1, 7.5.4.12-1, 7.5.9.2-1.
func stageSessionBAR(session *Session, request any) error {
	candidate := *session
	var err error
	switch req := request.(type) {
	case *message.SessionEstablishmentRequest:
		err = createBAR(&candidate, req.CreateBAR)
	case *message.SessionModificationRequest:
		if err = removeBAR(&candidate, req.RemoveBAR); err == nil {
			if req.RemoveBAR != nil {
				// Clause 6.3.3.3 removes associations to the deleted BAR.
				candidate.FARs = maps.Clone(session.FARs)
				for id, far := range candidate.FARs {
					far.BARID = nil
					candidate.FARs[id] = far
				}
			}
			err = createBAR(&candidate, req.CreateBAR)
		}
		if err == nil {
			err = updateBAR(&candidate, req.UpdateBAR)
		}
	case *message.SessionReportResponse:
		err = updateBAR(&candidate, req.UpdateBAR)
	}
	if err != nil {
		return err
	}
	session.bar, session.barRevision = candidate.bar, candidate.barRevision
	session.FARs = candidate.FARs
	return nil
}

func retainBARReference(value *ie.IE, far *SFarInfo) error {
	if value == nil {
		return nil
	}
	if isNullIE(value) {
		far.BARID = nil
		return nil
	}
	id, err := bufferingRuleID(value)
	if err != nil {
		return err
	}
	far.BARID = &id
	return nil
}

func validateBARReferences(session *Session) error {
	for id, far := range session.FARs {
		if far.BARID != nil && (session.bar == nil || *far.BARID != session.bar.id) {
			return &ruleFailure{ie.RuleIDTypeFAR, id, fmt.Errorf("unknown referenced BAR %d", *far.BARID)}
		}
	}
	return nil
}

func createBAR(session *Session, value *ie.IE) error {
	if value == nil {
		return nil
	}
	fields, err := value.CreateBAR()
	if err != nil {
		return err
	}
	id, err := bufferingRuleID(fields.BARID)
	if err != nil {
		return err
	}
	if session.bar != nil {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), fmt.Errorf("session already contains BAR %d", session.bar.id)}
	}
	if err := rejectBufferingParameters(fields.MTEDTControlInformation, fields.MTSDTControlInformation); err != nil {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), err}
	}
	// Table 7.5.2.6-1: BAR ID zero is a present, valid identifier.
	bar := &bufferingActionRule{id: id}
	if err := applyBARParameters(bar, fields.DownlinkDataNotificationDelay, fields.SuggestedBufferingPacketsCount, fields.DLBufferingDuration, fields.DLBufferingSuggestedPacketCount); err != nil {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), err}
	}
	return storeBAR(session, bar, fields.DLBufferingDuration != nil)
}

func updateBAR(session *Session, value *ie.IE) error {
	if value == nil {
		return nil
	}
	var idIE, delay, count, duration, dlCount *ie.IE
	switch value.Type {
	case ie.UpdateBARWithinSessionModificationRequest:
		fields, err := value.UpdateBARWithinSessionModificationRequest()
		if err != nil {
			return err
		}
		if err := rejectBufferingParameters(fields.MTEDTControlInformation, fields.MTSDTControlInformation, fields.ExtendedDLBufferingNotificationPolicy); err != nil {
			return err
		}
		idIE, delay, count, duration, dlCount = fields.BARID, fields.DownlinkDataNotificationDelay, fields.SuggestedBufferingPacketsCount, fields.DLBufferingDuration, fields.DLBufferingSuggestedPacketCount
	case ie.UpdateBARWithinSessionReportResponse:
		fields, err := value.UpdateBARWithinSessionReportResponse()
		if err != nil {
			return err
		}
		if err := rejectBufferingParameters(fields.ExtendedDLBufferingNotificationPolicy); err != nil {
			return err
		}
		idIE, delay, count, duration, dlCount = fields.BARID, fields.DownlinkDataNotificationDelay, fields.SuggestedBufferingPacketsCount, fields.DLBufferingDuration, fields.DLBufferingSuggestedPacketCount
	default:
		return &ie.InvalidTypeError{Type: value.Type}
	}

	id, err := bufferingRuleID(idIE)
	if err != nil {
		return err
	}
	if session.bar == nil || session.bar.id != id {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), fmt.Errorf("BAR %d does not exist: %w", id, ErrSessionNotFound)}
	}
	bar := *session.bar
	if err := applyBARParameters(&bar, delay, count, duration, dlCount); err != nil {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), err}
	}
	return storeBAR(session, &bar, duration != nil)
}

func removeBAR(session *Session, value *ie.IE) error {
	if value == nil {
		return nil
	}
	fields, err := value.RemoveBAR()
	if err != nil {
		return err
	}
	id, err := bufferingRuleID(fields.BARID)
	if err != nil {
		return err
	}
	if session.bar == nil || session.bar.id != id {
		return &ruleFailure{ie.RuleIDTypeBAR, uint32(id), fmt.Errorf("BAR %d does not exist: %w", id, ErrSessionNotFound)}
	}
	// Table 7.5.4.12-1: removal affects only the candidate session.
	session.bar = nil
	return nil
}

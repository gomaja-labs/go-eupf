package core

import (
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog"
)

func TestBARStoresBufferingParameters(t *testing.T) {
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0),
		ie.NewDownlinkDataNotificationDelay(150*time.Millisecond),
		ie.NewSuggestedBufferingPacketsCount(8))); err != nil {
		t.Fatalf("create BAR with delay and shared packet bound: %v", err)
	}
	if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0),
		ie.NewDLBufferingDuration(4*time.Second), ie.NewDLBufferingSuggestedPacketCount(5))); err != nil {
		t.Fatalf("update extended buffering: %v", err)
	}
	bar := session.bar
	if bar.id != 0 || bar.notificationDelay != 150*time.Millisecond || !bar.packetCountPresent || bar.packetCount != 8 || !bar.durationPresent || bar.duration != 4*time.Second || !bar.dlPacketCountPresent || bar.dlPacketCount != 5 {
		t.Fatalf("buffering instructions were not retained: %+v", bar)
	}
}

func TestBARPlanningIsAtomicAndSessionScoped(t *testing.T) {
	session := NewSession(1, 2, "", "", false)
	create := func(id uint8) *message.SessionEstablishmentRequest {
		return message.NewSessionEstablishmentRequest(0, 1, ie.NewCreateBAR(ie.NewBARID(id), ie.NewSuggestedBufferingPacketsCount(7)))
	}
	if err := stageSessionBAR(session, create(0)); err != nil {
		t.Fatal(err)
	}
	original := session.bar
	for _, request := range []message.Message{
		create(0), create(1),
		message.NewSessionModificationRequest(1, 2, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(1))),
		message.NewSessionModificationRequest(1, 2, ie.NewRemoveBAR(ie.NewBARID(1))),
		message.NewSessionModificationRequest(1, 2, ie.NewRemoveBAR(ie.NewBARID(0)), ie.NewCreateBAR(ie.NewBARID(1)), ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(2))),
	} {
		if err := stageSessionBAR(session, request); err == nil {
			t.Fatalf("accepted conflicting/missing BAR in %T", request)
		}
		if session.bar != original || session.barRevision != 1 {
			t.Fatalf("rejected plan changed the live BAR: %+v", session.bar)
		}
	}
	other := NewSession(2, 3, "", "", false)
	if err := stageSessionBAR(other, create(0)); err != nil {
		t.Fatalf("another session could not use BAR zero: %v", err)
	}
	candidate := cloneSession(session)
	if err := stageSessionBAR(candidate, message.NewSessionModificationRequest(1, 2, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(9)))); err != nil {
		t.Fatal(err)
	}
	if session.bar.packetCount != 7 || candidate.bar.packetCount != 9 || candidate.bar.revision != 2 || session.bar != original {
		t.Fatal("candidate BAR update changed its live predecessor")
	}
	if err := stageSessionBAR(candidate, message.NewSessionModificationRequest(1, 3, ie.NewRemoveBAR(ie.NewBARID(0)), ie.NewCreateBAR(ie.NewBARID(255)))); err != nil {
		t.Fatal(err)
	}
	if candidate.bar.id != 255 || candidate.bar.revision != 3 || session.bar.id != 0 {
		t.Fatal("remove/create did not retain independent lifetimes")
	}
	if err := stageSessionBAR(candidate, message.NewSessionModificationRequest(1, 4, ie.NewRemoveBAR(ie.NewBARID(255)))); err != nil || candidate.bar != nil {
		t.Fatalf("remove BAR: %v", err)
	}
}

func TestBARReportResponseUpdateAndNullRemoval(t *testing.T) {
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(7), ie.NewDownlinkDataNotificationDelay(50*time.Millisecond), ie.NewSuggestedBufferingPacketsCount(4))); err != nil {
		t.Fatal(err)
	}
	original := session.bar
	response := message.NewSessionReportResponse(1, 9, ie.NewCause(ie.CauseRequestAccepted),
		ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(7), ie.NewDLBufferingDuration(6*time.Second), ie.NewDLBufferingSuggestedPacketCount(8)))
	if err := stageSessionBAR(session, response); err != nil {
		t.Fatal(err)
	}
	if session.bar.notificationDelay != 50*time.Millisecond || session.bar.packetCount != 4 || session.bar.duration != 6*time.Second || session.bar.dlPacketCount != 8 || session.bar.revision != 2 || original.durationPresent {
		t.Fatalf("response lost existing fields or changed its predecessor: %+v", session.bar)
	}
	response.UpdateBAR = ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(7), ie.NewDownlinkDataNotificationDelay(0),
		ie.New(ie.SuggestedBufferingPacketsCount, nil), ie.New(ie.DLBufferingDuration, nil), ie.New(ie.DLBufferingSuggestedPacketCount, nil))
	if err := stageSessionBAR(session, response); err != nil {
		t.Fatal(err)
	}
	if session.bar.notificationDelay != 0 || session.bar.packetCountPresent || session.bar.durationPresent || session.bar.dlPacketCountPresent {
		t.Fatalf("null removal retained provisioned parameters: %+v", session.bar)
	}
	response.UpdateBAR = ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(7), ie.NewSuggestedBufferingPacketsCount(0), ie.NewDLBufferingSuggestedPacketCount(0), ie.New(ie.DLBufferingDuration, []byte{0}))
	if err := stageSessionBAR(session, response); err != nil {
		t.Fatal(err)
	}
	if !session.bar.packetCountPresent || !session.bar.durationPresent || !session.bar.dlPacketCountPresent || session.bar.packetCount != 0 || session.bar.duration != 0 || session.bar.dlPacketCount != 0 {
		t.Fatalf("explicit zero was treated as absence: %+v", session.bar)
	}
}

func TestBARTimerUnitsAndCountBounds(t *testing.T) {
	for _, tc := range []struct {
		octet byte
		want  time.Duration
	}{
		{0, 0}, {31, 62 * time.Second}, {0x3f, 31 * time.Minute}, {0x5f, 310 * time.Minute},
		{0x7f, 31 * time.Hour}, {0x9f, 310 * time.Hour}, {0xa1, time.Minute}, {0xc2, 2 * time.Minute}, {0xe0, math.MaxInt64},
	} {
		session := NewSession(1, 2, "", "", false)
		err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(255), ie.New(ie.DLBufferingDuration, []byte{tc.octet}),
			ie.NewDownlinkDataNotificationDelay(12750*time.Millisecond), ie.NewSuggestedBufferingPacketsCount(255), ie.NewDLBufferingSuggestedPacketCount(65535)))
		if err != nil {
			t.Fatal(err)
		}
		if session.bar.duration != tc.want || session.bar.packetCount != 255 || session.bar.dlPacketCount != 65535 || session.bar.notificationDelay != 12750*time.Millisecond {
			t.Fatalf("unit %d: %+v want duration %s", tc.octet, session.bar, tc.want)
		}
	}
}

func TestBARRejectsInvalidUpdatesWithoutChangingState(t *testing.T) {
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(5))); err != nil {
		t.Fatal(err)
	}
	original := session.bar
	for _, field := range []*ie.IE{
		ie.New(ie.ExtendedDLBufferingNotificationPolicy, []byte{1}),
		ie.New(ie.MTEDTControlInformation, []byte{1}), ie.New(ie.MTSDTControlInformation, []byte{1}),
	} {
		err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(9), field))
		if err == nil || session.bar != original || session.barRevision != 1 {
			t.Fatalf("invalid field %s changed BAR: error=%v BAR=%+v", field.Type, err, session.bar)
		}
	}
	for _, id := range []*ie.IE{nil, ie.New(ie.BARID, nil)} {
		fresh := NewSession(1, 2, "", "", false)
		err := createBAR(fresh, ie.NewCreateBAR(id))
		if err == nil || fresh.bar != nil {
			t.Fatal("created BAR without a valid identity")
		}
		var failure *requestIEError
		if !errors.As(err, &failure) || failure.offending != ie.BARID {
			t.Fatalf("missing/invalid ID lost Offending IE: %v", err)
		}
	}
	session.barRevision = math.MaxUint64
	if err := updateBAR(session, ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0))); err == nil || session.bar != original {
		t.Fatal("BAR revision wrapped and could alias a stale response")
	}
}

func TestBARSurvivesRejectedRuleTransaction(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	session := NewSession(2, 42, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(7))); err != nil {
		t.Fatal(err)
	}
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
	if err != nil || cause == ie.CauseRequestAccepted || !reflect.DeepEqual(conn.GetAssociation(peer).Sessions[2], before) {
		t.Fatalf("rejected transaction changed BAR/session: cause=%d error=%v", cause, err)
	}
}

func TestFARBindingRetainsBARZeroAndRemovesNullReference(t *testing.T) {
	conn, _ := PreparePfcpConnection(t)
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		t.Fatal(err)
	}
	pool := NewOperationPool()
	err := createFARs([]*ie.IE{ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1), ie.NewBARID(0))}, conn.mapOperations, session, pool, zerolog.Nop(), conn.profile)
	if err != nil {
		t.Fatal(err)
	}
	if session.FARs[1].BARID == nil || *session.FARs[1].BARID != 0 {
		t.Fatal("FAR lost its present BAR zero reference")
	}
	err = updateFARs([]*ie.IE{ie.NewUpdateFAR(ie.NewFARID(1), ie.New(ie.BARID, nil))}, conn.mapOperations, session, pool, zerolog.Nop(), conn.profile, nil)
	if err != nil || session.FARs[1].BARID != nil {
		t.Fatalf("null BAR ID did not remove FAR reference: %v", err)
	}
}

func TestBARRemovalDetachesFARsOnlyInCandidate(t *testing.T) {
	conn, _ := PreparePfcpConnection(t)
	session := NewSession(1, 2, "", "", false)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		t.Fatal(err)
	}
	id := uint8(0)
	session.FARs[1] = SFarInfo{BARID: &id, FarInfo: ebpf.FarInfo{Action: 1}}
	if err := validateSessionRuleShapes(conn, session); err != nil {
		t.Fatalf("valid BAR binding rejected: %v", err)
	}
	candidate := cloneSession(session)
	if err := stageSessionBAR(candidate, message.NewSessionModificationRequest(1, 2, ie.NewRemoveBAR(ie.NewBARID(0)))); err != nil {
		t.Fatal(err)
	}
	if candidate.FARs[1].BARID != nil || session.FARs[1].BARID == nil || session.bar == nil {
		t.Fatal("BAR removal retained a dangling FAR reference or changed its predecessor")
	}
	candidate.FARs[1] = session.FARs[1]
	if err := validateSessionRuleShapes(conn, candidate); err == nil {
		t.Fatal("accepted reference to a removed BAR")
	}
	if err := createBAR(candidate, ie.NewCreateBAR(ie.NewBARID(1))); err != nil {
		t.Fatal(err)
	}
	if err := validateSessionRuleShapes(conn, candidate); err == nil {
		t.Fatal("accepted reference to a different BAR ID")
	}
}

func FuzzBARPlanning(f *testing.F) {
	for _, group := range []*ie.IE{
		ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(8)),
		ie.NewUpdateBARWithinSessionModificationRequest(ie.NewBARID(0), ie.New(ie.DLBufferingDuration, []byte{0xa1})),
		ie.NewRemoveBAR(ie.NewBARID(0)),
		ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingSuggestedPacketCount(256)),
	} {
		wire, err := group.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := ie.Parse(data)
		if err != nil {
			return
		}
		session := NewSession(1, 2, "", "", false)
		if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(7))); err != nil {
			t.Fatal(err)
		}
		before := *session.bar
		original := session.bar
		candidate := cloneSession(session)
		switch value.Type {
		case ie.CreateBAR:
			err = stageSessionBAR(candidate, message.NewSessionEstablishmentRequest(0, 1, value))
		case ie.UpdateBARWithinSessionModificationRequest, ie.RemoveBAR:
			err = stageSessionBAR(candidate, message.NewSessionModificationRequest(1, 1, value))
		case ie.UpdateBARWithinSessionReportResponse:
			err = stageSessionBAR(candidate, message.NewSessionReportResponse(1, 1, value))
		default:
			return
		}
		if *session.bar != before || session.barRevision != 1 || session.bar != original {
			t.Fatal("BAR planning modified the original session")
		}
		if err != nil && (candidate.bar != original || candidate.barRevision != 1) {
			t.Fatal("rejected plan changed its candidate")
		}
	})
}

package core

import (
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestDownlinkBARDoesNotSuppressUnassociatedFAR(t *testing.T) {
	conn, _, session, _ := downlinkFixture(t, true)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	id := uint8(0)
	far := session.FARs[1]
	far.BARID = &id
	session.FARs[1] = far
	far = session.FARs[2]
	far.BARID = nil
	session.FARs[2] = far
	now := time.Now()
	conn.stateMu.Lock()
	conn.noteDownlinkPacketLocked(session, 1, ebpf.BufferRecord{SessionID: 11, Cookie: 7, PDRID: 1, Notify: true}, now)
	conn.noteDownlinkPacketLocked(session, 2, ebpf.BufferRecord{SessionID: 11, Cookie: 8, PDRID: 2, Notify: true}, now)
	pending := append([]downlinkNotice(nil), session.downlink.pending...)
	conn.stateMu.Unlock()
	if len(pending) != 1 || pending[0].farID != 2 {
		t.Fatal("BAR suppressed a FAR that is not associated with it")
	}
}

func TestDownlinkExpiredWindowCannotNotifyFromDelayedOldRecord(t *testing.T) {
	conn, _, session, _ := downlinkFixture(t, true)
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second))); err != nil {
		t.Fatal(err)
	}
	id := uint8(0)
	far := session.FARs[1]
	far.BARID = &id
	session.FARs[1] = far
	now := time.Now()
	conn.stateMu.Lock()
	defer conn.stateMu.Unlock()
	conn.applyDownlinkDurationLocked(session, now)
	conn.applyDownlinkDurationLocked(session, now.Add(2*time.Second))
	conn.noteDownlinkPacketLocked(session, 1, ebpf.BufferRecord{SessionID: 11, Cookie: 7, PDRID: 1, Notify: true}, now.Add(time.Second))
	if len(session.downlink.pending) != 0 {
		t.Fatal("delayed record from the suppression interval generated a new report")
	}
	conn.noteDownlinkPacketLocked(session, 1, ebpf.BufferRecord{SessionID: 11, Cookie: 7, PDRID: 2, Notify: true}, now.Add(2*time.Second))
	if len(session.downlink.pending) != 1 || session.downlink.pending[0].pdrID != 2 {
		t.Fatal("first packet after extended buffering did not rearm")
	}
}

//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBufferAdmissionRecordsProcessedDownlink(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 12, BufferSessionID: 42, BufferCookie: 7, BufferLane: 0}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink([]byte{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3, QerIDs: []uint32{1}, UrrIDs: []uint32{1}, NRFlag: true}); err != nil {
		t.Fatal(err)
	}
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Qfi: 0, QfiPresent: 1})
	packet := ethernetDatapath(t, 0x0800, udpDatapath(t, false))
	action, _, err := b.UpfIpEntrypointFunc.Test(packet)
	if err != nil || action != 1 {
		t.Fatalf("buffer packet action=%d error=%v", action, err)
	}
	reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
	record, err := reader.Read()
	if err != nil {
		t.Fatalf("BUFF|NOCP produced no admission record: %v", err)
	}
	if record.SessionID != 42 || record.Cookie != 7 || record.Sequence != 1 || record.PDRID != 9 || !record.Notify || !record.QFIPresent || record.QFI != 0 || record.Kind != 1 {
		t.Fatalf("incorrect admission metadata: %+v", record)
	}
	if record.Packet[22] != 63 {
		t.Fatalf("buffered TTL=%d want processed TTL 63", record.Packet[22])
	}
	if got := binary.BigEndian.Uint16(record.Packet[16:18]); got != 32 {
		t.Fatalf("buffered IPv4 length=%d", got)
	}
	counters, err := b.GetUrr(1)
	if err != nil || counters.DownlinkVolume != 32 {
		t.Fatalf("usage=%+v error=%v", counters, err)
	}
}

func bufferedFrame(t *testing.T, destination byte, id uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Id: id, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, destination}}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, udp, gopacket.Payload([]byte{1, 2, 3, 4})))
}

func TestBufferCreditsAreSharedAcrossFARsAndCompletionIsIdempotent(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := b.NewBufferReader(); err == nil {
		t.Fatal("claimed the shared ring twice")
	}
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}, {Index: 1, Cookie: 8, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	for lane := uint32(0); lane < 2; lane++ {
		if err := b.UpdateFar(3+lane, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7 + uint64(lane), BufferLane: lane}); err != nil {
			t.Fatal(err)
		}
		if err := b.PutPdrDownlink(net.IP{198, 51, 100, byte(2 + lane)}, PdrInfo{SessionID: 42, PdrID: 9 + lane, FarId: 3 + lane}); err != nil {
			t.Fatal(err)
		}
	}
	for i, destination := range []byte{2, 3, 3} {
		action, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, destination, uint16(i+1)))
		if err != nil || action != 1 {
			t.Fatalf("admit %d: %d %v", i, action, err)
		}
	}
	for i := 0; i < 2; i++ {
		reader.SetDeadline(time.Now().Add(time.Second))
		if _, err := reader.Read(); err != nil {
			t.Fatal(err)
		}
	}
	reader.SetDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := reader.Read(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("session exceeded shared limit: %v", err)
	}
	command := BufferCommand{SessionID: 42, Cookie: 7, Lane: 0, Operation: 3}
	state, err := b.BufferControl(command)
	if err != nil || state.Produced != 1 || state.Completed != 0 || state.Outstanding != 2 {
		t.Fatalf("admission state=%+v error=%v", state, err)
	}
	command.Operation = 0
	command.Sequence = 1
	for i := 0; i < 2; i++ {
		state, err = b.BufferControl(command)
		if err != nil || state.Outstanding != 1 {
			t.Fatalf("completion %d state=%+v error=%v", i, state, err)
		}
	}
	command.Cookie = 8
	command.Lane = 1
	command.Sequence = 2
	if _, err := b.BufferControl(command); err == nil {
		t.Fatal("out-of-order completion accepted")
	}
	command.Cookie = 99
	command.Sequence = 1
	if _, err := b.BufferControl(command); err == nil {
		t.Fatal("stale lifetime completion accepted")
	}
	command.Cookie = 8
	command.Operation = 1
	command.Mode = BufferDiscard
	command.Sequence = 0
	if _, err := b.BufferControl(command); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 3, 4)); err != nil {
		t.Fatal(err)
	}
	reader.SetDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := reader.Read(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("discarded lifetime admitted a late packet: %v", err)
	}
	command.Operation = 0
	command.Sequence = 1
	command.Mode = 0
	state, err = b.BufferControl(command)
	if err != nil || state.Outstanding != 0 {
		t.Fatalf("cancel completion=%+v error=%v", state, err)
	}
}

func TestBufferAdmissionSequencesConcurrentProducers(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	const count = 128
	if err := b.CreateBufferAnchor(42, count, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	packets := make([][]byte, count)
	for i := range count {
		packets[i] = bufferedFrame(t, 2, uint16(i+1))
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := worker; i < count; i += 8 {
				action, _, err := b.UpfIpEntrypointFunc.Test(packets[i])
				if err != nil || action != 1 {
					t.Errorf("producer %d action=%d error=%v", i, action, err)
				}
			}
		}()
	}
	wg.Wait()
	sequences, ids := make(map[uint64]bool), make(map[uint16]bool)
	for range count {
		reader.SetDeadline(time.Now().Add(time.Second))
		record, err := reader.Read()
		if err != nil {
			t.Fatal(err)
		}
		id := binary.BigEndian.Uint16(record.Packet[18:20])
		if record.Sequence < 1 || record.Sequence > count || sequences[record.Sequence] || id < 1 || id > count || ids[id] {
			t.Fatalf("duplicate or missing admission sequence=%d packet=%d", record.Sequence, id)
		}
		sequences[record.Sequence] = true
		ids[id] = true
		for _, v := range reader.record.RawSample[64+len(record.Packet):] {
			if v != 0 {
				t.Fatal("fixed slot exposed unused packet bytes")
			}
		}
	}
	command, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || command.Produced != count || command.Outstanding != count || command.Preparing != 0 {
		t.Fatalf("concurrent accounting=%+v error=%v", command, err)
	}
}

func TestBufferReservationFailureCannotStrandASequence(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := b.CreateBufferAnchor(42, 5000, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	packet := bufferedFrame(t, 2, 1)
	for range 2300 {
		if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
			t.Fatal(err)
		}
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Produced == 0 || state.Produced >= 2300 || state.Outstanding != uint32(state.Produced) || state.Preparing != 0 {
		t.Fatalf("ring did not reach its finite bound: %+v error=%v", state, err)
	}
	for sequence := uint64(1); sequence <= state.Produced; sequence++ {
		reader.SetDeadline(time.Now().Add(time.Second))
		record, err := reader.Read()
		if err != nil || record.Sequence != sequence {
			t.Fatalf("stranded sequence %d, got %d error=%v", sequence, record.Sequence, err)
		}
	}
	if _, _, err := b.UpfIpEntrypointFunc.Test(packet); err != nil {
		t.Fatal(err)
	}
	reader.SetDeadline(time.Now().Add(time.Second))
	record, err := reader.Read()
	if err != nil || record.Sequence != state.Produced+1 {
		t.Fatalf("post-overflow admission got %d error=%v", record.Sequence, err)
	}
}

func TestBufferControlCannotBypassTheDrainBarrier(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	_, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferForward})
	if err == nil {
		t.Fatal("control published ordinary forwarding without producer grace or completion")
	}
}

func TestBufferUnloadedObjectsReturnErrors(t *testing.T) {
	b := NewBpfObjects()
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err == nil {
		t.Fatal("unloaded anchor succeeded")
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3}); err == nil {
		t.Fatal("unloaded control succeeded")
	}
	if _, err := b.NewBufferReader(); err == nil {
		t.Fatal("unloaded reader succeeded")
	}
}

func TestBufferReaderClosesWithItsObjects(t *testing.T) {
	b := loadDatapath(t)
	reader, err := b.NewBufferReader()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := reader.Read(); done <- err }()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("closed reader returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing maps did not release their reader")
	}
}

func TestBufferJournalRestoresModeWithoutRestoringLiveCounters(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	if err := b.UpdateFar(3, FarInfo{Action: 4, BufferSessionID: 42, BufferCookie: 7}); err != nil {
		t.Fatal(err)
	}
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{SessionID: 42, PdrID: 9, FarId: 3}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.UpfIpEntrypointFunc.Test(bufferedFrame(t, 2, 1)); err != nil {
		t.Fatal(err)
	}
	tx, err := b.BeginRuleTransaction(42)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	journal, ok := tx.(interface {
		JournalBufferControl(BufferCommand) error
		BufferGrace() <-chan struct{}
	})
	if !ok {
		t.Fatal("buffer admission state is outside the rule journal")
	}
	grace := journal.BufferGrace()
	if err := journal.JournalBufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDiscard}); err != nil {
		t.Fatal(err)
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Mode != BufferDiscard {
		t.Fatalf("staged mode=%+v error=%v", state, err)
	}
	if _, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-grace:
		t.Fatal("uncommitted journal reported producer grace")
	default:
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-grace:
	case <-time.After(2 * time.Second):
		t.Fatal("rollback did not signal producer grace")
	}
	state, err = b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 3})
	if err != nil || state.Mode != BufferHold || state.Produced != 1 || state.Completed != 1 || state.Outstanding != 0 {
		t.Fatalf("rollback overwrote live counters: %+v error=%v", state, err)
	}
}

func TestBufferPreparedProducerPreventsDirectMode(t *testing.T) {
	b := loadDatapath(t)
	if err := b.CreateBufferAnchor(42, 2, []BufferLane{{Index: 0, Cookie: 7, Mode: BufferHold}}); err != nil {
		t.Fatal(err)
	}
	// Synthetic producer paused between eligibility and the copy continuation.
	// The anchor's first lane has its preparing count after the 32-byte state.
	raw, err := b.BufferAnchors.LookupBytes(uint64(42))
	if err != nil || len(raw) < 52 {
		t.Fatalf("anchor: %v", err)
	}
	binary.LittleEndian.PutUint32(raw[48:], 1)
	if err := b.BufferAnchors.Put(uint64(42), raw); err != nil {
		t.Fatal(err)
	}
	state, err := b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDrain, Ready: 1})
	if err != nil || state.Mode != BufferDrain {
		t.Fatalf("prepared producer was bypassed: mode=%d error=%v", state.Mode, err)
	}
	binary.LittleEndian.PutUint32(raw[48:], 0)
	if err := b.BufferAnchors.Put(uint64(42), raw); err != nil {
		t.Fatal(err)
	}
	state, err = b.BufferControl(BufferCommand{SessionID: 42, Cookie: 7, Operation: 1, Mode: BufferDrain, Ready: 1})
	if err != nil || state.Mode != BufferForward {
		t.Fatalf("finished producers did not release barrier: mode=%d error=%v", state.Mode, err)
	}
}

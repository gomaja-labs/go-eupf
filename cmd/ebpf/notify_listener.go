package ebpf

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type SdfEvent struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	proto   uint8
}

func (e *SdfEvent) UnmarshalIPv4(buffer []byte) error {
	if len(buffer) < 13 {
		return fmt.Errorf("IPv4 SDF tuple: %w", io.ErrUnexpectedEOF)
	}

	e.srcIP = append(net.IP(nil), buffer[:4]...)
	e.dstIP = append(net.IP(nil), buffer[4:8]...)
	e.srcPort = binary.BigEndian.Uint16(buffer[8:10])
	e.dstPort = binary.BigEndian.Uint16(buffer[10:12])
	e.proto = buffer[12]
	return nil
}

func (e *SdfEvent) UnmarshalIPv6(buffer []byte) error {
	if len(buffer) < 37 {
		return fmt.Errorf("IPv6 SDF tuple: %w", io.ErrUnexpectedEOF)
	}

	e.srcIP = append(net.IP(nil), buffer[:16]...)
	e.dstIP = append(net.IP(nil), buffer[16:32]...)
	e.srcPort = binary.BigEndian.Uint16(buffer[32:34])
	e.dstPort = binary.BigEndian.Uint16(buffer[34:36])
	e.proto = buffer[36]
	return nil
}

func (e *SdfEvent) String() string {

	if len(e.srcIP) != len(e.dstIP) || (len(e.srcIP) != 4 && len(e.srcIP) != 16) {
		return ""
	}

	if e.proto == 6 || e.proto == 17 || e.proto == 132 {
		return fmt.Sprintf("permit in %d from %v/%d %d to %v/%d %d", e.proto, e.srcIP, len(e.srcIP)*8, e.srcPort, e.dstIP, len(e.srcIP)*8, e.dstPort)
	} else {
		return fmt.Sprintf("permit in %d from %v/%d to %v/%d", e.proto, e.srcIP, len(e.srcIP)*8, e.dstIP, len(e.srcIP)*8)
	}
}

// SdfFlowNotification identifies the session and PDR that matched a flow.
// IDs remain control-plane identities, independently of tunnel/address keys.
type SdfFlowNotification struct {
	SessionID uint64
	PDRID     uint32
	SDFFilter string
}

type SdfNotifyListener struct {
	reader          *perf.Reader
	notifyC         chan SdfFlowNotification
	mu              sync.Mutex
	running, closed bool
	done            chan struct{}
	wg              sync.WaitGroup
	closeChannel    sync.Once
}

func NewSdfNotifyListener(eventMap *ebpf.Map) (*SdfNotifyListener, error) {

	reader, err := perf.NewReader(eventMap, 4096)
	if err != nil {
		return nil, fmt.Errorf("create SDF notification reader: %w", err)
	}

	return &SdfNotifyListener{
		reader:  reader,
		notifyC: make(chan SdfFlowNotification, 64),
		done:    make(chan struct{}),
	}, nil
}

// Close cancels the sender, unblocks the reader and waits before closing the
// notification channel. It is safe to call repeatedly and concurrently.
func (l *SdfNotifyListener) Close() {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.done)
		_ = l.reader.Close()
	}
	l.mu.Unlock()
	l.wg.Wait()
	l.closeChannel.Do(func() { close(l.notifyC) })
}

func (l *SdfNotifyListener) SetNonblocked() {
	l.reader.SetDeadline(time.Now())
}

func (l *SdfNotifyListener) GetNotificationChannel() <-chan SdfFlowNotification {
	return l.notifyC
}

func (l *SdfNotifyListener) readEvent(rec *perf.Record) (*SdfFlowNotification, error) {
	if err := l.reader.ReadInto(rec); err != nil {
		return nil, fmt.Errorf("read SDF notification: %w", err)
	}

	return parseSdfRecord(rec)
}

func parseSdfRecord(rec *perf.Record) (*SdfFlowNotification, error) {
	if rec.LostSamples > 0 {
		return nil, fmt.Errorf("lost samples from sdf notification map: %d", rec.LostSamples)
	}

	var sdf SdfEvent
	sampleLength := len(rec.RawSample)
	if sampleLength < 14 {
		return nil, fmt.Errorf("SDF envelope: %w", io.ErrUnexpectedEOF)
	}
	magic := binary.LittleEndian.Uint16(rec.RawSample[:2])
	sessionID := binary.LittleEndian.Uint64(rec.RawSample[2:10])
	pdrID := binary.LittleEndian.Uint32(rec.RawSample[10:14])
	switch magic {
	case 0x1ea1:
		if sampleLength < 27 {
			return nil, fmt.Errorf("perf sample for IPv4 SDF too small: %d", sampleLength)
		}
		if err := sdf.UnmarshalIPv4(rec.RawSample[14:]); err != nil {
			return nil, err
		}
	case 0x2ea2:
		if sampleLength < 51 {
			return nil, fmt.Errorf("perf sample for IPv6 SDF too small: %d", sampleLength)
		}
		if err := sdf.UnmarshalIPv6(rec.RawSample[14:]); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown event: %d", magic)
	}

	return &SdfFlowNotification{SessionID: sessionID, PDRID: pdrID, SDFFilter: sdf.String()}, nil
}

func (l *SdfNotifyListener) ReadEventOnce() (*SdfFlowNotification, error) {
	var rec perf.Record
	return l.readEvent(&rec)
}

func (l *SdfNotifyListener) ReadEventLoop() {
	l.mu.Lock()
	if l.closed || l.running {
		l.mu.Unlock()
		return
	}
	l.running = true
	l.wg.Add(1)
	l.mu.Unlock()
	defer l.wg.Done()
	defer l.closeChannel.Do(func() { close(l.notifyC) })
	var rec perf.Record
	for {
		if err := l.reader.ReadInto(&rec); err != nil {
			return
		}
		notification, err := parseSdfRecord(&rec)
		if err != nil {
			continue
		}
		// Bounded delivery: a slow consumer cannot stall shutdown or the perf ring.
		select {
		case <-l.done:
			return
		case l.notifyC <- *notification:
		default:
		}
	}
}

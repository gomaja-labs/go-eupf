//go:build linux

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

type bufferPFCPCapture struct {
	stop, done chan struct{}
	once       sync.Once
	data       []byte
	err        error
}

func startBufferPFCPCapture(t *testing.T, limits ...int) *bufferPFCPCapture {
	limit := 1 << 20
	if len(limits) > 0 {
		limit = limits[0]
	}
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0x0300)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20); err != nil {
		t.Fatal(errors.Join(err, unix.Close(fd)))
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: 0x0300}); err != nil {
		t.Fatal(errors.Join(err, unix.Close(fd)))
	}
	capture := &bufferPFCPCapture{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(capture.done)
		defer func() {
			stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
			capture.err = errors.Join(capture.err, err)
			if stats != nil && stats.Drops != 0 {
				capture.err = errors.Join(capture.err, fmt.Errorf("PFCP fixture capture lost %d packets", stats.Drops))
			}
			capture.err = errors.Join(capture.err, unix.Close(fd))
		}()
		var data bytes.Buffer
		writer := pcapgo.NewWriter(&data)
		if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
			capture.err = err
			return
		}
		defer func() { capture.data = data.Bytes() }()
		frame := make([]byte, 65535)
		for {
			n, address, err := unix.Recvfrom(fd, frame, unix.MSG_DONTWAIT)
			if errors.Is(err, unix.EAGAIN) {
				select {
				case <-capture.stop:
					return
				default:
				}
				_, err = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 20)
				if err != nil && !errors.Is(err, unix.EINTR) {
					capture.err = err
					return
				}
				continue
			}
			if err != nil {
				capture.err = err
				return
			}
			link, ok := address.(*unix.SockaddrLinklayer)
			if !ok || link.Pkttype == unix.PACKET_OUTGOING || n < 50 || frame[12] != 8 || frame[13] != 0 || frame[23] != 17 {
				continue
			}
			if binary.BigEndian.Uint16(frame[34:36]) != 8805 && binary.BigEndian.Uint16(frame[36:38]) != 8805 {
				continue
			}
			if frame[43] != message.MsgTypeSessionReportRequest && frame[43] != message.MsgTypeSessionReportResponse {
				continue
			}
			if data.Len() > limit {
				capture.err = errors.New("PFCP capture exceeded its bounded fixture")
				return
			}
			if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: n, Length: n}, frame[:n]); err != nil {
				capture.err = err
				return
			}
		}
	}()
	t.Cleanup(func() {
		capture.close()
		if capture.err != nil {
			t.Error(capture.err)
		}
	})
	return capture
}
func (capture *bufferPFCPCapture) close() {
	capture.once.Do(func() { close(capture.stop) })
	<-capture.done
}
func readBufferWireReport(t *testing.T, peer *net.UDPConn) *message.SessionReportRequest {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 65535)
	n, _, err := peer.ReadFromUDP(wire)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := message.Parse(wire[:n])
	if err != nil {
		t.Fatal(err)
	}
	report, ok := parsed.(*message.SessionReportRequest)
	if !ok {
		t.Fatalf("unexpected message %T", parsed)
	}
	return report
}
func TestApplicationBufferPFCPReportControlsOnTheSocket(t *testing.T) {
	plane, buffering, conn, assoc, session, peer := publishPacketBufferFixture(t)
	conn.stateMu.Lock()
	if err := createBAR(session, ie.NewCreateBAR(ie.NewBARID(0))); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	barID := uint8(0)
	far := session.FARs[1]
	far.BARID = &barID
	session.FARs[1] = far
	conn.requestTimeout, conn.requestRetries = time.Second, 1
	conn.stateMu.Unlock()
	capture := startBufferPFCPCapture(t)
	go conn.Run()
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100)); err != nil {
		t.Fatal(err)
	}
	first := readBufferWireReport(t, peer)
	retry := readBufferWireReport(t, peer)
	if first.Sequence() != retry.Sequence() || first.SEID() != 77 || first.DownlinkDataReport == nil {
		t.Fatal("DLDR retransmission changed its transaction or destination SEID")
	}
	response := message.NewSessionReportResponse(11, first.Sequence(), ie.NewCause(ie.CauseRequestAccepted), ie.NewUpdateBARWithinSessionReportResponse(ie.NewBARID(0), ie.NewDLBufferingDuration(2*time.Second), ie.NewDLBufferingSuggestedPacketCount(3)), ie.NewPFCPSRRspFlags(1))
	if _, err := peer.WriteToUDP(protocolWire(t, response), conn.socket().LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	var until time.Time
	for {
		conn.stateMu.RLock()
		current := assoc.Sessions[11]
		changed := current.FARs[1].FarInfo.BufferCookie != far.FarInfo.BufferCookie
		until = current.downlink.extendedUntil
		conn.stateMu.RUnlock()
		if changed && !until.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket response did not apply BAR and DROBU")
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 101)); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 65535)
	if _, _, err := peer.ReadFromUDP(wire); err == nil {
		t.Fatal("extended buffering sent another DLDR")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	if wait := time.Until(until.Add(50 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	if _, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 102)); err != nil {
		t.Fatal(err)
	}
	next := readBufferWireReport(t, peer)
	if next.Sequence() == first.Sequence() || next.DownlinkDataReport == nil {
		t.Fatal("expiry did not originate a new DLDR")
	}
	accepted := message.NewSessionReportResponse(11, next.Sequence(), ie.NewCause(ie.CauseRequestAccepted))
	if _, err := peer.WriteToUDP(protocolWire(t, accepted), conn.socket().LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(time.Second)
	for {
		conn.transport.mu.Lock()
		pending := len(conn.transport.pending)
		conn.transport.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket acceptance retained a report")
		}
		time.Sleep(time.Millisecond)
	}
	capture.close()
	if capture.err != nil {
		t.Fatal(capture.err)
	}
	if dir := os.Getenv("EUPF_BUFFER_CAPTURE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "downlink-report-controls.pcap"), capture.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-buffering.Failures():
		t.Fatal(err)
	default:
	}
}

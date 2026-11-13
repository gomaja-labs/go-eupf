//go:build linux

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func openBufferWireReceiver(t *testing.T, namespace string) int {
	t.Helper()
	target, err := os.Open("/run/netns/" + namespace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := target.Close(); err != nil {
			t.Error(err)
		}
	}()
	type socketResult struct {
		packet, sink int
		err          error
	}
	opened := make(chan socketResult, 1)
	go func() {
		// runtime.LockOSThread guarantees that exiting without unlocking
		// terminates this thread. No application thread inherits the test netns.
		runtime.LockOSThread()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			opened <- socketResult{err: err}
			return
		}
		iface, err := net.InterfaceByName("buffer-input")
		if err != nil {
			opened <- socketResult{err: err}
			return
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0x0300)
		if err != nil {
			opened <- socketResult{err: err}
			return
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: 0x0300}); err != nil {
			opened <- socketResult{err: errors.Join(err, unix.Close(fd))}
			return
		}
		sink, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			opened <- socketResult{err: errors.Join(err, unix.Close(fd))}
			return
		}
		if err := unix.Bind(sink, &unix.SockaddrInet4{Port: 2152, Addr: [4]byte{198, 18, 1, 2}}); err != nil {
			opened <- socketResult{err: errors.Join(err, unix.Close(fd), unix.Close(sink))}
			return
		}
		opened <- socketResult{packet: fd, sink: sink}
	}()
	result := <-opened
	if result.err != nil {
		t.Fatal(result.err)
	}
	t.Cleanup(func() {
		if err := errors.Join(unix.Close(result.packet), unix.Close(result.sink)); err != nil {
			t.Error(err)
		}
	})
	return result.packet
}

func TestApplicationBufferFramesReachReceiver(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	command := func(args ...string) {
		t.Helper()
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, output)
		}
	}
	command("netns", "add", "buffer-receiver")
	t.Cleanup(func() {
		if output, err := exec.Command("ip", "netns", "del", "buffer-receiver").CombinedOutput(); err != nil {
			t.Errorf("remove receiver: %v %s", err, output)
		}
	})
	packetBufferRoute(t, plane)
	command("link", "set", "buffer-input", "netns", "buffer-receiver")
	command("-n", "buffer-receiver", "link", "set", "buffer-input", "address", "02:00:00:00:00:02")
	command("-n", "buffer-receiver", "link", "set", "buffer-input", "up")
	command("-n", "buffer-receiver", "addr", "add", "198.18.1.2/24", "dev", "buffer-input")
	fd := openBufferWireReceiver(t, "buffer-receiver")
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint16{100, 101} {
		action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id))
		if err != nil || action != 1 {
			t.Fatalf("admit %d: action=%d error=%v", id, action, err)
		}
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if directory := os.Getenv("EUPF_BUFFER_CAPTURE_DIR"); directory != "" {
			if err := os.MkdirAll(directory, 0755); err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(filepath.Join(directory, "buffered-drain-ipv4-outer.pcap"), capture.Bytes(), 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	received := 0
	for {
		frame := make([]byte, 65535)
		n, _, err := unix.Recvfrom(fd, frame, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) && received == 2 {
				break
			}
			t.Fatalf("receive buffered frame %d: %v", received, err)
		}
		frame = frame[:n]
		if n < 58 || frame[12] != 8 || frame[13] != 0 || frame[23] != 17 || binary.BigEndian.Uint16(frame[36:38]) != 2152 {
			continue
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: n, Length: n}, frame); err != nil {
			t.Fatal(err)
		}
		if received >= 2 || binary.BigEndian.Uint16(frame[54:56]) != uint16(100+received) {
			t.Fatal("receiver observed a duplicate or out-of-order buffered packet")
		}
		received++
		if received == 2 {
			if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 50000}); err != nil {
				t.Fatal(err)
			}
		}
	}
	stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil || stats.Drops != 0 {
		t.Fatalf("receiver stats=%+v error=%v", stats, err)
	}
	select {
	case err := <-buffering.Failures():
		t.Fatal(err)
	default:
	}
	t.Logf("receiver matched=%d socket_packets=%d socket_drops=%d", received, stats.Packets, stats.Drops)
}

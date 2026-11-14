//go:build linux

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func bufferAttachedFrame(t *testing.T, v6 bool, sequence uint16) []byte {
	t.Helper()
	if !v6 {
		return bufferKernelPacket(t, sequence)
	}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload, sequence)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv6}, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
func TestApplicationBufferAttachedXDPOrdersConcurrentTransition(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { testApplicationBufferAttachedTransition(t, v6, false) })
	}
}
func TestApplicationBufferAttachedKernelXDPOrdersConcurrentTransition(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { testApplicationBufferAttachedTransition(t, v6, true) })
	}
}
func testApplicationBufferAttachedTransition(t *testing.T, v6, kernel bool) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixtureOptions(t, BufferingOptions{Packets: 4096, PerSession: 64, FrameBytes: ebpf.BufferFrameSize, Retention: time.Minute})
	command := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	if v6 {
		conn.stateMu.Lock()
		pdr := session.PDRs[9]
		pdr.Ipv6 = net.ParseIP("2001:db8::2")
		session.PDRs[9] = pdr
		err := applyPDR(pdr, conn.mapOperations)
		conn.stateMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	command("netns", "add", "buffer-attached-receiver")
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", "buffer-attached-receiver").CombinedOutput(); err != nil {
			t.Errorf("remove receiver: %v %s", err, out)
		}
	})
	packetBufferRoute(t, plane)
	command("link", "set", "buffer-input", "netns", "buffer-attached-receiver")
	command("-n", "buffer-attached-receiver", "link", "set", "buffer-input", "address", "02:00:00:00:00:02")
	command("-n", "buffer-attached-receiver", "link", "set", "buffer-input", "up")
	command("-n", "buffer-attached-receiver", "addr", "add", "198.18.1.2/24", "dev", "buffer-input")
	// Native veth redirect requires an XDP program on its receiving peer.
	command("-n", "buffer-attached-receiver", "link", "set", "buffer-input", "xdp", "obj", "../ebpf/zeroentrypoint_bpf.o", "sec", "xdp/upf_zero_entrypoint")
	receiver := openBufferWireReceiver(t, "buffer-attached-receiver")
	if err := unix.SetsockoptTimeval(receiver, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(receiver, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, 4<<20); err != nil {
		t.Fatal(err)
	}
	command("link", "add", "buffer-source", "type", "veth", "peer", "name", "buffer-ingress")
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "link", "del", "buffer-source").CombinedOutput(); err != nil {
			t.Errorf("remove ingress: %v %s", err, out)
		}
	})
	command("link", "set", "buffer-source", "up")
	command("link", "set", "buffer-ingress", "up")
	// The synthetic tunnel source needs an explicit reverse path for Linux RPF.
	command("route", "add", "192.0.2.0/24", "dev", "buffer-ingress")
	ingress, err := net.InterfaceByName("buffer-ingress")
	if err != nil {
		t.Fatal(err)
	}
	attached, err := link.AttachXDP(link.XDPOptions{Program: plane.UpfIpEntrypointFunc, Interface: ingress.Index, Flags: link.XDPDriverMode})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := attached.Close(); err != nil {
			t.Error(err)
		}
	})
	source, err := net.InterfaceByName("buffer-source")
	if err != nil {
		t.Fatal(err)
	}
	output, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Close(output); err != nil {
			t.Error(err)
		}
	})
	// Block the first old packet while newer traffic continues arriving through
	// the attached program. All of it must remain behind that packet's guard.
	original := buffering.sender
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblock sync.Once
	t.Cleanup(func() {
		unblock.Do(func() { close(release) })
		if err := original.Close(); err != nil {
			t.Error(err)
		}
	})
	buffering.sender = bufferSenderFunc(func(packet ebpf.RenderedBuffer) error {
		once.Do(func() { close(entered); <-release })
		return original.Send(packet)
	})
	const total = 96
	frames := make([][]byte, total)
	for id := range total {
		frames[id] = bufferAttachedFrame(t, v6, uint16(id+100))
		copy(frames[id][:6], ingress.HardwareAddr)
		copy(frames[id][6:12], source.HardwareAddr)
	}
	reached := make(chan struct{})
	producer := make(chan error, 1)
	go func() {
		for id, frame := range frames {
			if err := unix.Sendto(output, frame, 0, &unix.SockaddrLinklayer{Ifindex: source.Index, Protocol: binary.NativeEndian.Uint16(frame[12:14])}); err != nil {
				producer <- err
				return
			}
			if id == 15 {
				close(reached)
			}
			time.Sleep(5 * time.Millisecond)
		}
		producer <- nil
	}()
	<-reached
	deadline := time.Now().Add(2 * time.Second)
	for {
		buffering.mu.Lock()
		held := len(buffering.entries) - len(buffering.free)
		buffering.mu.Unlock()
		if held >= 16 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial attached packets held=%d", held)
		}
		time.Sleep(time.Millisecond)
	}
	if kernel {
		command("neigh", "del", "198.18.1.2", "dev", "buffer-output")
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not start")
	}
	time.Sleep(10 * time.Millisecond)
	unblock.Do(func() { close(release) })
	var capture bytes.Buffer
	writer := pcapgo.NewWriter(&capture)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if directory := os.Getenv("EUPF_BUFFER_CAPTURE_DIR"); directory != "" {
			prefix := "attached-ordered"
			if kernel {
				prefix = "attached-kernel-ordered"
			}
			name := fmt.Sprintf("%s-inner-v%d.pcap", prefix, map[bool]int{false: 4, true: 6}[v6])
			if err := os.WriteFile(filepath.Join(directory, name), capture.Bytes(), 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	received := 0
	for {
		frame := make([]byte, 4096)
		n, _, err := unix.Recvfrom(receiver, frame, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			if errors.Is(err, unix.EAGAIN) && received == total {
				break
			}
			t.Fatalf("receive %d/%d: %v", received, total, err)
		}
		frame = frame[:n]
		if n < 70 || frame[12] != 8 || frame[13] != 0 || frame[23] != 17 || binary.BigEndian.Uint16(frame[36:38]) != 2152 {
			continue
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), Length: n, CaptureLength: n}, frame); err != nil {
			t.Fatal(err)
		}
		offset := 54
		if v6 {
			offset = 98
		}
		if n < offset+2 {
			t.Fatalf("short inner packet: %d", n)
		}
		got := binary.BigEndian.Uint16(frame[offset:])
		if received >= total || got != uint16(received+100) {
			t.Fatalf("wire order at %d: got %d", received, got)
		}
		received++
		if received == total {
			if err := unix.SetsockoptTimeval(receiver, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 50000}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := <-producer; err != nil {
		t.Fatal(err)
	}
	stats, err := unix.GetsockoptTpacketStats(receiver, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil || stats.Drops != 0 {
		t.Fatalf("capture stats=%+v %v", stats, err)
	}
	t.Logf("attached driver XDP received=%d capture_drops=%d", received, stats.Drops)
}

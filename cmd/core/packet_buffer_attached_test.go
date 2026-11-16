//go:build linux

package core

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
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
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { testApplicationBufferAttachedTransition(t, v6, false, false) })
	}
}
func TestApplicationBufferAttachedKernelXDPOrdersConcurrentTransition(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { testApplicationBufferAttachedTransition(t, v6, true, false) })
	}
}
func TestApplicationBufferAttachedKernelOnlyXDPKeepsWireOrder(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { testApplicationBufferAttachedTransition(t, v6, true, true) })
	}
}
func TestApplicationBufferGenericKernelContinuation(t *testing.T) {
	for _, oneLink := range []bool{false, true} {
		for _, overlap := range []bool{false, true} {
			t.Run(fmt.Sprintf("one-link=%t/overlap=%t", oneLink, overlap), func(t *testing.T) {
				testApplicationBufferAttachedTransition(t, false, true, true, bufferAttachedOptions{generic: true, oneLink: oneLink, overlap: overlap})
			})
		}
	}
}

type bufferAttachedOptions struct{ generic, oneLink, overlap bool }

func testApplicationBufferAttachedTransition(t *testing.T, v6, kernel, allKernel bool, options ...bufferAttachedOptions) {
	var option bufferAttachedOptions
	if len(options) > 0 {
		option = options[0]
	}

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
	if option.generic {
		conn.stateMu.Lock()
		id, err := plane.NewUrr(ebpf.UrrInfo{})
		if err != nil {
			conn.stateMu.Unlock()
			t.Fatal(err)
		}
		session.URRs[1] = SUrrInfo{GlobalId: id}
		pdr := session.PDRs[9]
		pdr.URRIDs = []uint32{1}
		session.PDRs[9] = pdr
		err = conn.rebindSessionRules(session)
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
	ingressName := "buffer-ingress"
	if option.oneLink {
		ingressName = "buffer-output"
	}
	if !option.oneLink {
		command("link", "add", "buffer-source", "type", "veth", "peer", "name", "buffer-ingress")
		t.Cleanup(func() {
			if out, err := exec.Command("ip", "link", "del", "buffer-source").CombinedOutput(); err != nil {
				t.Errorf("remove ingress: %v %s", err, out)
			}
		})
		command("link", "set", "buffer-source", "up")
		command("link", "set", "buffer-ingress", "up")
	}
	// The synthetic tunnel source needs an explicit reverse path for Linux RPF.
	command("route", "add", "192.0.2.0/24", "dev", ingressName)
	ingress, err := net.InterfaceByName(ingressName)
	if err != nil {
		t.Fatal(err)
	}
	mode := link.XDPDriverMode
	if option.generic {
		mode = link.XDPGenericMode
	}
	attached, err := link.AttachXDP(link.XDPOptions{Program: plane.UpfIpEntrypointFunc, Interface: ingress.Index, Flags: mode})
	if err != nil {
		t.Fatal(err)
	}
	if err := plane.SetBufferGenericIngress(uint32(ingress.Index), option.generic); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := attached.Close(); err != nil {
			t.Error(err)
		}
	})
	var sourceIndex int
	var sourceMAC net.HardwareAddr
	output := receiver
	if option.oneLink {
		address, err := unix.Getsockname(receiver)
		if err != nil {
			t.Fatal(err)
		}
		sourceIndex = address.(*unix.SockaddrLinklayer).Ifindex
		sourceMAC = net.HardwareAddr{2, 0, 0, 0, 0, 2}
	} else {
		source, err := net.InterfaceByName("buffer-source")
		if err != nil {
			t.Fatal(err)
		}
		sourceIndex, sourceMAC = source.Index, source.HardwareAddr
		output, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := unix.Close(output); err != nil {
				t.Error(err)
			}
		})
	}
	if option.overlap {
		id, err := plane.NewFar(ebpf.FarInfo{Action: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := plane.PutPdrDownlink(net.IP{198, 18, 1, 2}, ebpf.PdrInfo{SessionID: 99, PdrID: 10, FarId: id}); err != nil {
			t.Fatal(err)
		}
	}
	statistics := &ebpf.UpfXdpActionStatistic{BpfObjects: plane}
	if option.generic {
		for _, corrupt := range []func([]byte){
			func(frame []byte) { frame[22] ^= 1 },
			func(frame []byte) { binary.NativeEndian.PutUint32(frame[18:], uint32(ingress.Index+1)) },
		} {
			frame, err := plane.BufferKernelEnvelope(bufferKernelPacket(t, 0), uint32(ingress.Index))
			if err != nil {
				t.Fatal(err)
			}
			copy(frame[:6], ingress.HardwareAddr)
			corrupt(frame)
			if err := unix.Sendto(output, frame, 0, &unix.SockaddrLinklayer{Ifindex: sourceIndex, Protocol: binary.NativeEndian.Uint16(frame[12:14])}); err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(time.Second)
		for {
			passed, dropped, err := plane.BufferContinuationCounts()
			if err != nil || passed != 0 || dropped > 2 {
				t.Fatalf("invalid envelope counts passed=%d dropped=%d error=%v", passed, dropped, err)
			}
			if dropped == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("invalid envelopes not dropped: %d", dropped)
			}
			time.Sleep(time.Millisecond)
		}
	}
	beforeCounters := statistics.GetUpfExtStat()
	defer func() { t.Logf("packet counter delta: %+v", beforeCounters.Delta(statistics.GetUpfExtStat())) }()
	if err := unix.SetsockoptInt(receiver, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		t.Fatal(err)
	}
	type handover struct {
		ID          uint16
		Action      uint32
		ReturnedNS  int64
		Thread, CPU int
	}
	var handovers []handover
	var handoverMu sync.Mutex
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
		if allKernel && packet.Action != 2 {
			return fmt.Errorf("fixed kernel continuation changed to action %d", packet.Action)
		}
		err := original.Send(packet)
		if err == nil {
			offset := 54
			if v6 {
				offset = 98
			}
			if len(packet.Frame) < offset+2 {
				return errors.New("short hand-over frame")
			}
			var affinity unix.CPUSet
			if err := unix.SchedGetaffinity(0, &affinity); err != nil {
				return err
			}
			cpu := -1
			for id := range 1024 {
				if affinity.IsSet(id) {
					cpu = id
					break
				}
			}
			if kernel && affinity.Count() != 1 {
				t.Errorf("kernel hand-over can migrate between %d CPUs", affinity.Count())
			}
			entry := handover{ID: binary.BigEndian.Uint16(packet.Frame[offset:]), Action: packet.Action, ReturnedNS: time.Now().UnixNano(), Thread: unix.Gettid(), CPU: cpu}
			handoverMu.Lock()
			handovers = append(handovers, entry)
			count := len(handovers)
			handoverMu.Unlock()
			if allKernel && count == 48 {
				// All retained packets have entered the same kernel path before
				// resolving the neighbour releases its queue.
				out, err := exec.Command("ip", "neigh", "replace", "198.18.1.2", "lladdr", "02:00:00:00:00:02", "nud", "permanent", "dev", "buffer-output").CombinedOutput()
				if err != nil {
					return fmt.Errorf("resolve kernel continuation: %w %s", err, out)
				}
			}
		}
		return err
	})
	total := 96
	if allKernel {
		total = 48
	}
	frames := make([][]byte, total)
	for id := range total {
		frames[id] = bufferAttachedFrame(t, v6, uint16(id+100))
		copy(frames[id][:6], ingress.HardwareAddr)
		copy(frames[id][6:12], sourceMAC)
	}
	reached := make(chan struct{})
	producer := make(chan error, 1)
	go func() {
		for id, frame := range frames {
			if err := unix.Sendto(output, frame, 0, &unix.SockaddrLinklayer{Ifindex: sourceIndex, Protocol: binary.NativeEndian.Uint16(frame[12:14])}); err != nil {
				producer <- err
				return
			}
			if !allKernel && id == 15 || allKernel && id == total-1 {
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
		target := 16
		if allKernel {
			target = total
		}
		if held >= target {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("initial attached packets held=%d", held)
		}
		time.Sleep(time.Millisecond)
	}
	if kernel {
		command("neigh", "del", "198.18.1.2", "dev", "buffer-output")
		if allKernel {
			command("netns", "exec", "buffer-attached-receiver", "sysctl", "-w", "net.ipv4.conf.buffer-input.arp_ignore=8")
		}
	}
	_ = switchBufferedFARToForward(t, conn, assoc, session)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("drain did not start")
	}
	if allKernel {
		// Select the fixed kernel continuation for every retained packet before
		// any send starts neighbour resolution. Linux v5.15 net/core/filter.c:
		// bpf_fib_set_fwd_params accepts an existing unresolved neighbour, so
		// recomputing after the first send can select a different continuation.
		func() {
			conn.stateMu.RLock()
			defer conn.stateMu.RUnlock()
			current := assoc.Sessions[session.LocalSEID]
			cycle := current.buffers.cycles[1]
			for index := cycle.head; index != noBufferedPacket; index = buffering.entries[index].next {
				rendered, err := plane.RenderBufferedPacket(buffering.entries[index].record, current.FARs[1].GlobalId)
				if err != nil || rendered.Action != 2 {
					t.Fatalf("select fixed kernel continuation: action=%d error=%v", rendered.Action, err)
				}
			}
		}()
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
			if allKernel {
				prefix = "attached-kernel-only-ordered"
			}
			if option.generic {
				prefix += fmt.Sprintf("-generic-one-link-%t-overlap-%t", option.oneLink, option.overlap)
			}
			name := fmt.Sprintf("%s-inner-v%d.pcap", prefix, map[bool]int{false: 4, true: 6}[v6])
			if err := os.WriteFile(filepath.Join(directory, name), capture.Bytes(), 0600); err != nil {
				t.Error(err)
			}
			handoverMu.Lock()
			raw, err := json.MarshalIndent(handovers, "", "  ")
			handoverMu.Unlock()
			if err != nil {
				t.Error(err)
			} else if err := os.WriteFile(filepath.Join(directory, name+".handovers.json"), append(raw, '\n'), 0600); err != nil {
				t.Error(err)
			}
		}
	}()
	received := 0
	wireTimes := make(map[uint16]int64, total)
	for {
		frame := make([]byte, 4096)
		ancillary := make([]byte, 128)
		n, oobn, flags, _, err := unix.Recvmsg(receiver, frame, ancillary, 0)
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
		port := uint16(2152)
		minimum := 70
		if n < minimum || frame[12] != 8 || frame[13] != 0 || frame[23] != 17 || binary.BigEndian.Uint16(frame[36:38]) != port {
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
		if got < 100 || got >= uint16(100+total) || wireTimes[got] != 0 {
			t.Fatalf("duplicate/invalid wire packet %d", got)
		}
		if (!kernel || allKernel) && got != uint16(received+100) {
			t.Fatalf("wire order at %d: got %d", received, got)
		}
		if flags&unix.MSG_CTRUNC != 0 {
			t.Fatal("truncated receive timestamp")
		}
		messages, err := unix.ParseSocketControlMessage(ancillary[:oobn])
		if err != nil {
			t.Fatal(err)
		}
		for _, message := range messages {
			if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SCM_TIMESTAMPNS && len(message.Data) >= 16 {
				wireTimes[got] = int64(binary.NativeEndian.Uint64(message.Data))*int64(time.Second) + int64(binary.NativeEndian.Uint64(message.Data[8:]))
			}
		}
		if wireTimes[got] == 0 {
			t.Fatal("packet has no kernel receive timestamp")
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
	handoverMu.Lock()
	log := append([]handover(nil), handovers...)
	handoverMu.Unlock()
	if len(log) < 16 || log[0].ID != 100 {
		t.Fatalf("missing retained hand-over log: %v", log)
	}
	handed := make(map[uint16]handover, len(log))
	for i, entry := range log {
		if i > 0 && (entry.ID <= log[i-1].ID || entry.ReturnedNS < log[i-1].ReturnedNS) {
			t.Fatalf("hand-over order: %v", log)
		}
		if kernel && (entry.Thread != log[0].Thread || entry.CPU != log[0].CPU) {
			t.Fatal("kernel continuation changed its backlog CPU")
		}
		handed[entry.ID] = entry
	}
	for id := uint16(100); id < uint16(100+total); id++ {
		if _, ok := handed[id]; ok {
			continue
		}
		for _, older := range log {
			if older.ID < id && wireTimes[id] < older.ReturnedNS {
				t.Fatalf("native packet %d handed over before retained %d: native=%d older_return=%d", id, older.ID, wireTimes[id], older.ReturnedNS)
			}
		}
	}
	t.Logf("continuation hand-overs=%d native=%d FIFO=true", len(log), total-len(log))
	stats, err := unix.GetsockoptTpacketStats(receiver, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil || stats.Drops != 0 {
		t.Fatalf("capture stats=%+v %v", stats, err)
	}
	if option.generic {
		usage, err := plane.GetUrr(session.URRs[1].GlobalId)
		if err != nil || usage.DownlinkVolume != uint64(total*32) || usage.UplinkVolume != 0 {
			t.Fatalf("continuation repeated usage: %+v error=%v want=%d", usage, err, total*32)
		}
		delta := beforeCounters.Delta(statistics.GetUpfExtStat())
		if delta.RxIp4 != uint64(total) || delta.RxUdp != uint64(total) || delta.RxGtpUnexp != 0 {
			t.Fatalf("continuation repeated parsing or emitted Error Indication: %+v", delta)
		}
		passed, dropped, err := plane.BufferContinuationCounts()
		if err != nil || passed != uint64(total) || dropped != 2 {
			t.Fatalf("envelope counts passed=%d dropped=%d error=%v", passed, dropped, err)
		}
	}
	t.Logf("attached XDP mode=%v received=%d capture_drops=%d", mode, received, stats.Drops)
}

//go:build linux

package core

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestPacketBufferBARCountsShareDirectionsWithoutRestrictingOtherFARs(t *testing.T) {
	plane, buffering, conn, assoc, session, _ := publishPacketBufferFixture(t)
	cfg := ebpf.IpEntrypointDataplaneConfig{N3Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1}), N9Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 2})}
	if err := plane.GlobalConfig.Set(cfg); err != nil {
		t.Fatal(err)
	}
	conn.stateMu.Lock()
	after := cloneSession(session)
	if err := createBAR(after, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(2), ie.NewDLBufferingSuggestedPacketCount(1))); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	barID := uint8(0)
	far := after.FARs[1]
	far.BARID = &barID
	after.FARs[1] = far
	after.FARs[2] = SFarInfo{FarInfo: ebpf.FarInfo{Action: 4}}
	start, finish := conn.prepareSessionMutation(after, updateSessionMutation, true)
	defer func() {
		conn.stateMu.Lock()
		defer conn.stateMu.Unlock()
		if err := finish(false); err != nil {
			t.Error(err)
		}
	}()
	conn.stagePacketBuffering(assoc, session, after, updateSessionMutation, false)
	if err := start(); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	slot, err := conn.mapOperations.GetNextFAR()
	if err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	far = after.FARs[2]
	far.GlobalId = slot
	after.FARs[2] = far
	if err := conn.mapOperations.UpdateFar(slot, far.FarInfo); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	secondID := uint32(2)
	after.PDRs[10] = SPDRInfo{FARID: &secondID, PdrID: 10, Ipv4: net.IP{198, 51, 100, 3}, SourceInterface: 1, PdrInfo: ebpf.PdrInfo{SessionID: 11, PdrID: 10}}
	firstID := uint32(1)
	after.PDRs[11] = SPDRInfo{FARID: &firstID, PdrID: 11, Teid: 10, SourceInterface: 0, PdrInfo: ebpf.PdrInfo{SessionID: 11, PdrID: 11, SourceInterfacePresent: true, SourceInterface: 0}}
	if err := conn.rebindSessionRules(after); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	if err := finish(true); err != nil {
		conn.stateMu.Unlock()
		t.Fatal(err)
	}
	assoc.Sessions[11] = after
	conn.stateMu.Unlock()
	for _, id := range []uint16{100, 101} {
		if action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, id)); err != nil || action != 1 {
			t.Fatalf("DL input: %d %v", action, err)
		}
	}
	for _, id := range []uint16{110, 111} {
		if action, _, err := plane.UpfIpEntrypointFunc.Test(bufferUplinkKernelPacket(t, id)); err != nil || action != 1 {
			t.Fatalf("UL input: %d %v", action, err)
		}
	}
	for _, id := range []uint16{200, 201, 202} {
		packet := bufferKernelPacket(t, id)
		// A second UE address selects the unassociated FAR; serializing again
		// retains a valid IPv4 and UDP checksum for this synthetic vector.
		ip := &layers.IPv4{Version: 4, TTL: 64, Id: id, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 3}}
		udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		wire := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(wire, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(packet[len(packet)-4:])); err != nil {
			t.Fatal(err)
		}
		if action, _, err := plane.UpfIpEntrypointFunc.Test(wire.Bytes()); err != nil || action != 1 {
			t.Fatalf("unassociated input: %d %v", action, err)
		}
	}
	first := after.buffers.cycles[1]
	second := after.buffers.cycles[2]
	state, err := plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: first.cookie, Lane: first.lane, Operation: 3})
	if err != nil || state.Produced != 2 || state.Outstanding != 4 {
		t.Fatalf("BAR total/DL bound was not shared: %+v error=%v", state, err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		conn.stateMu.RLock()
		received := first.received
		conn.stateMu.RUnlock()
		if received == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reader did not consume both directions")
		}
		time.Sleep(time.Millisecond)
	}
	conn.stateMu.RLock()
	kinds := map[uint8]int{}
	for index := first.head; index != noBufferedPacket; index = buffering.entries[index].next {
		kinds[buffering.entries[index].record.Kind]++
	}
	conn.stateMu.RUnlock()
	if kinds[1] != 1 || kinds[3] != 1 {
		t.Fatalf("buffered direction classes: %v", kinds)
	}
	state, err = plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: second.cookie, Lane: second.lane, Operation: 3})
	if err != nil || state.Produced != 2 {
		t.Fatalf("BAR restricted an unassociated FAR: %+v error=%v", state, err)
	}
}

func bufferUplinkKernelPacket(t *testing.T, id uint16) []byte {
	t.Helper()
	frame := bufferKernelPacket(t, id)
	inner := frame[14 : 14+int(binary.BigEndian.Uint16(frame[16:18]))]
	gtp := make([]byte, 8+len(inner))
	gtp[0], gtp[1] = 0x30, 255
	binary.BigEndian.PutUint16(gtp[2:], uint16(len(inner)))
	binary.BigEndian.PutUint32(gtp[4:], 10)
	copy(gtp[8:], inner)
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{192, 0, 2, 2}, DstIP: net.IP{192, 0, 2, 1}}
	udp := &layers.UDP{SrcPort: 2152, DstPort: 2152}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	wire := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(wire, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(gtp)); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

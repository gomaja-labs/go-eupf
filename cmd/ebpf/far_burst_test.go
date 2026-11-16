//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	cilium "github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestChartSizedFARReplacementBurstKeepsPacketVersions(t *testing.T) {
	b := loadDatapath(t, func(b *BpfObjects) {
		b.SetPdrMapSize(2048)
		b.SetFarMapSize(2048)
		b.SetBufferCapacity(1024, 4096)
	})
	const sessions = 1024
	current := make([]uint32, 2*sessions)
	packets := make([][]byte, 4*sessions)
	addresses := make([]net.IP, 2*sessions)
	if err := b.DeletePdrUplink(10, 0, 1); err != nil {
		t.Fatal(err)
	}
	for i := range sessions {
		address := net.IP{10, 60, byte(i >> 8), byte(i)}
		addresses[2*i] = address
		addresses[2*i+1] = net.IP{10, 61, byte(i >> 8), byte(i)}
		far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: uint32(100000 + i), RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), TransportLevelMarking: 0x10fc}
		for lane := 0; lane < 2; lane++ {
			id, err := b.NewFar(far)
			if err != nil {
				t.Fatal(err)
			}
			current[2*i+lane] = id
			if err := b.PutPdrDownlink(addresses[2*i+lane], PdrInfo{SessionID: uint64(i + 1), PdrID: uint32(lane + 1), FarId: id}); err != nil {
				t.Fatal(err)
			}
			if err := b.PutPdrUplink(uint32(4096+2*i+lane), PdrInfo{SessionID: uint64(i + 1), PdrID: uint32(lane + 3), FarId: id, OuterHeaderRemovalPresent: true}); err != nil {
				t.Fatal(err)
			}
		}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: address}
		udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		packets[4*i] = serializeDatapath(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(make([]byte, 16)))
		otherIP := *ip
		otherIP.DstIP = addresses[2*i+1]
		otherUDP := *udp
		if err := otherUDP.SetNetworkLayerForChecksum(&otherIP); err != nil {
			t.Fatal(err)
		}
		packets[4*i+1] = serializeDatapath(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, &otherIP, &otherUDP, gopacket.Payload(make([]byte, 16)))
		for lane := 0; lane < 2; lane++ {
			packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
			tunnel := append([]byte(nil), packet[42:]...)
			binary.BigEndian.PutUint32(tunnel[4:8], uint32(4096+2*i+lane))
			packets[4*i+lane+2] = outerDatapath(t, tunnel, false)
		}
	}
	for name, m := range map[string]*cilium.Map{"uplink": b.PdrMapTeidIp4, "downlink": b.PdrMapDownlinkIp4} {
		count := 0
		iterator := m.Iterate()
		var key uint32
		var value IpEntrypointPdrIndex
		for iterator.Next(&key, &value) {
			count++
		}
		if err := iterator.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 2048 {
			t.Fatalf("%s hash is not full: %d keys", name, count)
		}
	}
	if err := b.SynchronizeRules(); err != nil {
		t.Fatal(err)
	}
	var complete atomic.Bool
	result := make(chan error, 1)
	go func() {
		defer complete.Store(true)
		defer pinPublicationCPU(t, 2)()
		for index, old := range current {
			i, lane := index/2, index%2
			tx, err := b.BeginRuleTransaction(uint64(i + 1))
			if err != nil {
				result <- err
				return
			}
			next, err := tx.NewFar(FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: uint32(200000 + i), RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), TransportLevelMarking: 0x20fc})
			if err == nil {
				err = tx.PutPdrDownlink(addresses[2*i+lane], PdrInfo{SessionID: uint64(i + 1), PdrID: uint32(lane + 1), FarId: next})
			}
			if err == nil {
				err = tx.PutPdrUplink(uint32(4096+2*i+lane), PdrInfo{SessionID: uint64(i + 1), PdrID: uint32(lane + 3), FarId: next, OuterHeaderRemovalPresent: true})
			}
			if err == nil {
				err = tx.DeleteFar(old)
			}
			if err == nil {
				err = tx.Commit()
			}
			if err != nil {
				_ = tx.Rollback()
				result <- fmt.Errorf("session %d replacement: %w", i+1, err)
				return
			}
		}
		result <- nil
	}()
	defer pinPublicationCPU(t, 5)()
	observations, mixed := 0, 0
	for i := 0; !complete.Load() || i < len(packets); i++ {
		packetIndex := i % len(packets)
		index := packetIndex / 4
		action, out, err := b.UpfIpEntrypointFunc.Test(packets[packetIndex])
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		gtp, ok := packet.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U)
		ip, ipOK := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if action != 4 || !ok || !ipOK ||
			(gtp.TEID != uint32(100000+index) || ip.TOS != 0x10) &&
				(gtp.TEID != uint32(200000+index) || ip.TOS != 0x20) {
			mixed++
		}
		observations++
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	t.Logf("sessions=%d replaced-FARs=2048 full-hash-keys=4096 observations=%d mixed-FAR=%d", sessions, observations, mixed)
	if mixed != 0 {
		t.Fatal("FAR burst exposed a mixed configuration")
	}
}

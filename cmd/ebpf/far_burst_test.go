//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestChartSizedFARReplacementBurstKeepsPacketVersions(t *testing.T) {
	b := loadDatapath(t, func(b *BpfObjects) {
		b.SetPdrMapSize(2048)
		b.SetFarMapSize(2048)
		b.SetBufferCapacity(1024, 4096)
	})
	for range 3 {
		if _, err := b.GetNextFAR(); err != nil {
			t.Fatal(err)
		}
	}
	const sessions = 1024
	current := make([]uint32, sessions)
	packets := make([][]byte, sessions)
	addresses := make([]net.IP, sessions)
	for i := range sessions {
		address := net.IP{10, 60, byte(i >> 8), byte(i)}
		addresses[i] = address
		far := FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: uint32(100000 + i), RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), TransportLevelMarking: 0x10fc}
		id, err := b.NewFar(far)
		if err != nil {
			t.Fatal(err)
		}
		current[i] = id
		if err := b.PutPdrDownlink(address, PdrInfo{SessionID: uint64(i + 1), PdrID: 1, FarId: id}); err != nil {
			t.Fatal(err)
		}
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{198, 51, 100, 1}, DstIP: address}
		udp := &layers.UDP{SrcPort: 1234, DstPort: 4321}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		packets[i] = serializeDatapath(t, &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(make([]byte, 16)))
	}
	var complete atomic.Bool
	result := make(chan error, 1)
	go func() {
		defer complete.Store(true)
		defer pinPublicationCPU(t, 2)()
		for i, old := range current {
			tx, err := b.BeginRuleTransaction(uint64(i + 1))
			if err != nil {
				result <- err
				return
			}
			next, err := tx.NewFar(FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: uint32(200000 + i), RemoteIP: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), TransportLevelMarking: 0x20fc})
			if err == nil {
				err = tx.PutPdrDownlink(addresses[i], PdrInfo{SessionID: uint64(i + 1), PdrID: 1, FarId: next})
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
	for i := 0; !complete.Load() || i < sessions; i++ {
		index := i % sessions
		action, out, err := b.UpfIpEntrypointFunc.Test(packets[index])
		if err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
		gtp, ok := packet.Layer(layers.LayerTypeGTPv1U).(*layers.GTPv1U)
		ip, ipOK := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if action != 4 || !ok || !ipOK || !(gtp.TEID == uint32(100000+index) && ip.TOS == 0x10 || gtp.TEID == uint32(200000+index) && ip.TOS == 0x20) {
			mixed++
		}
		observations++
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	t.Logf("replaced=%d observations=%d mixed-FAR=%d", sessions, observations, mixed)
	if mixed != 0 {
		t.Fatal("FAR burst exposed a mixed configuration")
	}
}

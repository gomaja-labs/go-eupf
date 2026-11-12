// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the go-eupf authors

//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	cilium "github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func loadDatapath(t *testing.T) *BpfObjects {
	t.Helper()
	if err := IncreaseResourceLimits(); err != nil {
		t.Fatal(err)
	}
	b := NewBpfObjects()
	if err := b.Load(); err != nil {
		var ve *cilium.VerifierError
		if errors.As(err, &ve) {
			t.Logf("%+v", ve)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	cfg := IpEntrypointDataplaneConfig{
		N3Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1}),
		N9Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 2}),
		Ip6RaSupport:  1, Ip6RaPrefixLength: 64,
	}
	copy(cfg.Ip6RaPrefix[:], net.ParseIP("2001:db8:1234:5678::").To16())
	if err := b.GlobalConfig.Set(cfg); err != nil {
		t.Fatal(err)
	}
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2})
	putDatapath(t, b.FarMap.Put, uint32(2), &IpEntrypointFarInfo{Action: 1})
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{})
	putDatapath(t, b.FarMap.Put, uint32(3), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2})})
	if err := b.PutPdrUplink(10, PdrInfo{OuterHeaderRemovalPresent: true, PdrID: 1, Precedence: ^uint32(0), ReturnFarID: 3, ReturnQerIDs: []uint32{1}, FarId: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
		t.Fatal(err)
	}
	return b
}

func putDatapath[T any](t *testing.T, put func(interface{}, interface{}) error, key uint32, value *T) {
	t.Helper()
	if err := put(key, value); err != nil {
		t.Fatal(err)
	}
}

func serializeDatapath(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(b.Bytes())
}

func ethernetDatapath(t *testing.T, typ layers.EthernetType, payload []byte) []byte {
	t.Helper()
	return serializeDatapath(t, &layers.Ethernet{
		SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: typ,
	}, gopacket.Payload(payload))
}

func udpDatapath(t *testing.T, v6 bool) []byte {
	t.Helper()
	u := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if v6 {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP,
			SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		if err := u.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		return serializeDatapath(t, ip, u, gopacket.Payload([]byte{1, 2, 3, 4}))
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}
	if err := u.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return serializeDatapath(t, ip, u, gopacket.Payload([]byte{1, 2, 3, 4}))
}

func gtpDatapath(t *testing.T, inner, optional []byte, flags byte, options bool) []byte {
	t.Helper()
	g := make([]byte, 8)
	g[0], g[1] = flags, 255
	binary.BigEndian.PutUint16(g[2:4], uint16(len(inner)+len(optional)))
	binary.BigEndian.PutUint32(g[4:8], 10)
	g = append(g, optional...)
	g = append(g, inner...)
	return outerDatapath(t, g, options)
}

func outerDatapath(t *testing.T, g []byte, options bool, sourcePorts ...layers.UDPPort) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{192, 0, 2, 2}, DstIP: net.IP{192, 0, 2, 1}}
	if options {
		ip.Options = []layers.IPv4Option{{OptionType: 1}, {OptionType: 1}, {OptionType: 1}, {OptionType: 1}}
	}
	sourcePort := layers.UDPPort(2152)
	if len(sourcePorts) > 0 {
		sourcePort = sourcePorts[0]
	}
	u := &layers.UDP{SrcPort: sourcePort, DstPort: 2152}
	if err := u.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, u, gopacket.Payload(g)))
}

// Set EUPF_PACKET_DIR to retain the exact BPF_PROG_TEST_RUN input and output.
// These captures describe returned buffers, not delivery by a physical NIC.
type datapathContext struct {
	Data, DataEnd, DataMeta, IngressIfindex, RxQueueIndex, EgressIfindex uint32
}

func runDatapath(t *testing.T, b *BpfObjects, packet []byte, context ...*datapathContext) (uint32, []byte) {
	t.Helper()
	var action uint32
	var out []byte
	var err error
	if len(context) == 0 {
		action, out, err = b.UpfIpEntrypointFunc.Test(packet)
	} else {
		inputContext := *context[0]
		inputContext.DataEnd = uint32(len(packet))
		opts := cilium.RunOptions{Data: packet, DataOut: make([]byte, len(packet)+512), Context: &inputContext}
		action, err = b.UpfIpEntrypointFunc.Run(&opts)
		out = opts.DataOut
	}
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("EUPF_PACKET_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0750); err != nil {
			t.Fatal(err)
		}
		name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
		f, err := os.CreateTemp(dir, name+"-*.pcap")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("capture=%s", f.Name())
		w := pcapgo.NewWriter(f)
		if err := w.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
			t.Fatal(err)
		}
		for i, p := range [][]byte{packet, out} {
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(0, int64(i)*1000000), CaptureLength: len(p), Length: len(p)}
			if err := w.WritePacket(ci, p); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("action=%d input=%d output=%d", action, len(packet), len(out))
	return action, out
}

func rsDatapath(t *testing.T, src string, hopLimit uint8, code uint8) []byte {
	t.Helper()
	ip := &layers.IPv6{Version: 6, HopLimit: hopLimit, NextHeader: layers.IPProtocolICMPv6,
		SrcIP: net.ParseIP(src), DstIP: net.ParseIP("ff02::2")}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, code)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return serializeDatapath(t, ip, icmp, &layers.ICMPv6RouterSolicitation{})
}

func TestDatapathRouterAdvertisementDestination(t *testing.T) {
	// RFC 4861 sections 4.2 and 6.2.6: reply to the solicitor or all-nodes.
	for _, src := range []string{"fe80::1234", "::"} {
		t.Run(src, func(t *testing.T) {
			b := loadDatapath(t)
			_, out := runDatapath(t, b, gtpDatapath(t, rsDatapath(t, src, 255, 0), nil, 0x30, false))
			p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			ip, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok || p.Layer(layers.LayerTypeICMPv6RouterAdvertisement) == nil {
				t.Fatal("no router advertisement in output")
			}
			if !ip.DstIP.Equal(net.ParseIP("ff02::1")) && (src == "::" || !ip.DstIP.Equal(net.ParseIP(src))) {
				t.Errorf("RA destination=%s, want all-nodes or non-unspecified solicitor %s", ip.DstIP, src)
			}
		})
	}
}

func TestDatapathRejectInvalidRouterSolicitation(t *testing.T) {
	// RFC 4861 section 6.1.1 requires all validity checks before responding.
	for _, tc := range []struct {
		name        string
		hop, code   uint8
		badChecksum bool
	}{{"hop_limit", 254, 0, false}, {"code", 255, 1, false}, {"checksum", 255, 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			b := loadDatapath(t)
			inner := rsDatapath(t, "fe80::1234", tc.hop, tc.code)
			if tc.badChecksum {
				inner[42] ^= 1
			}
			_, out := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
			p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			if p.Layer(layers.LayerTypeICMPv6RouterAdvertisement) != nil {
				t.Error("invalid solicitation produced a router advertisement")
			}
		})
	}
}

func TestDatapathDecapsulateHeaderLengths(t *testing.T) {
	// TS 29.281 V19.2.0 clauses 5.1 and 5.2.1 specify optional words and
	// extension lengths in four-octet units. RFC 791 section 3.1 defines IHL.
	for _, tc := range []struct {
		name     string
		flags    byte
		optional []byte
		options  bool
	}{
		{"base", 0x30, nil, false},
		{"sequence", 0x32, []byte{0, 1, 0, 0}, false},
		{"psc_four_octets", 0x34, []byte{0, 0, 0, 0x85, 1, 0x10, 5, 0}, false},
		// UL Delay Result is present (TS 38.415 V19.1.0 figure 5.5.2.2-1).
		{"extension_eight_octets", 0x34, []byte{0, 0, 0, 0x85, 2, 0x12, 5, 0, 0, 0, 1, 0}, false},
		// Unknown type 0x21 has comprehension-not-required bits 00.
		{"extension_chain", 0x34, []byte{0, 0, 0, 0x85, 1, 0x10, 5, 0x21, 1, 0, 0, 0}, false},
		{"ipv4_options", 0x30, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := loadDatapath(t)
			inner := udpDatapath(t, false)
			action, out := runDatapath(t, b, gtpDatapath(t, inner, tc.optional, tc.flags, tc.options))
			if action == 0 || len(out) < 14+len(inner) || !bytes.Equal(out[14:14+len(inner)], inner) {
				t.Error("valid variable-length GTP/IP header did not decapsulate to the original T-PDU")
			}
		})
	}
}

func anyDatapathFilter(proto uint8) SdfFilter {
	return SdfFilter{Protocol: proto, SrcPortRange: PortRange{0, 65535}, DstPortRange: PortRange{0, 65535}}
}

func TestDatapathICMPSdfSelection(t *testing.T) {
	// TS 29.244 V20.1.0 clauses 5.2.1A and 8.2.5: match the protocol in
	// the provisioned SDF filter before applying its FAR.
	b := loadDatapath(t)
	if err := b.PutPdrUplink(10, PdrInfo{FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(0)}}); err != nil {
		t.Fatal(err)
	}
	inner := serializeDatapath(t, &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4,
		SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)})
	action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
	if action != 1 {
		t.Errorf("matching ICMP DROP filter returned action=%d", action)
	}
}

func TestDatapathIPv6DownlinkUDPSdfSelection(t *testing.T) {
	b := loadDatapath(t)
	ip := net.ParseIP("2001:db8::2")
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3}), Teid: 20})
	if err := b.PutDownlinkPdrIp6(ip, PdrInfo{OuterHeaderRemovalPresent: true, PdrID: 1, Precedence: ^uint32(0), ReturnFarID: 3, ReturnQerIDs: []uint32{1}, FarId: 1, QerIDs: []uint32{1}}); err != nil {
		t.Fatal(err)
	}
	f := anyDatapathFilter(3)
	f.DstPortRange = PortRange{4321, 4321}
	if err := b.PutDownlinkPdrIp6(ip, PdrInfo{FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{f}}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv6, udpDatapath(t, true)))
	if action != 1 {
		t.Errorf("matching IPv6 UDP-port DROP filter returned action=%d", action)
	}
}

func TestDatapathIPv6SubnetSdfSelection(t *testing.T) {
	b := loadDatapath(t)
	f := anyDatapathFilter(1)
	ip, subnet, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatal(err)
	}
	f.SrcAddress = IpWMask{Type: 2, Ip: ip, Mask: subnet.Mask}
	if err := b.PutPdrUplink(10, PdrInfo{FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{f}}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, true), nil, 0x30, false))
	if action != 1 {
		t.Errorf("matching IPv6 /64 DROP filter returned action=%d", action)
	}
}

func TestDatapathQerRateAboveGigabit(t *testing.T) {
	// TS 29.244 V20.1.0 clause 5.4.4: a nonzero MBR must be enforced.
	b := loadDatapath(t)
	q := IpEntrypointQerInfo{UlMaximumBitrate: 2_000_000_000}
	putDatapath(t, b.QerMap.Put, uint32(1), &q)
	// A local N9 tunnel keeps the input reusable across kernel benchmark
	// repetitions. Tail calls are bounded by the kernel; the QER must
	// enforce the same budget on every traversal.
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{
		Action: 2, OuterHeaderCreation: 1, Teid: 10,
		Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1}),
	})
	inner := udpDatapath(t, false)
	// A large, valid T-PDU makes the enforcement check insensitive to
	// userspace syscall overhead. The repeat loop runs inside the kernel.
	inner = append(inner, make([]byte, 1368)...)
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.IP{198, 51, 100, 1}, DstIP: net.IP{198, 51, 100, 2}}
	u := &layers.UDP{SrcPort: 1234, DstPort: 4321}
	if err := u.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	inner = serializeDatapath(t, ip, u, gopacket.Payload(inner[28:]))
	packet := gtpDatapath(t, inner, nil, 0x30, false)
	start := time.Now()
	if _, _, err := b.UpfIpEntrypointFunc.Benchmark(packet, 10000, func() {}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	usage, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	// Allow a full 5ms burst window and one packet beyond the wall-time
	// rate budget. A slow machine can pass this check; it cannot fail a
	// correct limiter merely because the benchmark ran slowly.
	budget := uint64((elapsed+5*time.Millisecond).Nanoseconds())/4 + uint64(len(inner))
	t.Logf("elapsed=%s delivered=%d budget=%d", elapsed, usage.UplinkVolume, budget)
	if usage.UplinkVolume > budget {
		t.Errorf("2Gbit/s MBR exceeded: delivered=%d allowed=%d", usage.UplinkVolume, budget)
	}
}

func TestDatapathIDZeroRemainsReserved(t *testing.T) {
	ids := NewIdTracker(3)
	ids.Release(0)
	id, err := ids.GetNext()
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Error("releasing zero made the reserved default-map entry allocatable")
	}
}

func TestDatapathUrrCountsTPDU(t *testing.T) {
	// TS 29.244 V20.1.0 clause 8.2.44 measures user traffic volume;
	// TS 32.255 V19.7.0 clause 5.2.1.4 counts user plane payload at the UPF.
	// GTP sequence/extension words and Ethernet padding are not T-PDU data.
	for _, tc := range []struct {
		name     string
		downlink bool
		optional []byte
		flags    byte
	}{
		{"uplink_sequence", false, []byte{0, 1, 0, 0}, 0x32},
		{"downlink_padding", true, nil, 0x30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := loadDatapath(t)
			inner := udpDatapath(t, false)
			var packet []byte
			if tc.downlink {
				putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3}), Teid: 20})
				if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{FarId: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
					t.Fatal(err)
				}
				packet = ethernetDatapath(t, layers.EthernetTypeIPv4, inner)
			} else {
				packet = gtpDatapath(t, inner, tc.optional, tc.flags, false)
			}
			runDatapath(t, b, packet)
			u, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			got := u.UplinkVolume
			if tc.downlink {
				got = u.DownlinkVolume
			}
			if got != 32 {
				t.Errorf("counted %d octets for a 32-octet T-PDU", got)
			}
		})
	}
}

func TestDatapathPreprocessPreservesLookupError(t *testing.T) {
	_, err := preparePDR(func(interface{}, interface{}) error { return syscall.EBADF }, uint32(10), PdrInfo{})
	if !errors.Is(err, syscall.EBADF) {
		t.Errorf("lookup EBADF was discarded: %v", err)
	}
}

func TestDatapathResizeReplacesProgramMap(t *testing.T) {
	b := NewBpfObjects()
	if err := b.ResizeAllMaps(2048, 2048, 2048, 2048); err != nil {
		t.Fatal(err)
	}
	if err := b.Load(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	}()
	info, err := b.FarMap.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxEntries != 2048 {
		t.Fatalf("capacity=%d", info.MaxEntries)
	}
	putDatapath(t, b.FarMap.Put, uint32(1500), &IpEntrypointFarInfo{Action: 1})
	if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{FarId: 1500}); err != nil {
		t.Fatal(err)
	}
	action, _ := runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false)))
	if action != 1 {
		t.Errorf("program ignored resized FAR map: action=%d", action)
	}
	if err := b.ResizeAllMaps(4096, 4096, 4096, 4096); err == nil {
		t.Error("live resize accepted")
	}
	action, _ = runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false)))
	if action != 1 {
		t.Error("rejected live resize changed map references")
	}
}

func TestDatapathShortSdfEvent(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[v6], func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("short event panicked: %v", r)
				}
			}()
			var e SdfEvent
			if v6 {
				if err := e.UnmarshalIPv6(make([]byte, 32)); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("short tuple error=%v", err)
				}
			} else {
				if err := e.UnmarshalIPv4(make([]byte, 8)); !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Errorf("short tuple error=%v", err)
				}
			}
		})
	}
}

func TestDatapathUnexpectedGtpCounter(t *testing.T) {
	c := UpfCounters{}
	c.Add(UpfCounters{RxGtpUnexp: 3})
	if c.RxGtpUnexp != 3 {
		t.Errorf("unexpected-GTP aggregate=%d, want 3", c.RxGtpUnexp)
	}
	previous := UpfCounters{}
	d := previous.Delta(UpfCounters{RxGtpUnexp: 3})
	if d.RxGtpUnexp != 3 {
		t.Errorf("unexpected-GTP delta=%d, want 3", d.RxGtpUnexp)
	}
}

func TestDatapathRouterAdvertisementRouteFallback(t *testing.T) {
	// This isolates the existing RS/RA fixture's local tunnel from the
	// separate RFC 4861 destination defect. No IPv6 route is installed.
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local_tunnel", false: "remote_tunnel"}[local], func(t *testing.T) {
			b := loadDatapath(t)
			remote := net.IP{192, 0, 2, 3}
			if local {
				remote = net.IP{192, 0, 2, 1}
			}
			putDatapath(t, b.FarMap.Put, uint32(3), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(remote), Teid: 10})
			if err := b.PutDownlinkPdrIp6(net.ParseIP("fe80::1234"), PdrInfo{FarId: 3, QerIDs: []uint32{1}}); err != nil {
				t.Fatal(err)
			}
			action, out := runDatapath(t, b, gtpDatapath(t, rsDatapath(t, "fe80::1234", 255, 0), nil, 0x30, false))
			p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			stats := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfRouteStat()
			t.Logf("local=%t route counters=%+v", local, stats)
			if local {
				if action != 2 || stats.FibLookupIp6ErrorPass != 1 || p.Layer(layers.LayerTypeGTPv1U) != nil || p.Layer(layers.LayerTypeICMPv6RouterAdvertisement) == nil {
					t.Error("expected local tunnel decapsulation followed by IPv6 FIB fallback")
				}
			} else if p.Layer(layers.LayerTypeGTPv1U) == nil {
				t.Error("remote tunnel did not retain GTP encapsulation")
			}
		})
	}
}

func checksumDatapath(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) != 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestDatapathN9IPv4OptionsChecksum(t *testing.T) {
	// RFC 791 section 3.1: the header checksum covers the complete header,
	// including options. RFC 1071 section 1 defines one's-complement sum.
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1,
		Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3}), Teid: 20})
	_, out := runDatapath(t, b, gtpDatapath(t, udpDatapath(t, false), nil, 0x30, true))
	if len(out) < 38 {
		t.Fatal("short N9 output")
	}
	if checksumDatapath(out[14:38]) != 0 {
		t.Error("N9 rewrite produced an invalid IPv4 options checksum")
	}
}

func TestDatapathIPv6TrafficClassPreservesFlowLabel(t *testing.T) {
	// RFC 8200 section 3: Traffic Class and Flow Label occupy distinct fields.
	b := loadDatapath(t)
	putDatapath(t, b.QerMap.Put, uint32(1), &IpEntrypointQerInfo{Dscp: 0xab})
	inner := udpDatapath(t, true)
	binary.BigEndian.PutUint32(inner[:4], 6<<28|0x35<<20|0x80001)
	_, out := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
	p := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
	ip, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ok {
		t.Fatal("no IPv6 output")
	}
	if ip.TrafficClass != 0xab || ip.FlowLabel != 0x80001 {
		t.Errorf("Traffic Class=%02x Flow Label=%05x, want ab and 80001", ip.TrafficClass, ip.FlowLabel)
	}
}

func TestDatapathOuterFragmentIsNotGTPHeader(t *testing.T) {
	// RFC 791 section 3.1: a nonzero fragment offset means the fragment
	// does not begin with the transport header of the original datagram.
	b := loadDatapath(t)
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	binary.BigEndian.PutUint16(packet[20:22], 1)
	packet[24], packet[25] = 0, 0
	binary.BigEndian.PutUint16(packet[24:26], checksumDatapath(packet[14:34]))
	runDatapath(t, b, packet)
	u, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if u.UplinkVolume != 0 {
		t.Errorf("noninitial fragment was interpreted as UDP/GTP and charged %d octets", u.UplinkVolume)
	}
}

func TestDatapathGateDirections(t *testing.T) {
	// TS 29.244 V20.1.0 clause 5.4.3 requires independent UL/DL gating.
	for _, downlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "uplink", true: "downlink"}[downlink], func(t *testing.T) {
			b := loadDatapath(t)
			q := IpEntrypointQerInfo{UlGateStatus: 1}
			packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
			if downlink {
				q = IpEntrypointQerInfo{DlGateStatus: 1}
				putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3}), Teid: 20})
				if err := b.PutPdrDownlink(net.IP{198, 51, 100, 2}, PdrInfo{FarId: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
					t.Fatal(err)
				}
				packet = ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false))
			}
			putDatapath(t, b.QerMap.Put, uint32(1), &q)
			action, _ := runDatapath(t, b, packet)
			u, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			if action != 1 || u.UplinkVolume != 0 || u.DownlinkVolume != 0 {
				t.Errorf("closed gate action=%d usage=%+v", action, u)
			}
		})
	}
}

func TestDatapathConcurrentUrrCounts(t *testing.T) {
	// TS 29.244 V20.1.0 clauses 5.2.2.2.1 and 8.2.44 require a shared
	// URR's volume to include packets arriving on every processing CPU.
	b := loadDatapath(t)
	putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{
		Action: 2, OuterHeaderCreation: 1, Teid: 10, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1}),
	})
	packet := gtpDatapath(t, udpDatapath(t, false), nil, 0x30, false)
	const repeats = 1000
	if _, _, err := b.UpfIpEntrypointFunc.Benchmark(packet, repeats, func() {}); err != nil {
		t.Fatal(err)
	}
	serial, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	if serial.UplinkVolume == 0 {
		t.Fatal("serial control processed no packets")
	}
	putDatapath(t, b.UrrMap.Put, uint32(1), &IpEntrypointUrrInfo{})
	const parallel = 4
	var wg sync.WaitGroup
	results := make(chan error, parallel)
	for range parallel {
		wg.Go(func() { _, _, err := b.UpfIpEntrypointFunc.Benchmark(packet, repeats, func() {}); results <- err })
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	concurrent, err := b.GetUrr(1)
	if err != nil {
		t.Fatal(err)
	}
	want := serial.UplinkVolume * parallel
	t.Logf("serial=%d concurrent=%d want=%d", serial.UplinkVolume, concurrent.UplinkVolume, want)
	if concurrent.UplinkVolume != want {
		t.Error("concurrent URR updates lost or duplicated traffic volume")
	}
}

func TestDatapathGtpEnvelopeValidation(t *testing.T) {
	// TS 29.281 V19.2.0 clause 5.1 defines the version, PT and complete
	// length of a GTP-U message. Invalid envelopes must not charge a PDR.
	for _, tc := range []struct {
		name   string
		flags  byte
		length uint16
	}{
		{"short_length", 0x30, 0}, {"long_length", 0x30, 65535},
		{"version_zero", 0x10, 32}, {"gtp_prime", 0x20, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := loadDatapath(t)
			g := make([]byte, 8)
			g[0], g[1] = tc.flags, 255
			binary.BigEndian.PutUint16(g[2:4], tc.length)
			binary.BigEndian.PutUint32(g[4:8], 10)
			g = append(g, udpDatapath(t, false)...)
			packet := outerDatapath(t, g, false)
			_, out := runDatapath(t, b, packet)
			u, err := b.GetUrr(1)
			if err != nil {
				t.Fatal(err)
			}
			if u.UplinkVolume != 0 {
				t.Errorf("invalid GTP envelope charged %d octets", u.UplinkVolume)
			}
			if !bytes.Equal(packet, out) {
				t.Error("invalid GTP envelope was decapsulated or rewritten")
			}
		})
	}
}

func TestDatapathEchoRecoveryWithIPv4Options(t *testing.T) {
	// TS 29.281 V19.2.0 clause 7.2.2 and table 7.2.2-1 require Recovery
	// in every Echo Response, including when the request has no tailroom.
	for _, count := range []int{0, 8} {
		t.Run(map[int]string{0: "base", 8: "options"}[count], func(t *testing.T) {
			b := loadDatapath(t)
			ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
				SrcIP: net.IP{192, 0, 2, 2}, DstIP: net.IP{192, 0, 2, 1}}
			for range count {
				ip.Options = append(ip.Options, layers.IPv4Option{OptionType: 1})
			}
			u := &layers.UDP{SrcPort: 2152, DstPort: 2152}
			if err := u.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			g := make([]byte, 18)
			g[0], g[1] = 0x32, 1
			binary.BigEndian.PutUint16(g[2:4], uint16(len(g)-8))
			binary.BigEndian.PutUint16(g[8:10], 0x1234)
			// A permitted Private Extension in the request must not become
			// stray bytes in the fresh mandatory-only Echo Response.
			copy(g[12:], []byte{255, 0, 3, 0x12, 0x34, 0xaa})
			packet := ethernetDatapath(t, layers.EthernetTypeIPv4, serializeDatapath(t, ip, u, gopacket.Payload(g)))
			action, out := runDatapath(t, b, packet)
			offset := 14 + 20 + count + 8
			if action != 3 || len(out) < offset+14 || binary.BigEndian.Uint16(out[offset+2:offset+4]) != 6 || binary.BigEndian.Uint16(out[offset+8:offset+10]) != 0x1234 || out[offset+12] != 14 || out[offset+13] != 0 {
				t.Error("Echo Response omitted its mandatory Recovery IE")
			}
		})
	}
}

func routeDatapathFixture(t *testing.T) *datapathContext {
	t.Helper()
	in, out := "dpin", "dpout"
	ip := func(args ...string) {
		t.Helper()
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, output)
		}
	}
	ip("link", "add", in, "type", "dummy")
	t.Cleanup(func() {
		if err := exec.Command("ip", "link", "del", in).Run(); err != nil {
			t.Error(err)
		}
	})
	ip("link", "add", out, "type", "dummy")
	t.Cleanup(func() {
		if err := exec.Command("ip", "link", "del", out).Run(); err != nil {
			t.Error(err)
		}
	})
	ip("link", "set", in, "up")
	ip("link", "set", out, "mtu", "1460", "up")
	ip("addr", "add", "198.18.0.1/24", "dev", out)
	ip("neigh", "add", "198.18.0.2", "lladdr", "02:00:00:00:00:03", "nud", "permanent", "dev", out)
	ip("-6", "addr", "add", "2001:db8:ef::1/64", "dev", out, "nodad")
	ip("-6", "neigh", "add", "2001:db8:ef::2", "lladdr", "02:00:00:00:00:03", "nud", "permanent", "dev", out)
	for _, path := range []string{"/proc/sys/net/ipv4/conf/dpin/forwarding", "/proc/sys/net/ipv6/conf/dpin/forwarding", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Error(err)
			}
		})
	}
	iface, err := net.InterfaceByName(in)
	if err != nil {
		t.Fatal(err)
	}
	return &datapathContext{IngressIfindex: uint32(iface.Index)}
}

func TestDatapathForwardingHopLimit(t *testing.T) {
	// RFC 791 section 3.2 and RFC 8200 section 3 require forwarding to
	// decrease TTL/Hop Limit and stop forwarding when it is exhausted.
	for _, v6 := range []bool{false, true} {
		for _, ttl := range []uint8{1, 64} {
			name := map[bool]string{false: "ipv4", true: "ipv6"}[v6] + "_" + map[uint8]string{1: "expired", 64: "forward"}[ttl]
			t.Run(name, func(t *testing.T) {
				ctx := routeDatapathFixture(t)
				b := loadDatapath(t)
				inner := udpDatapath(t, v6)
				if v6 {
					copy(inner[24:40], net.ParseIP("2001:db8:ef::2").To16())
					inner[7] = ttl
				} else {
					copy(inner[16:20], net.IP{198, 18, 0, 2})
					inner[8] = ttl
					inner[10], inner[11] = 0, 0
					binary.BigEndian.PutUint16(inner[10:12], checksumDatapath(inner[:20]))
				}
				// Recompute the UDP checksum after changing the destination.
				start := 20
				if v6 {
					start = 40
				}
				inner[start+6], inner[start+7] = 0, 0
				var pseudo []byte
				if v6 {
					pseudo = append(pseudo, inner[8:40]...)
					pseudo = append(pseudo, 0, 0, 0, 12, 0, 0, 0, 17)
				} else {
					pseudo = append(pseudo, inner[12:20]...)
					pseudo = append(pseudo, 0, 17, 0, 12)
				}
				pseudo = append(pseudo, inner[start:]...)
				binary.BigEndian.PutUint16(inner[start+6:start+8], checksumDatapath(pseudo))
				action, out := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false), ctx)
				stats := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfRouteStat()
				t.Logf("route counters=%+v", stats)
				if ttl == 1 {
					if action == 3 || action == 4 {
						t.Error("exhausted packet was forwarded")
					}
					return
				}
				if action != 3 && action != 4 {
					t.Fatal("fixture did not reach successful FIB forwarding")
				}
				offset := 14 + 8
				if v6 {
					offset = 14 + 7
				}
				if out[offset] != 63 {
					t.Errorf("forwarded TTL/Hop Limit=%d, want 63", out[offset])
				}
			})
		}
	}
}

func TestDatapathIPv6MTUIncludesHeader(t *testing.T) {
	// RFC 8200 section 5 requires the complete IPv6 packet to fit the
	// outgoing link MTU. The fixed IPv6 header contributes 40 octets.
	for _, tc := range []struct {
		name    string
		size    int
		forward bool
	}{
		{"fits", 1460, true}, {"header_exceeds_mtu", 1490, false}, {"payload_exceeds_mtu", 1501, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := routeDatapathFixture(t)
			b := loadDatapath(t)
			ip := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolUDP, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8:ef::2")}
			u := &layers.UDP{SrcPort: 1234, DstPort: 4321}
			if err := u.SetNetworkLayerForChecksum(ip); err != nil {
				t.Fatal(err)
			}
			inner := serializeDatapath(t, ip, u, gopacket.Payload(make([]byte, tc.size-48)))
			action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false), ctx)
			stats := (&UpfXdpActionStatistic{BpfObjects: b}).GetUpfRouteStat()
			t.Logf("IPv6 packet=%d link MTU=1460 route counters=%+v", len(inner), stats)
			forwarded := action == 3 || action == 4
			if forwarded != tc.forward {
				t.Errorf("IPv6 packet=%d link MTU=1460 forwarded=%t, want %t", len(inner), forwarded, tc.forward)
			}
		})
	}
}

func TestDatapathIPv4PdrAddressForms(t *testing.T) {
	// A net.IP representing IPv4 may have either four or sixteen bytes.
	// Both must install the same IPv4 datapath rule.
	for _, short := range []bool{true, false} {
		t.Run(map[bool]string{true: "four_bytes", false: "sixteen_bytes"}[short], func(t *testing.T) {
			b := loadDatapath(t)
			ip := net.ParseIP("198.51.100.2")
			if short {
				ip = ip.To4()
			}
			if err := b.PutPdrDownlink(ip, PdrInfo{FarId: 2, QerIDs: []uint32{1}}); err != nil {
				t.Fatal(err)
			}
			action, _ := runDatapath(t, b, ethernetDatapath(t, layers.EthernetTypeIPv4, udpDatapath(t, false)))
			if action != 1 {
				t.Errorf("IPv4 address length=%d did not install a DROP rule: action=%d", len(ip), action)
			}
		})
	}
}

func TestDatapathRouterSolicitationOptions(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		option       []byte
		valid        bool
	}{
		{"zero_length", "fe80::1234", []byte{1, 0, 2, 3, 4, 5, 6, 7}, false},
		{"truncated", "fe80::1234", []byte{1, 2, 2, 3, 4, 5, 6, 7}, false},
		{"unspecified_source_ll", "::", []byte{1, 1, 2, 3, 4, 5, 6, 7}, false},
		{"unknown_option", "fe80::1234", []byte{253, 1, 2, 3, 4, 5, 6, 7}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := loadDatapath(t)
			inner := append(rsDatapath(t, tc.source, 255, 0), tc.option...)
			length := len(inner) - 40
			binary.BigEndian.PutUint16(inner[4:6], uint16(length))
			inner[42], inner[43] = 0, 0
			pseudo := append(append([]byte(nil), inner[8:40]...), 0, 0, 0, byte(length), 0, 0, 0, 58)
			binary.BigEndian.PutUint16(inner[42:44], checksumDatapath(append(pseudo, inner[40:]...)))
			action, out := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
			packet := gopacket.NewPacket(out, layers.LayerTypeEthernet, gopacket.Default)
			ra := packet.Layer(layers.LayerTypeICMPv6RouterAdvertisement)
			if tc.valid && ra == nil {
				t.Error("valid unknown option prevented RA")
			}
			if !tc.valid && (ra != nil || action != 1) {
				t.Errorf("invalid RS option was not silently discarded: action=%d", action)
			}
		})
	}
}

func TestDatapathICMPv6SdfSelection(t *testing.T) {
	b := loadDatapath(t)
	if err := b.PutPdrUplink(10, PdrInfo{FarId: 2, QerIDs: []uint32{1}, SdfFilter: []SdfFilter{anyDatapathFilter(4)}}); err != nil {
		t.Fatal(err)
	}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	inner := serializeDatapath(t, ip, icmp, gopacket.Payload([]byte{0, 1, 0, 1}))
	action, _ := runDatapath(t, b, gtpDatapath(t, inner, nil, 0x30, false))
	if action != 1 {
		t.Errorf("ICMPv6 DROP filter was bypassed: action=%d", action)
	}
}

func TestDatapathDownlinkHopLimit(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, ttl := range []uint8{1, 64} {
			name := map[bool]string{false: "ipv4", true: "ipv6"}[v6] + "_" + map[uint8]string{1: "expired", 64: "forward"}[ttl]
			t.Run(name, func(t *testing.T) {
				b := loadDatapath(t)
				putDatapath(t, b.FarMap.Put, uint32(1), &IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 20, Remoteip: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 3})})
				inner := udpDatapath(t, v6)
				ip := net.IP{198, 51, 100, 2}
				etherType := layers.EthernetTypeIPv4
				hopOffset := 8
				if v6 {
					ip = net.ParseIP("2001:db8::2")
					etherType = layers.EthernetTypeIPv6
					hopOffset = 7
				}
				inner[hopOffset] = ttl
				if !v6 {
					inner[10], inner[11] = 0, 0
					binary.BigEndian.PutUint16(inner[10:12], checksumDatapath(inner[:20]))
				}
				if err := b.PutPdrDownlink(ip, PdrInfo{FarId: 1, QerIDs: []uint32{1}}); err != nil {
					t.Fatal(err)
				}
				action, out := runDatapath(t, b, ethernetDatapath(t, etherType, inner))
				if ttl == 1 {
					if action == 3 || action == 4 {
						t.Error("exhausted inner packet was encapsulated and forwarded")
					}
					return
				}
				if action != 4 {
					t.Fatalf("tunnel route action=%d", action)
				}
				if out[50+hopOffset] != 63 {
					t.Errorf("forwarded inner lifetime=%d, want 63", out[50+hopOffset])
				}
			})
		}
	}
}

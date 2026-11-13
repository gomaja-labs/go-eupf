// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	n3IP       = net.ParseIP("10.3.0.10")
	n9IP       = net.ParseIP("10.3.0.20")
	IPv6Prefix = net.ParseIP("2a03:d000:29a0:509::")

	n3MAC = net.HardwareAddr{1, 0, 0, 3, 0, 10}
	n9MAC = net.HardwareAddr{1, 0, 0, 3, 0, 20}
)

func testArp(bpfObjects *BpfObjects) error {

	packetArp := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packetArp, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	bpfRet, bufOut, err := bpfObjects.UpfIpEntrypointFunc.Test(packetArp.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %w", err)
	}
	if bpfRet != 2 { // XDP_PASS
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}
	if !reflect.DeepEqual(bufOut, packetArp.Bytes()) {
		return errors.New("unexpected data modification")
	}

	return nil
}

func testArpBenchmark(bpfObjects *BpfObjects, repeat int) (int64, error) {

	packetArp := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packetArp, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{},
	); err != nil {
		return 0, fmt.Errorf("serializing input packet failed: %w", err)
	}

	_, duration, err := bpfObjects.UpfIpEntrypointFunc.Benchmark(packetArp.Bytes(), repeat, func() {})
	if err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}

	return duration.Nanoseconds(), nil
}

func testGtpBenchmark(bpfObjects *BpfObjects, repeat int) (int64, error) {

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           1,
			SequenceNumber: 0,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.IP{1, 1, 1, 1},
			SrcIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoRequest,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return 0, fmt.Errorf("serializing input packet failed: %w", err)
	}

	_, duration, err := bpfObjects.UpfIpEntrypointFunc.Benchmark(packet.Bytes(), repeat, func() {})
	if err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}

	return duration.Nanoseconds(), nil
}

func testGtpWithPDRBenchmark(bpfObjects *BpfObjects, repeat int) (int64, error) {

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.IP{1, 1, 1, 1},
			SrcIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoRequest,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return 0, fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := IpEntrypointPdrInfo{Count: 1}
	pdr.Entries[0].Pdr.OuterHeaderRemoval = 0
	pdr.Entries[0].Pdr.FarId = 1
	pdr.Count = 1
	pdr.Entries[0].Pdr.QerCount = 1
	pdr.Entries[0].Pdr.QerId[0] = 1
	far := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &far); err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}
	if err := bpfObjects.PutPdrUplink(teid, DecodePDRBucket(pdr)[0]); err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}

	_, duration, err := bpfObjects.UpfIpEntrypointFunc.Benchmark(packet.Bytes(), repeat, func() {})
	if err != nil {
		return 0, fmt.Errorf("benchmark run failed: %w", err)
	}

	return duration.Nanoseconds(), nil
}

func testGtpEcho(t *testing.T, bpfObjects *BpfObjects) error {
	t.Helper()

	packetArp := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packetArp, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:            1,
			MessageType:        1, // GTPU_ECHO_REQUEST
			SequenceNumberFlag: true,
			TEID:               0,
			SequenceNumber:     0,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	bpfRet, bufOut, err := bpfObjects.UpfIpEntrypointFunc.Test(packetArp.Bytes())
	if err != nil {
		return fmt.Errorf("test run failed: %w", err)
	}
	if bpfRet != 3 { // XDP_TX
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	response := gopacket.NewPacket(bufOut, layers.LayerTypeEthernet, gopacket.Default)

	t.Logf("response: %v", response)
	t.Logf("gtpLayer: %v", response.Layer(layers.LayerTypeGTPv1U))

	if gtpLayer := response.Layer(layers.LayerTypeGTPv1U); gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		if gtp.MessageType != 2 { //GTPU_ECHO_RESPONSE
			return fmt.Errorf("unexpected gtp response: %d", gtp.MessageType)
		}
		if gtp.SequenceNumber != 0 {
			return fmt.Errorf("unexpected gtp sequence: %d", gtp.SequenceNumber)
		}
		if gtp.TEID != 0 {
			return fmt.Errorf("unexpected gtp TEID: %d", gtp.TEID)
		}
	} else {
		return errors.New("unexpected response")
	}

	return nil
}

func testGtpWithSDFFilter(bpfObjects *BpfObjects) error {

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.IP{1, 1, 1, 1},
			SrcIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoRequest,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	farDrop := IpEntrypointFarInfo{Action: 1, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.FarMap.Put(uint32(2), &farDrop); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	sdf := SdfFilter{
		Protocol:     SDFProtocolAny,
		SrcAddress:   IpWMask{Type: 1, Ip: net.IP{10, 60, 0, 1}, Mask: net.IPMask{255, 255, 255, 255}},
		DstAddress:   IpWMask{Type: 1, Ip: net.IP{1, 1, 1, 1}, Mask: net.IPMask{255, 255, 255, 255}},
		SrcPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
		DstPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
	}
	pdr.SdfFilter = []SdfFilter{sdf}
	pdr.FarId = 2
	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, _, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 1 { // XDP_DROP
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	return nil
}

func testGtpHeaderWithSequence(t *testing.T, bpfObjects *BpfObjects) error {
	t.Helper()

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:            1,
			MessageType:        255, // GTPU_G_PDU
			MessageLength:      44,
			TEID:               teid,
			SequenceNumberFlag: true,
			SequenceNumber:     1234,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.IP{1, 1, 1, 1},
			SrcIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoRequest,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	t.Logf("packet: %v", packet.Layers())

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 0, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, _, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 3 && bpfRet != 4 { // XDP_TX or XDP_REDIRECT
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	return nil
}

func testGtpIPv4WithSDFFilterV6(bpfObjects *BpfObjects) error {

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.ParseIP("1.1.1.1"),
			SrcIP:    net.ParseIP("10.60.0.1"),
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoRequest,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	farDrop := IpEntrypointFarInfo{Action: 1, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farDrop); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.FarMap.Put(uint32(2), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	srcIP, srcNet, err := net.ParseCIDR("ff02::2/128")
	if err != nil {
		return fmt.Errorf("can't parse CIDR: %w", err)
	}

	sdf := SdfFilter{
		Protocol:     58,
		SrcAddress:   IpWMask{Type: 2, Ip: srcIP, Mask: srcNet.Mask},
		DstAddress:   IpWMask{Type: 0},
		SrcPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
		DstPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
	}
	pdr.SdfFilter = []SdfFilter{sdf}
	pdr.FarId = 2
	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, _, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 1 { // XDP_DROP
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	return nil
}

func testGtpWithSDFFilterV6(bpfObjects *BpfObjects) error {

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv6{
			Version:    6,
			DstIP:      net.ParseIP("2001:db8::1"),
			SrcIP:      net.ParseIP("2001:db8::2"),
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
		},
		&layers.ICMPv6{
			TypeCode: layers.ICMPv6TypeEchoRequest,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	farDrop := IpEntrypointFarInfo{Action: 1, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.FarMap.Put(uint32(2), &farDrop); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	srcIP, srcNet, err := net.ParseCIDR("2001:db8::2/128")
	if err != nil {
		return fmt.Errorf("can't parse CIDR: %w", err)
	}

	dstIP, dstNet, err := net.ParseCIDR("2001:db8::1/128")
	if err != nil {
		return fmt.Errorf("can't parse CIDR: %w", err)
	}

	sdf := SdfFilter{
		Protocol:     SDFProtocolAny,
		SrcAddress:   IpWMask{Type: 2, Ip: srcIP, Mask: srcNet.Mask},
		DstAddress:   IpWMask{Type: 2, Ip: dstIP, Mask: dstNet.Mask},
		SrcPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
		DstPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
	}
	pdr.SdfFilter = []SdfFilter{sdf}
	pdr.FarId = 2
	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, _, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 1 { // XDP_DROP
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	return nil
}

func testGtpWithSDFFilterNotification(bpfObjects *BpfObjects) error {

	sdfListener, err := NewSdfNotifyListener(bpfObjects.SdfNotifyMap)
	if err != nil {
		return err
	}
	defer sdfListener.Close()
	sdfListener.SetNonblocked()

	teid := uint32(1)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    n3IP,
			SrcIP:    n9IP,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv4{
			Version: 4,
			TTL:     64,
			DstIP:   net.ParseIP("1.1.1.1"),
			SrcIP:   net.ParseIP("10.60.0.1"),
			//Protocol: layers.IPProtocolICMPv4,
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		// &layers.ICMPv4{
		// 	TypeCode: layers.ICMPv4TypeEchoRequest,
		// 	Id:       0,
		// 	Seq:      0,
		// },
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2153,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{Action: 2, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	farDrop := IpEntrypointFarInfo{Action: 1, OuterHeaderCreation: 1, Remoteip: binary.LittleEndian.Uint32(net.IP{198, 18, 1, 2}), Teid: 2, TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 0, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farDrop); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.FarMap.Put(uint32(2), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	sdf := SdfFilter{
		Protocol:     SDFProtocolAny,
		SrcAddress:   IpWMask{Type: 1, Ip: net.IP{10, 60, 0, 1}, Mask: net.IPMask{255, 255, 255, 255}},
		DstAddress:   IpWMask{Type: 1, Ip: net.IP{1, 1, 1, 1}, Mask: net.IPMask{255, 255, 255, 255}},
		SrcPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
		DstPortRange: PortRange{LowerBound: 0, UpperBound: 65535},
	}
	pdr.SdfFilter = []SdfFilter{sdf}
	pdr.FarId = 2
	pdr.NotifyFlag = true
	if err := bpfObjects.PutPdrUplink(teid, pdr); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, _, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	sdfEvent, err := sdfListener.ReadEventOnce()
	if err != nil {
		return fmt.Errorf("unexpected error while waiting for event: %v", err.Error())
	}

	if sdfEvent.SDFFilter != "permit in 17 from 10.60.0.1/32 2153 to 1.1.1.1/32 2152" {
		return fmt.Errorf("unexpected sdf flow filter: %v", sdfEvent.SDFFilter)
	}

	log.Println(sdfEvent.SDFFilter)

	if bpfRet != 4 { // XDP_REDIRECT
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	return nil
}

func testGtpExtHeader(t *testing.T, bpfObjects *BpfObjects) error {
	t.Helper()

	teid := uint32(2)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    net.IP{1, 1, 1, 1},
			DstIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			IHL:      5,
		},
		&layers.ICMPv4{
			TypeCode: layers.ICMPv4TypeEchoReply,
			Id:       0,
			Seq:      0,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{
		Action:                2,
		OuterHeaderCreation:   1,
		Remoteip:              binary.LittleEndian.Uint32(net.IP{10, 3, 0, 30}),
		Teid:                  teid,
		TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 5, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrDownlink(net.IP{10, 60, 0, 1}, pdr); err != nil {
		return fmt.Errorf("can't set downlink PDR: %w", err)
	}

	t.Logf("package %v", packet)

	bpfRet, bufOut, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 4 { // XDP_REDIRECT
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	response := gopacket.NewPacket(bufOut, layers.LayerTypeEthernet, gopacket.Default)
	if gtpLayer := response.Layer(layers.LayerTypeGTPv1U); gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		if gtp.MessageType != 255 { //GTPU_G_PDU
			return fmt.Errorf("unexpected gtp response: %d", gtp.MessageType)
		}
		if gtp.TEID != teid {
			return fmt.Errorf("unexpected gtp TEID: %d", gtp.TEID)
		}

		if gtp.ExtensionHeaderFlag == true {

			if len(gtp.GTPExtensionHeaders) != 1 {
				return fmt.Errorf("unexpected gtp extension header count: %d", len(gtp.GTPExtensionHeaders))
			}

			extHeader := gtp.GTPExtensionHeaders[0]
			if extHeader.Type != 0x85 {
				return fmt.Errorf("unexpected gtp extension header: %d", gtp.GTPExtensionHeaders[0].Type)
			}
			if len(extHeader.Content) != 2 {
				return fmt.Errorf("unexpected gtp extension header len: %d", len(extHeader.Content))
			}

			if extHeader.Content[1] != 5 {
				return fmt.Errorf("unexpected gtp extension header QFI: %d %d", extHeader.Content[0], extHeader.Content[1])
			}
		}
	} else {
		return fmt.Errorf("unexpected response: %v", response)
	}

	return nil
}

func testDLwithGTPPort(t *testing.T, bpfObjects *BpfObjects) error {
	t.Helper()

	teid := uint32(2)

	packet := gopacket.NewSerializeBuffer()
	if err := serializeFixture(packet, gopacket.SerializeOptions{
		FixLengths: true,
	},
		&layers.Ethernet{
			SrcMAC:       n3MAC,
			DstMAC:       n9MAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    net.IP{1, 1, 1, 1},
			DstIP:    net.IP{10, 60, 0, 1},
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			SrcPort: 2100,
			DstPort: 2152,
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{
		Action:                2,
		OuterHeaderCreation:   1,
		Remoteip:              binary.LittleEndian.Uint32(net.IP{10, 3, 0, 30}),
		Teid:                  teid,
		TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{QfiPresent: 1, Qfi: 5, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}

	if err := bpfObjects.PutPdrDownlink(net.IP{10, 60, 0, 1}, pdr); err != nil {
		return fmt.Errorf("can't set downlink PDR: %w", err)
	}

	t.Logf("package %v", packet)

	bpfRet, bufOut, err := bpfObjects.UpfIpEntrypointFunc.Test(packet.Bytes())
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 4 { // XDP_REDIRECT
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}

	response := gopacket.NewPacket(bufOut, layers.LayerTypeEthernet, gopacket.Default)
	if gtpLayer := response.Layer(layers.LayerTypeGTPv1U); gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		if gtp.MessageType != 255 { //GTPU_G_PDU
			return fmt.Errorf("unexpected gtp response: %d", gtp.MessageType)
		}
		if gtp.TEID != teid {
			return fmt.Errorf("unexpected gtp TEID: %d", gtp.TEID)
		}
		if gtp.ExtensionHeaderFlag == true {

			if len(gtp.GTPExtensionHeaders) != 1 {
				return fmt.Errorf("unexpected gtp extension header count: %d", len(gtp.GTPExtensionHeaders))
			}

			extHeader := gtp.GTPExtensionHeaders[0]
			if extHeader.Type != 0x85 {
				return fmt.Errorf("unexpected gtp extension header: %d", gtp.GTPExtensionHeaders[0].Type)
			}
			if len(extHeader.Content) != 2 {
				return fmt.Errorf("unexpected gtp extension header len: %d", len(extHeader.Content))
			}

			if extHeader.Content[1] != 5 {
				return fmt.Errorf("unexpected gtp extension header QFI: %d %d", extHeader.Content[0], extHeader.Content[1])
			}
		}
	} else {
		return fmt.Errorf("unexpected response: %v", response)
	}

	return nil
}

func testICMPv6RA(t *testing.T, bpfObjects *BpfObjects) error {
	//func TestICMPv6RA(t *testing.T) {
	teid := uint32(2)

	packet := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := serializeFixture(packet, opts,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 10},
			DstMAC:       net.HardwareAddr{1, 0, 0, 3, 0, 20},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			TTL:      64,
			DstIP:    net.IP{10, 3, 0, 10},
			SrcIP:    net.IP{10, 3, 0, 20},
			Protocol: layers.IPProtocolUDP,
			IHL:      5,
		},
		&layers.UDP{
			DstPort: 2152,
			SrcPort: 2152,
		},
		&layers.GTPv1U{
			Version:        1,
			MessageType:    255, // GTPU_G_PDU
			TEID:           teid,
			SequenceNumber: 0,
		},
		&layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   255,
			SrcIP:      net.ParseIP("fe80::1:0:8e11:2f19"),
			DstIP:      net.ParseIP("ff02::2"),
		},
		&layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0),
			//TypeCode: layers.ICMPv6TypeRouterSolicitation,
			Checksum: 0x268c,
		},
		&layers.ICMPv6RouterSolicitation{
			Options: []layers.ICMPv6Option{{Type: 1, Data: []byte{0x37, 0xb4, 0x18, 0x81, 0x48, 0x41}}},
		},
	); err != nil {
		return fmt.Errorf("serializing input packet failed: %w", err)
	}

	pdrUplink := PdrInfo{ReturnFarID: 1, ReturnQerIDs: []uint32{1}, OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 2, QerIDs: []uint32{1}}
	farUplink := FarInfo{Action: 2, OuterHeaderCreation: 0}

	pdr := PdrInfo{OuterHeaderRemovalPresent: true, OuterHeaderRemoval: 0, FarId: 1, QerIDs: []uint32{1}}
	farForward := IpEntrypointFarInfo{
		Action:                2,
		OuterHeaderCreation:   1,
		Remoteip:              binary.LittleEndian.Uint32(net.ParseIP("10.3.0.30").To4()),
		Teid:                  teid,
		TransportLevelMarking: 0}
	qer := IpEntrypointQerInfo{UlGateStatus: 0, DlGateStatus: 0, QfiPresent: 1, Qfi: 5, UlMaximumBitrate: 1000000, DlMaximumBitrate: 100000, UlStart: 0, DlStart: 0}

	if err := bpfObjects.FarMap.Put(uint32(1), &farForward); err != nil {
		return fmt.Errorf("can't set FAR: %w", err)
	}
	if err := bpfObjects.QerMap.Put(uint32(1), &qer); err != nil {
		return fmt.Errorf("can't set QER: %w", err)
	}
	if err := bpfObjects.PutPdrDownlink(net.ParseIP("fe80::1:0:8e11:2f19"), pdr); err != nil {
		return fmt.Errorf("can't set downlink PDR: %w", err)
	}

	if err := bpfObjects.UpdateFar(2, farUplink); err != nil {
		return fmt.Errorf("can't set uplink FAR: %w", err)
	}
	if err := bpfObjects.PutPdrUplink(teid, pdrUplink); err != nil {
		return fmt.Errorf("can't set uplink PDR: %w", err)
	}

	bpfRet, bufOut, err := bpfObjects.UpfIpEntrypointFunc.Test(append(packet.Bytes(), 0x00, 0x00, 0x00, 0x00))
	if err != nil {
		return fmt.Errorf("ebpf run failed: %w", err)
	}

	if bpfRet != 4 { // XDP_REDIRECT
		return fmt.Errorf("unexpected return value: %d", bpfRet)
	}
	response := gopacket.NewPacket(bufOut, layers.LayerTypeEthernet, gopacket.Default)
	t.Logf("decoded packet:\n%v", response)

	if icmpLayer := response.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv6)
		ip, ok := response.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if !ok || !ip.DstIP.Equal(net.ParseIP("fe80::1:0:8e11:2f19")) || ip.HopLimit != 255 {
			return fmt.Errorf("invalid RA IPv6 envelope")
		}
		body := append(append([]byte(nil), icmp.Contents...), icmp.Payload...)
		pseudo := append(append([]byte(nil), ip.SrcIP.To16()...), ip.DstIP.To16()...)
		pseudo = append(pseudo, 0, 0, 0, byte(len(body)), 0, 0, 0, 58)
		if checksumDatapath(append(pseudo, body...)) != 0 {
			return fmt.Errorf("invalid RA checksum")
		}
	} else {
		return fmt.Errorf("unexpected response: %v", response)
	}

	if raLayer := response.Layer(layers.LayerTypeICMPv6RouterAdvertisement); raLayer != nil {
		ra, _ := raLayer.(*layers.ICMPv6RouterAdvertisement)

		if len(ra.Options) != 1 {
			return fmt.Errorf("unexpected icmpv6 options: %v", ra.Options)
		}

	} else {
		return fmt.Errorf("unexpected response: %v", response)
	}

	return nil
}

func TestEntrypoint(t *testing.T) {

	if err := IncreaseResourceLimits(); err != nil {
		t.Fatalf("Can't increase resource limits: %s", err.Error())
	}

	bpfObjects := NewBpfObjects()

	if err := bpfObjects.Load(); err != nil {
		t.Fatalf("Loading bpf objects failed: %s", err.Error())
	}

	defer func() { _ = bpfObjects.Close() }()

	entrypointConfig := IpEntrypointDataplaneConfig{
		N3Ipv4Address:     binary.LittleEndian.Uint32(n3IP.To4()),
		N9Ipv4Address:     binary.LittleEndian.Uint32(n9IP.To4()),
		Ip6RaSupport:      1,
		Ip6RaPrefixLength: 64,
	}
	copy(entrypointConfig.Ip6RaPrefix[:], IPv6Prefix.To16())

	if err := bpfObjects.GlobalConfig.Set(entrypointConfig); err != nil {
		t.Fatalf("scan't set dataplane global config: %s", err.Error())
	}

	t.Run("Arp test", func(t *testing.T) {
		err := testArp(bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("GTP-U Echo test", func(t *testing.T) {
		err := testGtpEcho(t, bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("SDF filter test", func(t *testing.T) {
		err := testGtpWithSDFFilter(bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("SDF filter IPv4 test for IPv6", func(t *testing.T) {
		err := testGtpIPv4WithSDFFilterV6(bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("SDF filter IPv6 test for IPv6", func(t *testing.T) {
		err := testGtpWithSDFFilterV6(bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("SDF filter with notification", func(t *testing.T) {
		err := testGtpWithSDFFilterNotification(bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("GTP Extension Header test", func(t *testing.T) {
		err := testGtpExtHeader(t, bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("GTP-U with sequence field test", func(t *testing.T) {
		err := testGtpHeaderWithSequence(t, bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("DL packet with UDP port 2152 test", func(t *testing.T) {
		err := testDLwithGTPPort(t, bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

	t.Run("IMCPv6 Router Solicitation-Advirtesment test", func(t *testing.T) {
		err := testICMPv6RA(t, bpfObjects)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}
	})

}

func TestEntrypointBenchmark(t *testing.T) {

	if err := IncreaseResourceLimits(); err != nil {
		t.Fatalf("Can't increase resource limits: %s", err.Error())
	}

	bpfObjects := NewBpfObjects()

	if err := bpfObjects.Load(); err != nil {
		t.Fatalf("Loading bpf objects failed: %s", err.Error())
	}

	defer func() { _ = bpfObjects.Close() }()

	t.Run("Arp (x1)) benchmark", func(t *testing.T) {
		duration, err := testArpBenchmark(bpfObjects, 1)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})

	t.Run("Arp (x1000000) benchmark", func(t *testing.T) {
		duration, err := testArpBenchmark(bpfObjects, 1000000)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})

	t.Run("Gtp (x1)) benchmark", func(t *testing.T) {
		duration, err := testGtpBenchmark(bpfObjects, 1)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})

	t.Run("Gtp (x1000000) benchmark", func(t *testing.T) {
		duration, err := testGtpBenchmark(bpfObjects, 1000000)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})

	t.Run("Gtp with PDR (x1)) benchmark", func(t *testing.T) {
		duration, err := testGtpWithPDRBenchmark(bpfObjects, 1)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})

	t.Run("Gtp with PDR (x1000000) benchmark", func(t *testing.T) {
		duration, err := testGtpWithPDRBenchmark(bpfObjects, 1000000)
		if err != nil {
			t.Fatalf("test failed: %s", err)
		}

		t.Logf("%s result: %d ns", t.Name(), duration)
	})
}

// serializeFixture binds each transport checksum to its enclosing network
// layer, including packets nested in GTP. All positive vectors are valid IP.
func serializeFixture(buffer gopacket.SerializeBuffer, opts gopacket.SerializeOptions, ls ...gopacket.SerializableLayer) error {
	opts.FixLengths, opts.ComputeChecksums = true, true
	var network gopacket.NetworkLayer
	for _, layer := range ls {
		if n, ok := layer.(gopacket.NetworkLayer); ok {
			network = n
		}
		if c, ok := layer.(interface {
			SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
		}); ok {
			if err := c.SetNetworkLayerForChecksum(network); err != nil {
				return err
			}
		}
	}
	return gopacket.SerializeLayers(buffer, opts, ls...)
}

//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/cilium/ebpf/perf"
)

func FuzzSdfRecord(f *testing.F) {
	for _, n := range []int{0, 1, 5, 6, 18, 19, 42, 43} {
		for _, cookie := range []uint16{0x1ea1, 0x2ea2} {
			seed := make([]byte, n)
			if n >= 2 {
				binary.LittleEndian.PutUint16(seed, cookie)
			}
			f.Add(seed)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		event, err := parseSdfRecord(&perf.Record{RawSample: raw})
		if err == nil && event.SDFFilter == "" {
			t.Fatal("accepted an empty tuple")
		}
	})
}

func FuzzDatapathPacket(f *testing.F) {
	if err := IncreaseResourceLimits(); err != nil {
		f.Fatal(err)
	}
	b := NewBpfObjects()
	if err := b.Load(); err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() {
		if err := b.Close(); err != nil {
			f.Error(err)
		}
	})
	cfg := IpEntrypointDataplaneConfig{N3Ipv4Address: binary.LittleEndian.Uint32(net.IP{192, 0, 2, 1})}
	if err := b.GlobalConfig.Set(cfg); err != nil {
		f.Fatal(err)
	}
	far := IpEntrypointFarInfo{Action: 2}
	qer := IpEntrypointQerInfo{}
	if err := b.FarMap.Put(uint32(1), &far); err != nil {
		f.Fatal(err)
	}
	if err := b.QerMap.Put(uint32(1), &qer); err != nil {
		f.Fatal(err)
	}
	activity, err := b.NewSessionActivity()
	if err != nil {
		f.Fatal(err)
	}
	if err := b.PutPdrUplink(10, PdrInfo{ActivitySlot: activity, FarId: 1, QerIDs: []uint32{1}, UrrIDs: []uint32{1}}); err != nil {
		f.Fatal(err)
	}
	// Synthetic Ethernet / IPv4 / UDP / GTP / IPv4 / UDP, with a 32-byte T-PDU.
	seed := make([]byte, 82)
	seed[12], seed[13] = 8, 0
	ip := seed[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], 68)
	copy(ip[12:16], net.IP{192, 0, 2, 2})
	copy(ip[16:20], net.IP{192, 0, 2, 1})
	binary.BigEndian.PutUint16(ip[10:12], checksumDatapath(ip))
	udp := seed[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 2152)
	binary.BigEndian.PutUint16(udp[2:4], 2152)
	binary.BigEndian.PutUint16(udp[4:6], 48)
	g := seed[42:50]
	g[0], g[1] = 0x30, 255
	binary.BigEndian.PutUint16(g[2:4], 32)
	binary.BigEndian.PutUint32(g[4:8], 10)
	inner := seed[50:70]
	inner[0], inner[8], inner[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(inner[2:4], 32)
	copy(inner[12:16], net.IP{198, 51, 100, 1})
	copy(inner[16:20], net.IP{198, 51, 100, 2})
	binary.BigEndian.PutUint16(inner[10:12], checksumDatapath(inner))
	binary.BigEndian.PutUint16(seed[70:72], 1234)
	binary.BigEndian.PutUint16(seed[72:74], 4321)
	binary.BigEndian.PutUint16(seed[74:76], 12)
	f.Add(seed)
	f.Add(seed[:34])
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, packet []byte) {
		// BPF_PROG_TEST_RUN's Ethernet input contract bounds this harness.
		if len(packet) < 14 || len(packet) > 65535 {
			return
		}
		action, _, err := b.UpfIpEntrypointFunc.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		if action > 4 {
			t.Fatalf("internal packet transition escaped XDP: %d", action)
		}
	})
}

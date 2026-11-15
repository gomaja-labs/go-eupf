package core

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestSendPathAddressConstructorsMatchTheirFamilies(t *testing.T) {
	// TS 29.244 V20.1.0 clauses 8.2.3, 8.2.37, 8.2.38 and 8.2.62.
	for _, address := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		conn := &PfcpConnection{nodeAddrV4: netip.AddrPortFrom(netip.MustParseAddr(address), 8805)}
		value := conn.localFSEID(42)
		if _, err := value.Marshal(); err != nil {
			t.Fatalf("F-SEID %s: %v", address, err)
		}
		fields, err := value.FSEID()
		if err != nil {
			t.Fatal(err)
		}
		wantIPv4 := net.ParseIP(address).To4() != nil
		if (fields.Flags&2 != 0) != wantIPv4 || (fields.Flags&1 != 0) == wantIPv4 {
			t.Fatalf("F-SEID family %s flags=%d", address, fields.Flags)
		}
		for _, profile := range []PfcpProfile{DefaultProfile{}, testHuaweiProfile} {
			if _, err := profile.NodeID(address).Marshal(); err != nil {
				t.Fatalf("Node ID %s: %v", address, err)
			}
			for _, extra := range profile.SessionEstablishmentResponseAdditionalIEs(42, net.ParseIP(address)) {
				if _, err := extra.Marshal(); err != nil {
					t.Fatalf("profile address: %v", err)
				}
			}
		}
	}
	for _, source := range []uint8{ie.SrcInterfaceAccess, ie.SrcInterfaceCore} {
		pdr := SPDRInfo{PdrID: 9, SourceInterface: source, Teid: 10, AllocatedTEID: true, AllocatedUEIP: true, Ipv4: net.ParseIP("198.51.100.1"), Ipv6: net.ParseIP("2001:db8::2")}
		for _, value := range allocatedPDRChildren(pdr, net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")) {
			if _, err := value.Marshal(); err != nil {
				t.Fatalf("allocated resource IE %d: %v", value.Type, err)
			}
			if value.Type == ie.FTEID {
				fields, err := value.FTEID()
				if err != nil || fields.Flags != 1 || fields.IPv4Address.To4() == nil || fields.IPv6Address != nil {
					t.Fatalf("F-TEID family %+v error=%v", fields, err)
				}
			}
		}
	}
}

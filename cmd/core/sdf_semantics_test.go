package core

import (
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestAssignedSDFParses(t *testing.T) {
	for _, description := range []string{"permit out ip from any to assigned", "permit out 17 from 198.51.100.0/24 1000-2000 to assigned"} {
		if _, err := ParseSdfFilter(description); err != nil {
			t.Errorf("%s: %v", description, err)
		}
	}
}

func TestMalformedOptionalSDFFilterIsIgnored(t *testing.T) {
	s := NewSession(9, 42, "", "", false)
	ctx := NewPDRCreationContext(s, nil)
	for _, description := range []string{"invalid", "permit out udp from 192.0.2.1/99 to any", "permit out udp from any 2000-1000 to any"} {
		info := SPDRInfo{PdrID: 1}
		request := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.2", "", 0, 0), ie.NewSDFFilter(description, nil, nil, nil, 0)))
		if err := ctx.extractPDR(request, &info); err != nil {
			t.Errorf("malformed optional filter rejected: %s: %v", description, err)
		}
		if len(info.PdrInfo.SdfFilter) != 0 {
			t.Errorf("malformed filter retained: %s", description)
		}
	}
}

func TestOptionalSDFOptionIsIgnored(t *testing.T) {
	s := NewSession(9, 42, "", "", false)
	ctx := NewPDRCreationContext(s, nil)
	info := SPDRInfo{PdrID: 1}
	request := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.2", "", 0, 0), ie.NewSDFFilter("permit out tcp from any to any established", nil, nil, nil, 0)))
	if err := ctx.extractPDR(request, &info); err != nil {
		t.Fatalf("semantically incorrect optional filter must be ignored: %v", err)
	}
	if len(info.PdrInfo.SdfFilter) != 0 {
		t.Fatal("prohibited option retained")
	}
}

func FuzzSdfFlowDescription(f *testing.F) {
	for _, seed := range []string{
		"", "invalid", "permit out ip from any to assigned", "permit out ip from ::ffff:192.0.2.10/128 to any",
		"permit out 17 from 198.51.100.0/24 1000-2000 to assigned",
		"permit in udp from assigned to 2001:db8::/64 53",
		"permit out udp from 192.0.2.1/99 to any",
		"permit out udp from any 2000-1000 to any",
		"deny out ip from !192.0.2.1 to any", "permit out 132 from any to any",
		"permit out tcp from any to any established",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, description string) {
		filter, err := ParseSdfFilter(description)
		if err != nil {
			return
		}
		if filter.Protocol > ebpf.SDFProtocolAny || filter.SrcPortRange.LowerBound > filter.SrcPortRange.UpperBound || filter.DstPortRange.LowerBound > filter.DstPortRange.UpperBound {
			t.Fatal("accepted a classifier tuple outside its representable bounds")
		}
		for _, address := range []ebpf.IpWMask{filter.SrcAddress, filter.DstAddress} {
			switch address.Type {
			case 0, 3:
			case 1:
				_, bits := address.Mask.Size()
				if address.Ip.To4() == nil || bits != 32 {
					t.Fatal("accepted an invalid IPv4 constraint")
				}
			case 2:
				_, bits := address.Mask.Size()
				if len(address.Ip) != 16 || bits != 128 {
					t.Fatal("accepted an invalid IPv6 constraint")
				}
			default:
				t.Fatal("accepted an unknown address kind")
			}
		}
	})
}

package core

import (
	"net"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestPDIUpdateReplacesEveryMatchField(t *testing.T) {
	session := NewSession(9, 42, "", "", false)
	context := NewPDRCreationContext(session, nil)
	info := SPDRInfo{PdrID: 1, Teid: 9, Ipv4: net.ParseIP("192.0.2.1"), NetworkInstance: "old", PdrInfo: ebpf.PdrInfo{UEIPv4: net.ParseIP("192.0.2.1"), QFIs: []uint8{9}}}
	err := context.extractPDR(ie.NewUpdatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.2", "", 0, 0))), &info)
	if err != nil {
		t.Fatal(err)
	}
	if info.Teid != 0 || info.NetworkInstance != "" || len(info.PdrInfo.QFIs) != 0 {
		t.Fatalf("old PDI survived replacement: %+v", info)
	}
	if !info.Ipv4.Equal(net.ParseIP("192.0.2.2")) {
		t.Fatal(info.Ipv4)
	}
}

func TestUplinkSDFReversesDownlinkDescription(t *testing.T) {
	s := NewSession(9, 42, "", "", false)
	context := NewPDRCreationContext(s, nil)
	context.Restoration = true
	info := SPDRInfo{PdrID: 1}
	request := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceAccess), ie.NewFTEID(1, 10, net.ParseIP("192.0.2.1"), nil, 0), ie.NewUEIPAddress(2, "10.0.0.1", "", 0, 0), ie.NewSDFFilter("permit out udp from 1.1.1.1 53 to 10.0.0.1 1234", nil, nil, nil, 0)))
	if err := context.extractPDR(request, &info); err != nil {
		t.Fatal(err)
	}
	f := info.PdrInfo.SdfFilter[0]
	if !f.SrcAddress.Ip.Equal(net.ParseIP("10.0.0.1")) || !f.DstAddress.Ip.Equal(net.ParseIP("1.1.1.1")) || f.SrcPortRange.LowerBound != 1234 || f.DstPortRange.LowerBound != 53 {
		t.Fatalf("incorrect uplink filter: %+v", f)
	}
}

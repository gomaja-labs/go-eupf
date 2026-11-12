package core

import (
	"errors"
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

func TestValidUnsupportedSDFFilterIsRejected(t *testing.T) {
	s := NewSession(9, 42, "", "", false)
	ctx := NewPDRCreationContext(s, nil)
	info := SPDRInfo{PdrID: 1}
	request := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.2", "", 0, 0), ie.NewSDFFilter("permit out 132 from any to any", nil, nil, nil, 0)))
	if err := ctx.extractPDR(request, &info); !errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
		t.Fatalf("unsupported filter must reject: %v", err)
	}
}

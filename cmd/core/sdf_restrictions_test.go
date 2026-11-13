package core

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestFlowDescriptionDeparturesAreAbsent(t *testing.T) {
	descriptions := []string{
		"deny out ip from any to assigned", "permit in ip from any to assigned",
		"permit out ip from !192.0.2.1 to assigned", "permit out ip from assigned to assigned",
		"permit out ip from any to any", "permit out tcp from any 1,2 to assigned",
		"permit out tcp from any to assigned 1,2", "permit out tcp from any to assigned established",
		"permit out tcp from any to assigned setup", "permit out ip from any to assigned frag",
		"permit out tcp from any to assigned tcpflags syn", "permit out ip from any to assigned ipoptions rr",
		"permit out tcp from any to assigned tcpoptions mss", "permit out icmp from any to assigned icmptypes 8",
		"permit out unknownprotocol from any to assigned",
	}
	for _, description := range descriptions {
		t.Run(description, func(t *testing.T) {
			if _, err := ParseSdfFilter(description); err == nil {
				t.Error("accepted a TS 29.212 clause 5.4.2 departure")
			}
			before := ignoredSDFCount(t)
			session := NewSession(9, 42, "", "", false)
			ctx := NewPDRCreationContext(session, nil)
			info := SPDRInfo{PdrID: 1}
			pdr := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewUEIPAddress(6, "192.0.2.2", "", 0, 0), ie.NewSDFFilter(description, nil, nil, nil, 0)))
			if err := ctx.extractPDR(pdr, &info); err != nil {
				t.Fatalf("semantically incorrect optional SDF rejected the request: %v", err)
			}
			if len(info.PdrInfo.SdfFilter) != 0 {
				t.Fatal("semantically incorrect SDF retained")
			}
			if got := ignoredSDFCount(t) - before; got != 1 {
				t.Fatalf("ignored %g filters, want exactly one", got)
			}
		})
	}
}
func TestFlowDescriptionPortsOnOpaqueProtocolsParse(t *testing.T) {
	for _, protocol := range []string{"ip", "0", "1", "47", "50", "58", "253", "255"} {
		filter, err := ParseSdfFilter("permit out " + protocol + " from any 0-65535 to assigned 65535")
		if err != nil || !filter.PortsPresent {
			t.Errorf("non-port predicate must be representable: protocol=%s filter=%+v error=%v", protocol, filter, err)
		}
	}
}

func ignoredSDFCount(t *testing.T) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "upf_ignored_sdf_filters_total" {
			return family.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatal("ignored SDF counter is missing")
	return 0
}

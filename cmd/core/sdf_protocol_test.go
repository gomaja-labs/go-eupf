package core

import (
	"errors"
	"strconv"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestSDFEveryIPProtocolNumber(t *testing.T) {
	for n := 0; n < 256; n++ {
		got, err := ParseProtocol(strconv.Itoa(n))
		if err != nil || int(got) != n {
			t.Errorf("protocol %d: got %d, %v", n, got, err)
		}
	}
	for name, want := range map[string]int{"sctp": 132, "gre": 47, "esp": 50, "tcp": 6, "udp": 17, "icmp": 1, "ipv6-icmp": 58} {
		got, err := ParseProtocol(name)
		if err != nil || int(got) != want {
			t.Errorf("protocol %s: got %d, %v", name, got, err)
		}
	}
}

func TestSDFRestrictedGrammarRejectsOptions(t *testing.T) {
	for _, suffix := range []string{"frag", "ipoptions ssrr,!lsrr,rr,ts", "tcpoptions mss,!window,sack,ts,cc", "established", "setup", "tcpflags syn,!ack", "icmptypes 0,8,255", "icmptypes echo reply,destination unreachable", "icmptypes echoreply,echo,maskreq"} {
		_, err := ParseSdfFilter("permit out tcp from !192.0.2.10/24 1,2-3 to assigned 0-65535 " + suffix)
		if err == nil || errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
			t.Errorf("prohibited option %q was not semantically incorrect: %v", suffix, err)
		}
	}
	for _, description := range []string{"permit out 132 from any 80 to assigned 100-200", "permit out gre from any to assigned", "permit out esp from any to assigned"} {
		if _, err := ParseSdfFilter(description); err != nil {
			t.Errorf("supported description %q: %v", description, err)
		}
	}
}

func TestSDFIPv6MappedLiteralKeepsIPv6Mask(t *testing.T) {
	for _, address := range []string{"::ffff:192.0.2.10/128", "::ffff:192.0.2.10/120"} {
		filter, err := ParseSdfFilter("permit out ip from " + address + " to assigned")
		if err != nil {
			t.Fatalf("valid IPv6 SDF became absent: %s: %v", address, err)
		}
		if filter.SrcAddress.Type != 2 || len(filter.SrcAddress.Ip) != 16 {
			t.Fatalf("IPv6 literal changed family: %+v", filter.SrcAddress)
		}
	}
}

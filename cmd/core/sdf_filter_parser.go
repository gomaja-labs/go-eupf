// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

// ParseSdfFilter parses the IPFilterRule tuple and distinguishes invalid syntax
// from valid rules outside the supported packet classifier. RFC 6733 section
// 4.3.1 defines assigned, address negation, port lists and filter options.
func ParseSdfFilter(description string) (ebpf.SdfFilter, error) {
	fields := strings.Fields(description)
	bad := func() (ebpf.SdfFilter, error) { return ebpf.SdfFilter{}, fmt.Errorf("invalid SDF Flow Description") }
	if len(fields) < 7 || (fields[0] != "permit" && fields[0] != "deny") || (fields[1] != "out" && fields[1] != "in") || fields[3] != "from" {
		return bad()
	}
	unsupported := fields[0] == "deny"
	filter := ebpf.SdfFilter{Direction: fields[1]}
	var err error
	if filter.Protocol, err = ParseProtocol(fields[2]); err != nil {
		if !errors.Is(err, ebpf.ErrUnsupportedRuleContent) {
			return bad()
		}
		unsupported = true
	}
	index := 4
	endpoint := func() (ebpf.IpWMask, ebpf.PortRange, error) {
		ports := ebpf.PortRange{LowerBound: 0, UpperBound: 65535}
		if index >= len(fields) {
			return ebpf.IpWMask{}, ports, fmt.Errorf("missing SDF address")
		}
		token := fields[index]
		index++
		if strings.HasPrefix(token, "!") {
			unsupported = true
			token = strings.TrimPrefix(token, "!")
		}
		address := ebpf.IpWMask{}
		switch token {
		case "any":
		case "assigned":
			address.Type = 3
		default:
			pieces := strings.Split(token, "/")
			if len(pieces) > 2 {
				return address, ports, fmt.Errorf("invalid SDF address")
			}
			mask := ""
			if len(pieces) == 2 {
				mask = pieces[1]
				if mask == "" {
					return address, ports, fmt.Errorf("empty SDF mask")
				}
			}
			var e error
			address, e = ParseCidrIp(pieces[0], mask)
			if e != nil {
				return address, ports, e
			}
		}
		if index < len(fields) && len(fields[index]) > 0 && fields[index][0] >= '0' && fields[index][0] <= '9' {
			filter.PortsPresent = true
			parts := strings.Split(fields[index], ",")
			index++
			for n, part := range parts {
				parsed, e := ParsePortRange(part)
				if e != nil {
					return address, ports, e
				}
				if n == 0 {
					ports = parsed
				}
			}
			if len(parts) > 1 {
				unsupported = true
			}
		}
		return address, ports, nil
	}
	filter.SrcAddress, filter.SrcPortRange, err = endpoint()
	if err != nil {
		return bad()
	}
	if index >= len(fields) || fields[index] != "to" {
		return bad()
	}
	index++
	filter.DstAddress, filter.DstPortRange, err = endpoint()
	if err != nil {
		return bad()
	}
	for index < len(fields) {
		option := fields[index]
		index++
		switch option {
		case "frag", "established", "setup":
		case "ipoptions", "tcpoptions", "tcpflags", "icmptypes":
			if index >= len(fields) {
				return bad()
			}
			argument := fields[index]
			index++
			if option == "icmptypes" {
				for index < len(fields) && !isSDFOption(fields[index]) {
					argument += " " + fields[index]
					index++
				}
			}
			if !validSDFOption(option, argument) {
				return bad()
			}
		default:
			return bad()
		}
		unsupported = true
	}
	// RFC 6733 section 4.3.1 defines ports for TCP, UDP and SCTP only.
	if filter.PortsPresent && filter.Protocol != 6 && filter.Protocol != 17 && filter.Protocol != 132 {
		unsupported = true
	}
	if unsupported {
		return ebpf.SdfFilter{}, fmt.Errorf("SDF Flow Description requires an unsupported classifier: %w", ebpf.ErrUnsupportedRuleContent)
	}
	return filter, nil
}

func validSDFOption(option, argument string) bool {
	names := map[string]string{"ipoptions": ",ssrr,lsrr,rr,ts,", "tcpoptions": ",mss,window,sack,ts,cc,", "tcpflags": ",fin,syn,rst,psh,ack,urg,"}
	for _, part := range strings.Split(argument, ",") {
		if option == "icmptypes" {
			ports, err := ParsePortRange(part)
			if (err != nil || ports.UpperBound > 255) && !validICMPTypeName(part) {
				return false
			}
		} else if part == "" || !strings.Contains(names[option], ","+strings.TrimPrefix(part, "!")+",") {
			return false
		}
	}
	return true
}

// protocolNames is immutable after first use. Read the deployment's protocol
// database once, as required for locally configured IPFilterRule names.
var protocolNames = sync.OnceValue(func() map[string]uint16 {
	names := map[string]uint16{"icmp": 1, "tcp": 6, "udp": 17, "icmp6": 58, "ipv6-icmp": 58, "sctp": 132, "gre": 47, "esp": 50}
	file, err := os.Open("/etc/protocols")
	if err != nil {
		return names
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		number, err := strconv.ParseUint(fields[1], 10, 8)
		if err != nil {
			continue
		}
		names[strings.ToLower(fields[0])] = uint16(number)
		for _, alias := range fields[2:] {
			names[strings.ToLower(alias)] = uint16(number)
		}
	}
	return names
})

// ParseProtocol returns an IP protocol number, or SDFProtocolAny for "ip".
// RFC 6733 section 4.3.1 permits the complete eight-bit protocol space.
func ParseProtocol(protocol string) (uint16, error) {
	if protocol == "ip" {
		return ebpf.SDFProtocolAny, nil
	}
	if len(protocol) > 0 && protocol[0] >= '0' && protocol[0] <= '9' {
		number, err := strconv.ParseUint(protocol, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid SDF protocol: %w", err)
		}
		return uint16(number), nil
	}
	if number, ok := protocolNames()[strings.ToLower(protocol)]; ok {
		return number, nil
	}
	for i, c := range protocol {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_')) {
			return 0, fmt.Errorf("invalid SDF protocol name")
		}
	}
	if protocol == "" {
		return 0, fmt.Errorf("empty SDF protocol")
	}
	// A syntactically valid name unknown on this host must never silently
	// discard an optional SDF and widen its PDR.
	return 0, fmt.Errorf("unknown SDF protocol name %s: %w", protocol, ebpf.ErrUnsupportedRuleContent)
}

func ParseCidrIp(ipStr, maskStr string) (ebpf.IpWMask, error) {
	var ipType uint8
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip.To4() != nil {
			ipType = 1
			ip = ip.To4()
		} else {
			ipType = 2
		}
		mask := net.CIDRMask(8*len(ip), 8*len(ip))
		if maskStr != "" {
			if maskUint, err := strconv.ParseUint(maskStr, 10, 64); err == nil {
				if maskUint > uint64(8*len(ip)) {
					return ebpf.IpWMask{}, fmt.Errorf("IP mask is out of range")
				}
				mask = net.CIDRMask(int(maskUint), 8*len(ip))
				ip = ip.Mask(mask)
			} else {
				return ebpf.IpWMask{}, fmt.Errorf("bad IP mask formatting")
			}
		}
		return ebpf.IpWMask{
			Type: ipType,
			Ip:   ip,
			Mask: mask,
		}, nil
	} else {
		return ebpf.IpWMask{}, fmt.Errorf("bad IP formatting")
	}
}

func ParsePortRange(str string) (ebpf.PortRange, error) {
	re := regexp.MustCompile(`^(\d+)(?:-(\d+))?$`)
	match := re.FindStringSubmatch(str)
	if match == nil {
		return ebpf.PortRange{}, fmt.Errorf("bad port range formatting")
	}
	portRange := ebpf.PortRange{}
	var err error
	if portRange.LowerBound, err = ParsePort(match[1]); err != nil {
		return ebpf.PortRange{}, err
	}
	if match[2] != "" {
		if portRange.UpperBound, err = ParsePort(match[2]); err != nil {
			return ebpf.PortRange{}, err
		}
	} else {
		portRange.UpperBound = portRange.LowerBound
	}
	if portRange.LowerBound > portRange.UpperBound {
		return ebpf.PortRange{}, fmt.Errorf("invalid port range: left port should be less or equal to right port")
	}
	return portRange, nil
}

func ParsePort(str string) (uint16, error) {
	if port64, err := strconv.ParseUint(str, 10, 64); err == nil {
		if port64 > 65535 {
			return 0, fmt.Errorf("invalid port: port must be inside bounds [0, 65535]")
		}
		return uint16(port64), nil
	} else {
		return 0, err
	}
}

// RFC 6733 section 4.3.1 also permits symbolic ICMP type names.
func validICMPTypeName(name string) bool {
	name = strings.NewReplacer(" ", "", "-", "").Replace(name)
	switch name {
	case "echoreply", "unreach", "quench", "redirect", "echo", "routeradv", "routersol", "timex", "paramprob", "tstamp", "tstampreply", "ireq", "ireqreply", "maskreq", "maskreply", "destinationunreachable", "sourcequench", "echorequest", "routeradvertisement", "routersolicitation", "timetoliveexceeded", "ipheaderbad", "timestamprequest", "timestampreply", "informationrequest", "informationreply", "addressmaskrequest", "addressmaskreply":
		return true
	}
	return false
}

func isSDFOption(s string) bool {
	switch s {
	case "frag", "ipoptions", "tcpoptions", "established", "setup", "tcpflags", "icmptypes":
		return true
	}
	return false
}

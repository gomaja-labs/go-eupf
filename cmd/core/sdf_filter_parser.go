// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

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
			if !validSDFOption(option, argument) {
				return bad()
			}
		default:
			return bad()
		}
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
			if err != nil || ports.UpperBound > 255 {
				return false
			}
		} else if part == "" || !strings.Contains(names[option], ","+strings.TrimPrefix(part, "!")+",") {
			return false
		}
	}
	return true
}

func ParseProtocol(protocol string) (uint8, error) {
	if len(protocol) > 0 && protocol[0] >= '0' && protocol[0] <= '9' {
		if _, err := strconv.ParseUint(protocol, 10, 8); err != nil {
			return 0, fmt.Errorf("invalid SDF protocol: %w", err)
		}
	} else if protocol != "icmp" && protocol != "icmp6" && protocol != "ip" && protocol != "tcp" && protocol != "udp" {
		return 0, fmt.Errorf("invalid SDF protocol name")
	}

	switch protocol {
	case "58":
		protocol = "icmp6"
	case "1":
		protocol = "icmp"
	case "17":
		protocol = "udp"
	case "6":
		protocol = "tcp"
	}

	protocolMap := map[string]uint8{
		"icmp":  0,
		"ip":    1,
		"tcp":   2,
		"udp":   3,
		"icmp6": 4,
	}
	number, ok := protocolMap[protocol]
	if ok {
		return number, nil
	} else {
		return 0, fmt.Errorf("SDF filter protocol %s: %w", protocol, ebpf.ErrUnsupportedRuleContent)
	}
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

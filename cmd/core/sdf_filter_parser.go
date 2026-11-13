// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

// ParseSdfFilter parses TS 29.212 V20.0.0 clause 5.4.2, referenced by
// TS 29.244 V20.1.0 clause 8.2.5. RFC 6733 section 4.3.1 supplies the
// encoding; 3GPP restricts it to permit/out, one port or range, and no options.
// Every departure is semantically incorrect, so the caller ignores that
// optional SDF Filter under TS 29.244 clause 7.6.8.
func ParseSdfFilter(description string) (ebpf.SdfFilter, error) {
	bad := func() (ebpf.SdfFilter, error) {
		return ebpf.SdfFilter{}, fmt.Errorf("invalid SDF Flow Description under TS 29.212 clause 5.4.2")
	}
	for _, c := range description {
		if c > 127 {
			return bad()
		}
	}
	fields := strings.Fields(description)
	if len(fields) < 7 || len(fields) > 9 || fields[0] != "permit" || fields[1] != "out" || fields[3] != "from" {
		return bad()
	}
	filter := ebpf.SdfFilter{Direction: "out"}
	var err error
	filter.Protocol, err = ParseProtocol(fields[2])
	if err != nil {
		return bad()
	}
	index := 4
	endpoint := func(source bool) (ebpf.IpWMask, ebpf.PortRange, error) {
		ports := ebpf.PortRange{LowerBound: 0, UpperBound: 65535}
		if index >= len(fields) {
			return ebpf.IpWMask{}, ports, fmt.Errorf("missing SDF address")
		}
		token := fields[index]
		index++
		var address ebpf.IpWMask
		if source && token == "any" {
		} else if !source && token == "assigned" {
			address.Type = 3
		} else {
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
			address, err = ParseCidrIp(pieces[0], mask)
			if err != nil {
				return address, ports, err
			}
		}
		if index < len(fields) && fields[index] != "to" {
			ports, err = ParsePortRange(fields[index])
			if err != nil {
				return address, ports, err
			}
			filter.PortsPresent = true
			index++
		}
		return address, ports, nil
	}
	filter.SrcAddress, filter.SrcPortRange, err = endpoint(true)
	if err != nil {
		return bad()
	}
	if index >= len(fields) || fields[index] != "to" {
		return bad()
	}
	index++
	filter.DstAddress, filter.DstPortRange, err = endpoint(false)
	if err != nil || index != len(fields) {
		return bad()
	}
	// Explicit ports on an opaque protocol remain a predicate that matches no
	// packet: the packet classifier requires actual TCP/UDP/SCTP ports.
	return filter, nil
}

// protocolNames is immutable after first use. Read the deployment's protocol
// database once, as required for locally configured IPFilterRule names.
var protocolNames = sync.OnceValue(func() map[string]uint16 {
	names := map[string]uint16{"icmp": 1, "tcp": 6, "udp": 17, "icmp6": 58, "ipv6-icmp": 58, "sctp": 132, "gre": 47, "esp": 50}
	file, err := os.Open("/etc/protocols")
	if err != nil {
		return names
	}
	defer func() { _ = file.Close() }()
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
		allowed := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_')
		if !allowed {
			return 0, fmt.Errorf("invalid SDF protocol name")
		}
	}
	if protocol == "" {
		return 0, fmt.Errorf("empty SDF protocol")
	}
	// Unknown names cannot be encoded as a protocol number. The enclosing
	// optional Flow Description follows TS 29.244 clause 7.6.8.
	return 0, fmt.Errorf("unknown SDF protocol name %s", protocol)
}

func ParseCidrIp(ipStr, maskStr string) (ebpf.IpWMask, error) {
	var ipType uint8
	if ip := net.ParseIP(ipStr); ip != nil {
		if !strings.Contains(ipStr, ":") {
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
				for i := range ip {
					ip[i] &= mask[i]
				}
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

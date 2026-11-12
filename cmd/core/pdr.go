// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"net"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

const flagPresentIPv4 = 2
const flagPresentIPv6 = 1

func applyPDR(info SPDRInfo, maps ebpf.ForwardingPlaneController) error {
	if info.PCCInfo != nil {
		return nil
	}
	if info.Teid > 0 {
		return maps.PutPdrUplink(info.Teid, info.PdrInfo)
	}
	if info.Ipv4 != nil {
		if err := maps.PutPdrDownlink(info.Ipv4, info.PdrInfo); err != nil {
			return err
		}
	}
	if info.Ipv6 != nil {
		return maps.PutDownlinkPdrIp6(info.Ipv6, info.PdrInfo)
	}
	return nil
}

// TS 29.244 V20.1.0 Tables 7.5.3.2-1 and 7.5.5.5-1 require every
// newly allocated resource, including simultaneous F-TEID and UE-IP choices.
func allocatedPDRChildren(pdr SPDRInfo, n3, n9 net.IP) []*ie.IE {
	children := []*ie.IE{ie.NewPDRID(uint16(pdr.PdrID))}
	if pdr.AllocatedTEID {
		address := n3
		if pdr.SourceInterface == ie.SrcInterfaceCore {
			address = n9
		}
		children = append(children, ie.NewFTEID(1, pdr.Teid, cloneIP(address), nil, 0))
	}
	if pdr.AllocatedUEIP {
		if pdr.Ipv4 != nil {
			children = append(children, ie.NewUEIPAddress(flagPresentIPv4, pdr.Ipv4.String(), "", 0, 0))
		}
		if pdr.Ipv6 != nil {
			children = append(children, ie.NewUEIPAddress(flagPresentIPv6, "", pdr.Ipv6.String(), 0, 0))
		}
	}
	return children
}
func processCreatedPDRs(pdrs []SPDRInfo, n3, n9 net.IP) []*ie.IE {
	var result []*ie.IE
	for _, pdr := range pdrs {
		if pdr.AllocatedTEID || pdr.AllocatedUEIP {
			result = append(result, ie.NewCreatedPDR(allocatedPDRChildren(pdr, n3, n9)...))
		}
	}
	return result
}
func processUpdatedPDRs(pdrs []SPDRInfo, n3, n9 net.IP) []*ie.IE {
	var result []*ie.IE
	for _, pdr := range pdrs {
		if pdr.AllocatedTEID || pdr.AllocatedUEIP {
			result = append(result, ie.NewUpdatedPDR(allocatedPDRChildren(pdr, n3, n9)...))
		}
	}
	return result
}

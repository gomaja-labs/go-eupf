// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/rs/zerolog/log"

	"github.com/rs/zerolog"
)

const (
	N4PFCPKeyName  = "n4"
	SxaPFCPKeyName = "Sxa"
	SxbPFCPKeyName = "Sxb"

	GTPPortStr = ":2152"
)

var (
	ErrNilBPFObj         = errors.New("BpfObjects is nil")
	ErrNilGtpPathManager = errors.New("GtpPathManager is nil")
	ErrNilInterface      = errors.New("interface is nil")
	ErrAttachXDP         = errors.New("could not attach XDP program")
	ErrLookupIface       = errors.New("lookup network iface failed")
	ErrCloseOldLink      = errors.New("close old link failed")
	ErrNonePFCPConn      = errors.New("none PFCP connection")
)

func UpdateLogLevel(logLevel string) error {
	if err := SetLoggerLevel(logLevel); err != nil {
		return fmt.Errorf("logger configuring error: %w. Using '%s' level",
			err, zerolog.GlobalLevel().String())
	}

	return nil
}

func UpdateLogCaller(enableCaller bool) {
	SetLoggerCaller(enableCaller)
}

func BindDataPlaneInterfaces(
	bpfObjects *ebpf.BpfObjects,
	links *[]link.Link,
	interfaceNames []string,
	xdpAttachMode string,
) error {
	if bpfObjects == nil {
		log.Error().Msg("can't update InterfaceName: BpfObjects is nil")
		return ErrNilBPFObj
	}

	if links == nil {
		return ErrNilInterface
	}
	desired := make(map[uint32]bool)
	for _, name := range interfaceNames {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrLookupIface, name, err)
		}
		desired[uint32(iface.Index)] = true
	}
	existing := make(map[uint32]link.Link)
	for _, l := range *links {
		info, err := l.Info()
		if err != nil {
			return fmt.Errorf("inspect XDP link: %w", err)
		}
		if info.XDP() == nil {
			return fmt.Errorf("expected an XDP link")
		}
		existing[info.XDP().Ifindex] = l
	}
	var added []link.Link
	for index := range desired {
		if _, ok := existing[index]; ok {
			continue
		}
		l, err := link.AttachXDP(link.XDPOptions{Program: bpfObjects.UpfIpEntrypointFunc, Interface: int(index), Flags: StringToXDPAttachMode(xdpAttachMode)})
		if err != nil {
			var failures []error
			failures = append(failures, fmt.Errorf("%w: %w", ErrAttachXDP, err))
			for _, newLink := range added {
				if err := newLink.Close(); err != nil {
					*links = append(*links, newLink)
					failures = append(failures, err)
				}
			}
			return errors.Join(failures...)
		}
		added = append(added, l)
	}
	kept := added
	var failures []error
	for index, l := range existing {
		if desired[index] {
			kept = append(kept, l)
			continue
		}
		if err := l.Close(); err != nil {
			kept = append(kept, l)
			failures = append(failures, fmt.Errorf("%w: %w", ErrCloseOldLink, err))
		}
	}
	*links = kept
	return errors.Join(failures...)
}

// UpdateDataPlaneAddresses publishes a validated candidate's interface and
// advertised addresses. Sxa S1-U/S5S8 and Sxb PA addresses remain independent.
func UpdateDataPlaneAddresses(
	pfcpSrv map[string]*PfcpConnection,
	gtpPathManager *GtpPathManager,
	next *config.UpfConfig,
) error {
	if gtpPathManager == nil {
		return ErrNilGtpPathManager
	}
	gtpPathManager.UpdateLocalAddress(next.N3Address + GTPPortStr)
	// TS 29.244 V20.1.0 clause 5.5.3: new UP-allocated F-TEIDs use
	// the advertised address selected for the interface.
	if n4 := pfcpSrv[N4PFCPKeyName]; n4 != nil {
		n4.UpdateN3Address(net.ParseIP(next.N3AdvertisedAddress))
		n4.UpdateN9Address(net.ParseIP(next.N9AdvertisedAddress))
	}
	config.Conf.SetRuntimeN3AdvertisedAddress5G(next.GetN3AdvertisedAddress5G())
	return nil
}

// samePFCPEndpoint compares bind addresses after normalising wildcard and
// IPv4-mapped representations. A different port always needs a new socket.
func samePFCPEndpoint(a, b *net.UDPAddr) bool {
	if a.Port != b.Port {
		return false
	}
	aWildcard := len(a.IP) == 0 || a.IP.IsUnspecified()
	bWildcard := len(b.IP) == 0 || b.IP.IsUnspecified()
	if aWildcard || bWildcard {
		return aWildcard && bWildcard
	}
	return a.IP.Equal(b.IP) && a.Zone == b.Zone
}

func UpdatePFCPConnections(pfcpSrv map[string]*PfcpConnection, keyName, address, nodeID string, remoteNodes []string) error {
	return UpdatePFCPConnectionsAndPersist(pfcpSrv, keyName, address, nodeID, remoteNodes, nil)
}

// UpdatePFCPConnectionsAndPersist resolves peers and binds a replacement socket
// before committing configuration and publishing the new endpoint together.
func UpdatePFCPConnectionsAndPersist(pfcpSrv map[string]*PfcpConnection, keyName, address, nodeID string, remoteNodes []string, persist func() error) error {
	conn := pfcpSrv[keyName]
	if conn == nil {
		return ErrNonePFCPConn
	}
	var create func(string) (AssociationConnector, error)
	switch keyName {
	case N4PFCPKeyName:
		create = conn.profile.N4Connector
	case SxaPFCPKeyName:
		create = conn.profile.SxaConnector
	case SxbPFCPKeyName:
		create = conn.profile.SxbConnector
	default:
		return ErrNonePFCPConn
	}
	nodes := make([]AssociationConnector, 0, len(remoteNodes))
	for _, remote := range remoteNodes {
		connector, err := create(remote)
		if err != nil {
			return fmt.Errorf("prepare PFCP remote node: %w", err)
		}
		nodes = append(nodes, connector)
	}
	return conn.updateEndpoint(address, nodeID, &nodes, persist)
}

func UpdateAssociationSetupTimeout(
	pfcpSrv map[string]*PfcpConnection,
	associationSetupTimeout uint32,
) {
	for _, connection := range pfcpSrv {
		connection.SetAssociationSetupTimeout(associationSetupTimeout)
	}
}

func UpdateHeartbeatTimeout(
	pfcpSrv map[string]*PfcpConnection,
	heartbeatTimeout uint32,
) {
	for _, connection := range pfcpSrv {
		connection.SetHeartbeatTimeout(heartbeatTimeout)
	}
}

func UpdateGTPManager(
	gtpPathManager *GtpPathManager,
	gtpPeerAddresses []string,
	GtpEchoInterval uint32,
) {
	gtpPathManager.UpdateGtpPath(gtpPeerAddresses)
	gtpPathManager.UpdateCheckTicker(time.NewTicker(time.Duration(GtpEchoInterval) * time.Second))
}

func StringToXDPAttachMode(Mode string) link.XDPAttachFlags {
	switch Mode {
	case "generic":
		return link.XDPGenericMode
	case "native":
		return link.XDPDriverMode
	case "offload":
		return link.XDPOffloadMode
	default:
		return link.XDPGenericMode
	}
}

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
		return fmt.Errorf("logger configuring error: %s. Using '%s' level",
			err.Error(), zerolog.GlobalLevel().String())
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

func UpdateDataPlaneAddresses(
	pfcpConnection map[string]*PfcpConnection,
	gtpPathManager *GtpPathManager,
	n3Addr net.IP,
	n9Addr net.IP,
) error {
	if gtpPathManager == nil {
		return ErrNilGtpPathManager
	}

	gtpPathManager.UpdateLocalAddress(n3Addr.String() + GTPPortStr)

	for _, conn := range pfcpConnection {
		conn.UpdateN3Address(n3Addr)
		conn.UpdateN9Address(n9Addr)

	}

	return nil
}

func UpdatePFCPConnections(
	pfcpSrv map[string]*PfcpConnection,
	keyName string,
	address string,
	nodeID string,
	remoteNodes []string,
) error {
	conn, ok := pfcpSrv[keyName]
	if ok {
		if err := conn.Update(address, nodeID); err != nil {
			return err
		}
	} else {
		return ErrNonePFCPConn
	}
	if conn == nil {
		return ErrNonePFCPConn
	}

	switch keyName {
	case N4PFCPKeyName:
		remotePFCPNodes := make([]AssociationConnector, 0, len(remoteNodes))
		for _, remoteNode := range remoteNodes {
			connector, err := conn.profile.N4Connector(remoteNode)
			if err != nil {
				return fmt.Errorf("failed to create default association connector: %w", err)
			}
			remotePFCPNodes = append(remotePFCPNodes, connector)
		}

		conn.SetRemoteNodes(remotePFCPNodes)
	case SxaPFCPKeyName:
		remotePFCPNodes := make([]AssociationConnector, 0, len(remoteNodes))
		for _, remoteNode := range remoteNodes {
			connector, err := conn.profile.SxaConnector(remoteNode)
			if err != nil {
				return fmt.Errorf("failed to create sxa association connector: %w", err)
			}
			remotePFCPNodes = append(remotePFCPNodes, connector)
		}

		conn.SetRemoteNodes(remotePFCPNodes)
	case SxbPFCPKeyName:
		remotePFCPNodes := make([]AssociationConnector, 0, len(remoteNodes))
		for _, remoteNode := range remoteNodes {
			connector, err := conn.profile.SxbConnector(remoteNode)
			if err != nil {
				return fmt.Errorf("failed to create sxb association connector: %w", err)
			}
			remotePFCPNodes = append(remotePFCPNodes, connector)
		}

		conn.SetRemoteNodes(remotePFCPNodes)
	}

	return nil
}

func UpdateAssociationSetupTimeout(
	pfcpSrv map[string]*PfcpConnection,
	associationSetupTimeout uint32,
) {
	for _, connection := range pfcpSrv {
		connection.AssociationSetupTicker.Reset(time.Duration(associationSetupTimeout) * time.Second)
	}
}

func UpdateHeartbeatTimeout(
	pfcpSrv map[string]*PfcpConnection,
	heartbeatTimeout uint32,
) {
	for _, connection := range pfcpSrv {
		for _, nodeAssociation := range connection.NodeAssociations {
			nodeAssociation.HeartbeatTimeout.Reset(time.Duration(heartbeatTimeout) * time.Second)
		}
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

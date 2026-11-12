// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	kernel "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gomaja-labs/go-eupf/cmd/api/rest"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/server"
	"github.com/gomaja-labs/go-eupf/cmd/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

//go:generate go tool swag init --parseDependency --parseInternal --parseDepth 1 -g api/rest/handler.go

func waitForAllAssocReleases(ctx context.Context, conns ...*core.PfcpConnection) {
	const (
		pfcpAssocReleaseTimeout      = time.Second * 10
		pfcpAssocReleaseCheckTimeout = time.Millisecond * 100
	)

	ctx, cancel := context.WithTimeout(ctx, pfcpAssocReleaseTimeout)
	defer cancel()

	tick := time.NewTicker(pfcpAssocReleaseCheckTimeout)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Warn().Msg("Association release timeout")
			return
		case <-tick.C:
			totalAssocs := 0
			for _, conn := range conns {
				if conn == nil {
					continue
				}
				totalAssocs += conn.GetAssiciationCount()
			}

			if totalAssocs == 0 {
				log.Info().Msg("All associations released")
				return
			}
		}
	}
}

// safeReleaseConn sends an association release request and deletes all
// associations on the connection. It is a no-op when conn is nil, which
// happens when the corresponding Sxa/Sxb connection was not configured.
func safeReleaseConn(conn *core.PfcpConnection) {
	if conn == nil {
		return
	}
	conn.SendAssociationReleaseRequest()
	conn.DeleteAllAssociations()
}

// newStartupDumper returns capture initialization errors to the startup boundary.
func newStartupDumper(path string, files, size, packets int) (*utils.PacketDumper, error) {
	dumper, err := utils.NewPacketDumper(path, files, size, packets)
	if err != nil {
		return nil, fmt.Errorf("initialize packet capture: %w", err)
	}
	return dumper, nil
}

func main() {
	config.Init()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := supervise(ctx, run, 15*time.Second); err != nil {
		log.Error().Err(err).Msg("Service failed")
		os.Exit(1)
	}
}

// supervise bounds shutdown including deferred resource cleanup. A timeout is a
// real failure; normal signal handling lets run return after all defers finish.
func supervise(ctx context.Context, run func(context.Context) error, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("shutdown deadline exceeded after %s", timeout)
	}
}

func run(ctx context.Context) (runErr error) {
	resetAssociationChan := make(chan struct{}, 1)

	// Warning: inefficient log writing.
	// As zerolog docs says: "Pretty logging on the console is made possible using the provided (but inefficient) zerolog.ConsoleWriter."
	core.InitLogger()
	core.SetLoggerCaller(config.Conf.LoggingCaller)
	if err := core.SetLoggerLevel(config.Conf.LoggingLevel); err != nil {
		log.Error().Msgf("Logger configuring error: %s. Using '%s' level", err.Error(), zerolog.GlobalLevel().String())
	}

	if err := ebpf.IncreaseResourceLimits(); err != nil {
		return fmt.Errorf("increase resource limits: %w", err)
	}

	bpfObjects := ebpf.NewBpfObjects()
	bpfObjects.SetPdrMapSize(config.Conf.PdrMapSize)
	bpfObjects.SetFarMapSize(config.Conf.FarMapSize)
	bpfObjects.SetQerMapSize(config.Conf.QerMapSize)
	bpfObjects.SetUrrMapSize(config.Conf.UrrMapSize)
	if err := bpfObjects.Load(); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}

	defer func() { _ = bpfObjects.Close() }()

	var err error
	dumper, err := newStartupDumper(
		"dumps/",
		config.Conf.TraceMaxDumpFiles,
		config.Conf.TraceMaxDumpSize,
		config.Conf.TraceMaxDumpPackets,
	)
	if err != nil {
		return err
	} else {
		defer dumper.Close(false)
		go dumper.ReadTraceMap(bpfObjects.TraceMap)
	}

	entrypointConfig := ebpf.IpEntrypointDataplaneConfig{
		N3Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP(config.Conf.N3Address).To4()),
		N9Ipv4Address: binary.LittleEndian.Uint32(net.ParseIP(config.Conf.N9Address).To4()),
		TraceIn:       0,
		TraceOut:      0,
		TraceBlocked:  0,
		Ip6RaSupport:  0,
	}

	if config.Conf.TraceIn {
		entrypointConfig.TraceIn = 1
	}

	if config.Conf.TraceOut {
		entrypointConfig.TraceOut = 1
	}

	if config.Conf.TraceBlocked {
		entrypointConfig.TraceBlocked = 1
	}

	if config.Conf.IP6RaSupport {
		ip6Prefix, ip6Net, _ := net.ParseCIDR(config.Conf.Ip6RaPrefix)
		ip6PrefixLength, _ := ip6Net.Mask.Size()

		entrypointConfig.Ip6RaSupport = 1
		copy(entrypointConfig.Ip6RaPrefix[:], ip6Prefix.To16())
		entrypointConfig.Ip6RaPrefixLength = uint16(ip6PrefixLength)
	}

	if err := bpfObjects.GlobalConfig.Set(entrypointConfig); err != nil {
		return fmt.Errorf("set dataplane global config: %w", err)
	}

	sdfNotifier, err := newStartupSdfListener(bpfObjects.SdfNotifyMap)
	if err != nil {
		return err
	}
	defer sdfNotifier.Close()
	go sdfNotifier.ReadEventLoop()

	links := make([]link.Link, 0, len(config.Conf.InterfaceName))
	defer func() {
		for _, l := range links {
			err := l.Close()
			if err != nil {
				log.Error().Msgf("error closing link: %s", err.Error())
			}
		}
	}()

	for _, ifaceName := range config.Conf.InterfaceName {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return fmt.Errorf("lookup network interface %q: %w", ifaceName, err)
		}

		// Attach the program.
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   bpfObjects.UpfIpEntrypointFunc,
			Interface: iface.Index,
			Flags:     core.StringToXDPAttachMode(config.Conf.XDPAttachMode),
		})
		if err != nil {
			return fmt.Errorf("attach XDP program: %w", err)
		}

		links = append(links, l)

		log.Info().Msgf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	}

	log.Info().Msgf("Initialize resources: UEIP pool (CIDR: \"%s\"), TEID pool (size: %d)", config.Conf.UEIPPool, config.Conf.FTEIDPool)
	resourceManager, err := service.NewResourceManager(config.Conf.UEIPPool, config.Conf.FTEIDPool)
	if err != nil {
		return fmt.Errorf("create resource manager: %w", err)
	}

	// Select PFCP profile based on the pfcp_profile config key.
	var profile core.PfcpProfile
	switch config.Conf.PfcpProfile {
	case "huawei":
		profile = core.HuaweiProfile{
			S1UAddress:  config.Conf.S1UAddress,
			S5S8Address: config.Conf.S5S8Address,
			PAAddress:   config.Conf.PAAddress,
		}
	default:
		profile = core.DefaultProfile{}
	}

	type connSpec struct {
		label       string
		address     string
		nodeId      string
		n3Ip        string
		n9Ip        string
		sdfNotifyC  <-chan ebpf.SdfFlowNotification
		remoteNodes []string
		connectorFn func(string) (core.AssociationConnector, error)
	}

	startConn := func(s connSpec) (*core.PfcpConnection, error) {
		conn, err := core.NewPfcpConnection(s.address, s.nodeId, s.n3Ip, s.n9Ip, bpfObjects, resourceManager, dumper, s.sdfNotifyC, profile)
		if err != nil {
			return nil, fmt.Errorf("create %s connection: %w", s.label, err)
		}
		connectors := make([]core.AssociationConnector, 0, len(s.remoteNodes))
		for _, rn := range s.remoteNodes {
			c, err := s.connectorFn(rn)
			if err != nil {
				log.Warn().Msgf("failed to create %s association connector: %v", s.label, err)
				continue
			}
			connectors = append(connectors, c)
		}
		conn.SetRemoteNodes(connectors)
		go conn.Run()
		return conn, nil
	}

	// Create PFCP (N4) connection
	pfcpConn, err := startConn(connSpec{
		label:       "PFCP",
		address:     config.Conf.PfcpAddress,
		nodeId:      config.Conf.PfcpNodeId,
		n3Ip:        config.Conf.N3AdvertisedAddress,
		n9Ip:        config.Conf.N9AdvertisedAddress,
		sdfNotifyC:  nil,
		remoteNodes: config.Conf.PfcpRemoteNode,
		connectorFn: profile.N4Connector,
	})
	if err != nil {
		return err
	}
	defer pfcpConn.Close()

	// Create Sxa connection (optional — only when sxa_address is configured).
	// Without an Sxa peer the S1U/S5S8 interfaces are unused, so we skip the
	// connection entirely rather than binding a UDP socket to an empty address.
	var sxaConn *core.PfcpConnection
	if config.Conf.SxaLocalAddress != "" {
		sxaConn, err = startConn(connSpec{
			label:       "Sxa",
			address:     config.Conf.SxaLocalAddress,
			nodeId:      config.Conf.SxaLocalNodeId,
			n3Ip:        config.Conf.S1UAddress,
			n9Ip:        config.Conf.S5S8Address,
			sdfNotifyC:  nil,
			remoteNodes: config.Conf.SxaRemoteNode,
			connectorFn: profile.SxaConnector,
		})
		if err != nil {
			return err
		}
		defer sxaConn.Close()
	} else {
		log.Info().Msg("Sxa connection skipped (sxa_address not configured)")
	}

	// Create Sxb connection (optional — only when sxb_address is configured).
	var sxbConn *core.PfcpConnection
	if config.Conf.SxbLocalAddress != "" {
		sxbConn, err = startConn(connSpec{
			label:       "Sxb",
			address:     config.Conf.SxbLocalAddress,
			nodeId:      config.Conf.SxbLocalNodeId,
			n3Ip:        config.Conf.PAAddress,
			n9Ip:        config.Conf.PAAddress,
			sdfNotifyC:  sdfNotifier.GetNotificationChannel(),
			remoteNodes: config.Conf.SxbRemoteNode,
			connectorFn: profile.SxbConnector,
		})
		if err != nil {
			return err
		}
		defer sxbConn.Close()
	} else {
		log.Info().Msg("Sxb connection skipped (sxb_address not configured)")
	}

	gtpPathManager := core.NewGtpPathManager(config.Conf.N3Address+core.GTPPortStr, time.Duration(config.Conf.GtpEchoInterval)*time.Second)
	for _, peer := range config.Conf.GtpPeer {
		gtpPathManager.AddGtpPath(peer)
	}
	gtpPathManager.Run()
	defer gtpPathManager.Stop()

	ForwardPlaneStats := ebpf.UpfXdpActionStatistic{
		BpfObjects: bpfObjects,
	}

	// Build the PFCP connection map exposed to the API. Sxa/Sxb entries are
	// only present when the corresponding connection was actually created; the
	// REST handlers in cmd/api/rest/config.go already guard with `exists`, so
	// omitting a key is the signal that the connection is unavailable.
	pfcpMap := map[string]*core.PfcpConnection{
		core.N4PFCPKeyName: pfcpConn,
	}
	if sxaConn != nil {
		pfcpMap[core.SxaPFCPKeyName] = sxaConn
	}
	if sxbConn != nil {
		pfcpMap[core.SxbPFCPKeyName] = sxbConn
	}

	h := rest.NewApiHandler(
		bpfObjects,
		pfcpMap,
		&ForwardPlaneStats,
		&config.Conf,
		&links,
		gtpPathManager,
		resetAssociationChan,
	)

	engine := h.InitRoutes()
	metricsEngine := h.InitMetricsRoute()

	apiSrv := server.New(config.Conf.ApiAddress, engine)

	metricsSrv := server.New(config.Conf.MetricsAddress, metricsEngine)

	serverErrors := make(chan error, 2)
	go func() { serverErrors <- apiSrv.Run() }()
	go func() { serverErrors <- metricsSrv.Run() }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := errors.Join(apiSrv.Stop(shutdown), metricsSrv.Stop(shutdown)); err != nil {
			log.Error().Err(err).Msg("HTTP shutdown failed")
			runErr = errors.Join(runErr, err)
		}
	}()

	assocReleaseFunc := func() {
		// Request release and clear associations. safeReleaseConn is a no-op
		// for Sxa/Sxb connections that were never created (nil).
		safeReleaseConn(pfcpConn)
		safeReleaseConn(sxaConn)
		safeReleaseConn(sxbConn)

		// Wait until every existing connection reports zero associations.
		// waitForAllAssocReleases skips nil entries internally.
		waitForAllAssocReleases(ctx, pfcpConn, sxaConn, sxbConn)
	}

	for {
		select {
		case err := <-serverErrors:
			if err != nil {
				return fmt.Errorf("HTTP server: %w", err)
			}
		case <-ctx.Done():
			log.Info().Msg("OS signal received. Initiating graceful shutdown...")
			// Keep association release in one hook for the release-lifecycle follow-up.
			assocReleaseFunc()
			return nil
		case <-resetAssociationChan:
			assocReleaseFunc()
		}
	}
}

func newStartupSdfListener(m *kernel.Map) (*ebpf.SdfNotifyListener, error) {
	listener, err := ebpf.NewSdfNotifyListener(m)
	if err != nil {
		return nil, fmt.Errorf("initialize SDF notification listener: %w", err)
	}
	return listener, nil
}

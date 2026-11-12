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

func waitForAllAssocReleases(ctx context.Context, conns ...*core.PfcpConnection) error {
	period := time.Duration(0)
	for _, conn := range conns {
		period = max(period, conn.AssociationReleaseTimeout())
	}
	ctx, cancel := context.WithTimeout(ctx, period+core.AssociationCleanupTimeout+200*time.Millisecond)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		total := 0
		for _, conn := range conns {
			if conn == nil {
				continue
			}
			if err := conn.FatalError(); err != nil {
				return err
			}
			total += conn.GetAssiciationCount()
		}
		if total == 0 {
			log.Info().Msg("All associations and rules released")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for association/rule release: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

// safeReleaseConn starts the CP Release procedure and keeps associations and
// rules until CP Release or the bounded graceful period (TS 29.244 V20.1.0
// clause 6.2.7.3.1). Optional Sxa/Sxb connections may be nil.
func safeReleaseConn(conn *core.PfcpConnection) {
	if conn != nil {
		conn.SendAssociationReleaseRequest()
	}
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
	defer func() { pfcpConn.Close(); runErr = errors.Join(runErr, pfcpConn.FatalError()) }()

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
		defer func() { sxaConn.Close(); runErr = errors.Join(runErr, sxaConn.FatalError()) }()
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
		defer func() { sxbConn.Close(); runErr = errors.Join(runErr, sxbConn.FatalError()) }()
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
	if config.Conf.ApiTLSCertFile != "" {
		apiSrv, err = server.NewTLS(config.Conf.ApiAddress, engine, config.Conf.ApiTLSCertFile, config.Conf.ApiTLSKeyFile)
		if err != nil {
			return err
		}
	} else if config.Conf.ApiToken != "" {
		host, _, _ := net.SplitHostPort(config.Conf.ApiAddress)
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			log.Warn().Msg("Management API uses plaintext HTTP: bearer tokens require equivalent transport security (RFC 6750 section 5.3)")
		}
	}
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

	assocReleaseFunc := func() error {
		safeReleaseConn(pfcpConn)
		safeReleaseConn(sxaConn)
		safeReleaseConn(sxbConn)
		// Signal cancellation initiates shutdown; it must not cancel the CP's
		// opportunity to release. The separate supervisor bounds every defer.
		return waitForAllAssocReleases(context.Background(), pfcpConn, sxaConn, sxbConn)
	}

	for {
		select {
		case err := <-pfcpConn.Failures():
			return err
		case err := <-sxaConn.Failures():
			return err
		case err := <-sxbConn.Failures():
			return err
		case err := <-serverErrors:
			if err != nil {
				return fmt.Errorf("HTTP server: %w", err)
			}
		case <-ctx.Done():
			log.Info().Msg("OS signal received. Initiating graceful shutdown...")
			return assocReleaseFunc()
		case <-resetAssociationChan:
			if err := assocReleaseFunc(); err != nil {
				return err
			}
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

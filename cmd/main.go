// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
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
	releases := make([]*core.AssociationRelease, 0, len(conns))
	for _, conn := range conns {
		releases = append(releases, conn.CurrentRelease())
		period = max(period, conn.AssociationReleaseWaitTimeout())
	}
	ctx, cancel := context.WithTimeout(ctx, period+core.AssociationCleanupTimeout+200*time.Millisecond)
	defer cancel()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		total := 0
		for _, release := range releases {
			if err := release.Err(); err != nil {
				return err
			}
			if !release.Done() {
				total++
			}
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
	if err := supervise(ctx, run, processShutdownTimeout(config.Conf)); err != nil {
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
	memoryState, err := config.CgroupMemory()
	if err != nil {
		return fmt.Errorf("read container memory budget: %w", err)
	}
	memoryLimit, beforeMaps := memoryState.Limit, memoryState.Current
	log.Info().Str("cgroup_path", memoryState.Path).Str("cgroup_limit_source", memoryState.LimitSource).Str("cgroup_charge_source", memoryState.ChargeSource).Int64("container_limit_bytes", memoryLimit).Msg("Resolved process memory cgroup")
	if _, err := config.Conf.PFCPMemoryPlan(memoryLimit, beforeMaps); err != nil {
		return err
	}

	bpfObjects := ebpf.NewBpfObjects()
	bpfObjects.SetBufferCapacity(config.Conf.MaxSessions, config.Conf.Buffering().Packets)
	bpfObjects.SetPdrMapSize(config.Conf.PdrMapSize)
	bpfObjects.SetFarMapSize(config.Conf.FarMapSize)
	bpfObjects.SetQerMapSize(config.Conf.QerMapSize)
	bpfObjects.SetUrrMapSize(config.Conf.UrrMapSize)
	if err := bpfObjects.Load(); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}

	defer func() { runErr = errors.Join(runErr, bpfObjects.Close()) }()
	bufferSettings := config.Conf.Buffering()
	packetBuffers, err := core.NewPacketBuffering(bpfObjects, core.BufferingOptions{Packets: bufferSettings.Packets, PerSession: bufferSettings.PerSession, FrameBytes: ebpf.BufferFrameSize, Retention: time.Duration(bufferSettings.RetentionSeconds) * time.Second})
	if err != nil {
		return fmt.Errorf("initialize packet buffering: %w", err)
	}
	defer func() { runErr = errors.Join(runErr, packetBuffers.Close()) }()

	// SetMemoryLimit excludes kernel BPF memory. Keep the observed cgroup
	// baseline outside Go's allowance, including the default startup peak.
	debug.FreeOSMemory()
	loadedMemory, err := config.CgroupMemory()
	if err != nil {
		return fmt.Errorf("read loaded map memory charge: %w", err)
	}
	baseline := loadedMemory.Current
	var growingMaps []*kernel.MapInfo
	for _, m := range []*kernel.Map{bpfObjects.PdrMapDownlinkIp4, bpfObjects.PdrMapDownlinkIp6, bpfObjects.PdrMapTeidIp4} {
		info, err := m.Info()
		if err != nil {
			return fmt.Errorf("read PDR map capacity: %w", err)
		}
		growingMaps = append(growingMaps, info)
	}
	mapReserve, err := growingMapMemory(growingMaps...)
	if err != nil {
		return err
	}
	plannedBaseline := baseline + mapReserve
	softLimit, err := config.Conf.PFCPMemoryPlan(memoryLimit, plannedBaseline)
	if err != nil {
		return err
	}
	if softLimit > 0 {
		configured := debug.SetMemoryLimit(-1)
		if configured < softLimit {
			if _, err := config.Conf.PFCPMemoryPlan(configured+max(plannedBaseline, 64<<20)+(32<<20)+config.Conf.BufferKernelMemoryReserve(), plannedBaseline); err != nil {
				return fmt.Errorf("GOMEMLIMIT: %w", err)
			}
			softLimit = configured
		}
		debug.SetMemoryLimit(softLimit)
	}
	log.Info().Int64("container_limit_bytes", memoryLimit).Int64("cgroup_before_maps_bytes", beforeMaps).Int64("cgroup_loaded_baseline_bytes", baseline).Int64("growing_map_reserve_bytes", mapReserve).Int64("go_memory_limit_bytes", softLimit).Msg("PFCP process memory budget")

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

	if err := core.BindDataPlaneInterfaces(bpfObjects, &links, config.Conf.InterfaceName, config.Conf.XDPAttachMode); err != nil {
		return fmt.Errorf("attach dataplane interfaces: %w", err)
	}

	log.Info().Msgf("Initialize resources: UEIP pool (CIDR: \"%s\"), TEID pool (size: %d)", config.Conf.UEIPPool, config.Conf.FTEIDPool)
	resourceManager, err := service.NewResourceManager(config.Conf.UEIPPool, config.Conf.FTEIDPool)
	if err != nil {
		return fmt.Errorf("create resource manager: %w", err)
	}
	// TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses
	// 16.1b.1/17.1b.1: reserve the restoration period for explicit UE IPv4
	// restoration. Automatic TEIDs use the shared recovery timestamp generation.
	delay := config.Conf.RestorationPeriod
	resourceManager.HoldAutomaticIPv4Until(resourceManager.RecoveryTimestamp.Add(time.Duration(delay) * time.Second))

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
		if err := conn.SetPacketBuffering(packetBuffers); err != nil {
			conn.Close()
			return nil, err
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
	defer func() {
		packetBuffers.CancelPreparation()
		pfcpConn.Close()
		runErr = errors.Join(runErr, pfcpConn.FatalError())
	}()

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
		defer func() {
			packetBuffers.CancelPreparation()
			sxaConn.Close()
			runErr = errors.Join(runErr, sxaConn.FatalError())
		}()
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
		defer func() {
			packetBuffers.CancelPreparation()
			sxbConn.Close()
			runErr = errors.Join(runErr, sxbConn.FatalError())
		}()
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
	go startBufferingAfterAPI(ctx, apiSrv.Ready(), packetBuffers.Start)
	go func() { serverErrors <- metricsSrv.Run() }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := errors.Join(apiSrv.Stop(shutdown), metricsSrv.Stop(shutdown)); err != nil {
			log.Error().Err(err).Msg("HTTP shutdown failed")
			runErr = errors.Join(runErr, err)
		}
	}()

	runDone := make(chan struct{})
	defer close(runDone)
	defer func() {
		packetBuffers.CancelPreparation()
		beginShutdown(pfcpConn, sxaConn, sxbConn)
	}()
	go func() {
		select {
		case <-ctx.Done():
			packetBuffers.CancelPreparation()
		case <-runDone:
		}
	}()
	go watchShutdown(ctx, runDone, pfcpConn, sxaConn, sxbConn)

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
		case err := <-packetBuffers.Failures():
			return fmt.Errorf("packet buffering: %w", err)
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
			beginShutdown(pfcpConn, sxaConn, sxbConn)
			return assocReleaseFunc()
		case <-resetAssociationChan:
			if err := assocReleaseFunc(); err != nil {
				log.Error().Err(err).Msg("Management association release did not finish within its wait budget")
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

func beginShutdown(conns ...*core.PfcpConnection) {
	for _, conn := range conns {
		conn.BeginShutdown()
	}
}

func processShutdownTimeout(conf config.UpfConfig) time.Duration {
	interval := time.Duration(conf.PfcpRequestTimeout) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	window := interval * time.Duration(conf.PfcpRequestRetries+1)
	unit := 2 * time.Second
	period := min(8*time.Second, max(unit, ((window+unit-1)/unit)*unit))
	// Delivery window, the full period at the CP, HTTP shutdown, scheduling slack.
	return window + period + 4*time.Second
}

func watchShutdown(ctx context.Context, done <-chan struct{}, conns ...*core.PfcpConnection) {
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	beginShutdown(conns...)
	for _, conn := range conns {
		safeReleaseConn(conn)
	}
}

// Growing PDR maps allocate entries after startup. Reserve a rounded allocation
// per entry, doubled for trie nodes, plus a KiB for indexing/allocator overhead.
// Default-capacity map measurements include full hash/trie maps; counting only
// their empty startup charge would miss this kernel memory in the cgroup.
func growingMapMemory(infos ...*kernel.MapInfo) (int64, error) {
	var total int64
	for _, info := range infos {
		if info.MaxEntries == 0 || info.Type != kernel.Hash && info.Type != kernel.LPMTrie {
			continue
		}
		block := int64(1)
		for block < int64(info.KeySize)+int64(info.ValueSize)+128 {
			block *= 2
		}
		if info.Type == kernel.LPMTrie {
			block *= 2
		}
		perEntry := block + 1024
		if perEntry > (math.MaxInt64-total)/int64(info.MaxEntries) {
			return 0, fmt.Errorf("PDR map capacity overflows process memory budget")
		}
		total += int64(info.MaxEntries) * perEntry
	}
	return total, nil
}

// Use listener ownership directly: no connection, DNS lookup or polling is
// needed to start private forwarding after the API has successfully bound.
func startBufferingAfterAPI(ctx context.Context, ready <-chan struct{}, start func(context.Context) <-chan struct{}) {
	select {
	case <-ctx.Done():
		return
	case <-ready:
	}
	if ctx.Err() == nil {
		start(ctx)
	}
}

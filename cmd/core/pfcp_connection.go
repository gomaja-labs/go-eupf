// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/core/tracing"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-eupf/cmd/utils"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

type AssociationConnector interface {
	getAddress() string
	sendAssociationSetupRequest(connection *PfcpConnection)
}

var pfcpHandlers = PfcpHandlerMap{
	message.MsgTypeHeartbeatRequest:            HandlePfcpHeartbeatRequest,
	message.MsgTypeHeartbeatResponse:           HandlePfcpHeartbeatResponse,
	message.MsgTypeVersionNotSupportedResponse: HandlePfcpVersionNotSupportedResponse,
	message.MsgTypeAssociationSetupRequest:     HandlePfcpAssociationSetupRequest,
	message.MsgTypeAssociationSetupResponse:    HandlePfcpAssociationSetupResponse,
	message.MsgTypeAssociationUpdateRequest:    HandlePfcpAssociationUpdateRequest,
	message.MsgTypeSessionEstablishmentRequest: HandlePfcpSessionEstablishmentRequest,
	message.MsgTypeSessionDeletionRequest:      HandlePfcpSessionDeletionRequest,
	message.MsgTypeSessionModificationRequest:  HandlePfcpSessionModificationRequest,
	message.MsgTypeAssociationUpdateResponse:   HandlePfcpAssociationUpdateResponse,
	message.MsgTypeAssociationReleaseRequest:   HandlePfcpAssociationReleaseRequest,
	message.MsgTypeSessionReportResponse:       HandlePfcpSessionReportResponse,
	message.MsgTypeAssociationReleaseResponse:  HandlePfcpAssociationUpdateResponse,
}

type PfcpConnection struct {
	activitySessions, activityDirty map[uint64]*NodeAssociation
	activityQueue                   activityQueue
	activityCount                   atomic.Int64
	inactivityReleaseTimeout        time.Duration
	packetBuffers                   *PacketBuffering
	downlinkSessions                map[uint64]*NodeAssociation
	localReleases                   map[uint64]*localSessionRelease
	localReleaseBytes               int64
	localReleaseLimit               int64
	bufferUpdates                   []*bufferReportUpdate
	socketMu                        sync.RWMutex
	closeOnce                       sync.Once
	done                            chan struct{}

	stateMu               sync.RWMutex // Owns all associations, sessions and their indexes.
	nextSessionID         uint64       // UPF-wide SEID allocator, also owned by stateMu.
	transport             transportState
	requestTimeout        time.Duration
	requestRetries        uint32
	heartbeatTimeout      time.Duration
	heartbeatRetries      uint32
	responseRetention     time.Duration
	maxReplayEntries      uint32
	maxOriginatedRequests uint32
	replayMemoryMiB       uint32
	maxAssociations       uint32
	allowedPeers          []netip.Prefix
	heartbeatEvery        time.Duration
	setupEvery            time.Duration
	heartbeatGrace        time.Duration
	setupRetryAt          map[string]time.Time
	connectorNodes        map[string]string
	addressIndex          map[string]map[*NodeAssociation]int
	responseWait          <-chan error
	reportCleanup         []reportCleanup
	reportRetries         []*pendingRequest
	retiredAssociations   []*NodeAssociation // Invalid CP contexts awaiting safe rule reclamation.

	endMarkers    *endMarkerSender
	release       *AssociationRelease
	releasing     bool
	terminalError error
	failures      chan error

	udpConn                *net.UDPConn
	pfcpHandlerMap         PfcpHandlerMap
	NodeAssociations       map[string]*NodeAssociation
	nodeId                 string
	nodeAddrV4             netip.AddrPort
	n3Address              net.IP
	n9Address              net.IP
	mapOperations          ebpf.ForwardingPlaneController
	RecoveryTimestamp      time.Time
	featuresOctets         []uint8
	ResourceManager        *service.ResourceManager
	sdfNotifyC             <-chan ebpf.SdfFlowNotification
	nodes                  []AssociationConnector
	neValidator            *NeValidator
	tracingStorage         tracing.TraceRecordStorage
	dumper                 utils.Dumper
	AssociationSetupTicker *time.Ticker
	PCCRules               map[string]PCCInfo
	PCCRulesNameLinkURRID  map[uint32][]string
	profile                PfcpProfile
}

func NewPfcpConnection(
	addr string,
	nodeId string,
	n3Ip string,
	n9Ip string,
	mapOperations ebpf.ForwardingPlaneController,
	resourceManager *service.ResourceManager,
	dumper utils.Dumper,
	sdfNotifyC <-chan ebpf.SdfFlowNotification,
	profile PfcpProfile,
) (*PfcpConnection, error) {
	if err := config.Conf.ValidatePFCP(); err != nil {
		return nil, err
	}
	allowedPeers, err := config.Conf.PFCPPeerPrefixes()
	if err != nil {
		return nil, err
	}
	if err := validateLocalNodeID(profile, nodeId); err != nil {
		return nil, err
	}
	if resourceManager == nil {
		return nil, fmt.Errorf("a shared UPF resource manager is required")
	}
	if config.Conf.MaxSessions > 0 {
		if err := resourceManager.SetSessionCapacity(config.Conf.MaxSessions); err != nil {
			return nil, fmt.Errorf("configure session admission: %w", err)
		}
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Warn().Msgf("Can't resolve UDP address: %s", err.Error())
		return nil, err
	}

	n3Addr := net.ParseIP(n3Ip)
	if n3Addr == nil {
		return nil, fmt.Errorf("failed to parse N3 IP address: %s", n3Ip)
	}

	n9Addr := net.ParseIP(n9Ip)
	if n9Addr == nil {
		return nil, fmt.Errorf("failed to parse N9 IP address: %s", n9Ip)
	}

	log.Info().Msgf("Starting PFCP connection: %v with Node ID: %v, N3 address: %v, N9 address: %v", udpAddr, nodeId, n3Addr, n9Addr)

	// TS 29.244 V20.1.0 table 8.2.25-1: DDND (Sxa), DLBD and
	// DBDM (Sxa/N4), and UDBC (Sxb/Sxc/N4). BUCP, DDDS and EDBNC
	// are not implemented.
	featuresOctets := []uint8{0x06, 0x04, 0x40, 0, 0, 0, 0, 0x02} // BUNDL: IE octet 7 (payload byte 2), TS 29.244 V20.1.0 table 8.2.25-1
	// TS 29.244 V20.1.0 table 8.2.25-1: EMPU is payload byte 1, bit 1.
	featuresOctets[1] |= 1
	// TS 29.244 V20.1.0 clauses 5.18.1/8.2.25: Enhanced Association Release.
	featuresOctets[1] |= 0x80
	// TS 29.244 V20.1.0 clause 5.5.1: EPC and 5GC require UP allocation.
	featuresOctets[0] = setBit(featuresOctets[0], 4)
	if config.Conf.FeatureUEIP {
		featuresOctets[2] = setBit(featuresOctets[2], 2)
	}

	validator, err := NewNeValidator(config.Conf.AllowedApns, config.Conf.DeniedApns)
	if err != nil {
		return nil, fmt.Errorf("failed to init network instance validator: %s", err.Error())
	}

	udpConn, err := listenPFCP(udpAddr)
	if err != nil {
		log.Warn().Msgf("Can't listen UDP address: %s", err.Error())
		return nil, err
	}

	pccRule, pccRulesNameLinkURRID := buildPCCRuleMap()

	return &PfcpConnection{
		udpConn:                  udpConn,
		done:                     make(chan struct{}),
		failures:                 make(chan error, 1),
		pfcpHandlerMap:           pfcpHandlers,
		NodeAssociations:         map[string]*NodeAssociation{},
		nodeId:                   nodeId,
		nodeAddrV4:               udpConn.LocalAddr().(*net.UDPAddr).AddrPort(),
		n3Address:                n3Addr,
		n9Address:                n9Addr,
		mapOperations:            mapOperations,
		RecoveryTimestamp:        resourceManager.RecoveryTimestamp,
		featuresOctets:           featuresOctets,
		ResourceManager:          resourceManager,
		sdfNotifyC:               sdfNotifyC,
		nodes:                    []AssociationConnector{},
		neValidator:              validator,
		tracingStorage:           tracing.NewSimpleTraceRecordStorage(),
		dumper:                   dumper,
		PCCRules:                 pccRule,
		PCCRulesNameLinkURRID:    pccRulesNameLinkURRID,
		profile:                  profile,
		inactivityReleaseTimeout: time.Duration(config.Conf.InactivityReleaseTimeout) * time.Second,
		localReleaseLimit:        config.Conf.LocalReleaseMemoryReserve(),
		requestTimeout:           defaultDuration(config.Conf.PfcpRequestTimeout, 5), requestRetries: config.Conf.PfcpRequestRetries,
		responseRetention: defaultDuration(config.Conf.PfcpResponseRetention, 60), maxReplayEntries: config.Conf.PfcpMaxReplayEntries, maxOriginatedRequests: config.Conf.PfcpMaxOriginatedRequests, replayMemoryMiB: config.Conf.PfcpReplayMemoryMiB, maxAssociations: config.Conf.PfcpMaxAssociations, allowedPeers: allowedPeers, heartbeatGrace: time.Duration(config.Conf.HeartbeatFailureGrace) * time.Second,
		heartbeatTimeout: time.Duration(config.Conf.HeartbeatTimeout) * time.Second, heartbeatRetries: config.Conf.HeartbeatRetries,
		heartbeatEvery: time.Duration(config.Conf.HeartbeatInterval) * time.Second,
		setupEvery:     defaultDuration(config.Conf.AssociationSetupTimeout, 5),
	}, nil
}

func (connection *PfcpConnection) Update(
	pfcpAddress string,
	pfcpNodeId string,
) error {
	return connection.updateEndpoint(pfcpAddress, pfcpNodeId, nil, nil)
}

// updateEndpoint prepares every fallible resource first. Under stateMu, commit
// persists the candidate before publishing it, so failure retains the socket,
// transactions, identity and connectors without a lossy rollback.
func (connection *PfcpConnection) updateEndpoint(pfcpAddress, pfcpNodeId string, nodes *[]AssociationConnector, commit func() error) error {
	if connection.isClosed() {
		return net.ErrClosed
	}
	if err := validateLocalNodeID(connection.profile, pfcpNodeId); err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", pfcpAddress)
	if err != nil {
		log.Warn().Msgf("Can't resolve UDP address: %s", err.Error())
		return err
	}

	var replacement *net.UDPConn
	if !samePFCPEndpoint(connection.socket().LocalAddr().(*net.UDPAddr), udpAddr) {
		replacement, err = listenPFCP(udpAddr)
		if err != nil {
			return fmt.Errorf("listen updated PFCP endpoint: %w", err)
		}
	}
	connection.stateMu.Lock()
	if connection.isClosed() {
		connection.stateMu.Unlock()
		if replacement != nil {
			_ = replacement.Close()
		}
		return net.ErrClosed
	}
	if commit != nil {
		if err := commit(); err != nil {
			connection.stateMu.Unlock()
			if replacement != nil {
				_ = replacement.Close()
			}
			return err
		}
	}
	if nodes != nil {
		connection.nodes = *nodes
		clear(connection.setupRetryAt)
	}

	var old *net.UDPConn
	if replacement != nil {
		// A retransmission may never migrate to another local endpoint (clause 6.4).
		// Cancel old transactions instead of transmitting them from the new socket.
		connection.transport.mu.Lock()
		connection.socketMu.Lock()
		old = connection.udpConn
		connection.udpConn = replacement
		connection.socketMu.Unlock()
		for _, req := range connection.transport.pending {
			connection.completeRequestLocked(req, requestResult{outcome: requestCanceled, err: net.ErrClosed})
		}
		clear(connection.transport.pending)
		connection.transport.clearResponses()
		connection.transport.pendingBytes = 0
		connection.transport.mu.Unlock()
		connection.nodeAddrV4 = replacement.LocalAddr().(*net.UDPAddr).AddrPort()
		for _, assoc := range connection.NodeAssociations {
			assoc.heartbeatInFlight = false
			assoc.failedAt = time.Time{}
		}
	}
	connection.nodeId = pfcpNodeId
	connection.stateMu.Unlock()
	if old != nil {
		if err := old.Close(); err != nil {
			log.Warn().Err(err).Msg("close previous PFCP endpoint")
		}
	}

	return nil
}

func (connection *PfcpConnection) GetLocalAddr() string {
	return connection.socket().LocalAddr().String()
}

func (connection *PfcpConnection) UpdateN3Address(n3addr net.IP) {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	connection.n3Address = append(net.IP(nil), n3addr...)
}

func (connection *PfcpConnection) UpdateN9Address(n9addr net.IP) {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	connection.n9Address = append(net.IP(nil), n9addr...)
}

func (connection *PfcpConnection) GetN3Addr() string {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return connection.n3Address.String()
}

func (connection *PfcpConnection) GetN9Addr() string {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return connection.n9Address.String()
}

func (connection *PfcpConnection) GetMapOperations() ebpf.ForwardingPlaneController {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return connection.mapOperations
}

func (connection *PfcpConnection) GetResourceManager() *service.ResourceManager {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return connection.ResourceManager
}

func (connection *PfcpConnection) GetDumper() utils.Dumper {
	return connection.dumper
}

// GetAssociation requires stateMu. Identity lookup takes precedence; an address
// resolves only when it belongs to exactly one association (heartbeats carry no
// Node ID). Sessions always resolve through their local SEID instead.
func (connection *PfcpConnection) GetAssociation(identity string) *NodeAssociation {
	if assoc := connection.associationByID(identity); assoc != nil {
		return assoc
	}
	var match *NodeAssociation
	// TS 29.244 V20.1.0 clause 6.2.6.3: a matching UP-initiated Setup
	// Response can confirm another address without replacing the association.
	if nodeID := connection.connectorNodes[identity]; nodeID != "" {
		match = connection.NodeAssociations[nodeID]
	}
	for assoc := range connection.addressIndex[identity] {
		if connection.NodeAssociations[assoc.ID] != assoc {
			continue
		}
		if match != nil && match != assoc {
			return nil
		}
		match = assoc
	}
	// Node associations constructed directly by embedders may have no Setup
	// source. This bounded lookup never walks session state.
	if match == nil {
		for _, assoc := range connection.NodeAssociations {
			if assoc.Addr == identity || assoc.setupSource == identity {
				if match != nil {
					return nil
				}
				match = assoc
			}
		}
	}
	return match
}

func (connection *PfcpConnection) ValidateNetworkInstance(networkInstance string) bool {
	return connection.neValidator.Validate(networkInstance)
}

func buildPCCRuleMap() (map[string]PCCInfo, map[uint32][]string) {
	pccRules := make(map[string]PCCInfo)
	pccRulesURRLinks := make(map[uint32][]string)

	for i := range config.PCCConf.PccRules {
		sdfFilter, err := ParseSdfFilter(config.PCCConf.PccRules[i].SdfFilter)
		if err != nil {
			log.Error().Msgf("Error parsing SDF filter: %s", err.Error())

			continue
		}

		pccRulesURRLinks[config.PCCConf.PccRules[i].Urr.Urrid] = append(
			pccRulesURRLinks[config.PCCConf.PccRules[i].Urr.Urrid],
			config.PCCConf.PccRules[i].PccName,
		)

		pccRules[config.PCCConf.PccRules[i].PccName] = PCCInfo{
			PCCName:      config.PCCConf.PccRules[i].PccName,
			Notify:       config.PCCConf.PccRules[i].Notify,
			SDFFilter:    sdfFilter,
			RawSDFFilter: config.PCCConf.PccRules[i].SdfFilter,
			FAR: ebpf.FarInfo{
				Action:                config.PCCConf.PccRules[i].Far.Action,
				OuterHeaderCreation:   config.PCCConf.PccRules[i].Far.OuterHeaderCreation,
				Teid:                  config.PCCConf.PccRules[i].Far.Teid,
				RemoteIP:              config.PCCConf.PccRules[i].Far.RemoteIP,
				TransportLevelMarking: config.PCCConf.PccRules[i].Far.TransportLevelMarking,
			},
			QER: ebpf.QerInfo{
				GateStatusDL: 0,
				GateStatusUL: 0,
				Qfi:          config.PCCConf.PccRules[i].Qer.Qfi,
				MaxBitrateDL: uint64(config.PCCConf.PccRules[i].Qer.MaxBitrateDl),
				MaxBitrateUL: uint64(config.PCCConf.PccRules[i].Qer.MaxBitrateUl),
			},
		}
	}

	log.Info().Msgf("loaded pcc rules map %+v", config.PCCConf.PccRules)
	log.Info().Msgf("create pcc rules map %+v", pccRules)

	return pccRules, pccRulesURRLinks
}

func (connection *PfcpConnection) SetRemoteNodes(nodes []AssociationConnector) {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	connection.nodes = append([]AssociationConnector(nil), nodes...)
	clear(connection.setupRetryAt)
}

func (connection *PfcpConnection) SendAssociationReleaseRequest() *AssociationRelease {
	connection.stateMu.Lock()
	connection.releasing = true
	release := &AssociationRelease{conn: connection}
	connection.release = release
	for _, assoc := range connection.NodeAssociations {
		release.associations = append(release.associations, assoc)
	}
	// Do not create new UP-initiated associations while releasing this connection.
	connection.transport.mu.Lock()
	for seq, req := range connection.transport.pending {
		if req.typ == message.MsgTypeAssociationSetupRequest {
			connection.completeRequestLocked(req, requestResult{outcome: requestCanceled, err: errors.New("PFCP connection releasing")})
			connection.transport.deletePending(seq)
		}
	}
	connection.transport.mu.Unlock()
	var outgoing []admittedRequest
	now := time.Now()
	for _, assoc := range connection.NodeAssociations {
		request, err := connection.prepareAssociationReleaseLocked(assoc, now, true)
		if err != nil {
			log.Warn().Err(err).Str("node", assoc.ID).Msg("Start bounded association release procedure")
		}
		if request != nil {
			outgoing = append(outgoing, *request)
		}
	}
	if len(connection.NodeAssociations) == 0 {
		connection.releasing = false
	}
	connection.stateMu.Unlock()
	_ = connection.sendAdmitted(outgoing)
	return release
}

func (connection *PfcpConnection) Run() {
	go connection.runInactivity()
	ticker := connection.associationTicker()
	defer ticker.Stop()
	reportTicker := time.NewTicker(5 * time.Second)
	defer reportTicker.Stop()
	// A reassembled UDP payload can exceed the link MTU. Reading the maximum
	// non-jumbo UDP size avoids silently truncating valid PFCP messages.
	buf := make([]byte, 65535)
	var nextDownlinkService time.Time
	for {
		select {
		case <-connection.done:
			return
		case err := <-connection.ruleFailureChannel():
			connection.stateMu.Lock()
			connection.terminalError = err
			if connection.failures != nil {
				select {
				case connection.failures <- err:
				default:
				}
			}
			connection.stateMu.Unlock()
			return
		case <-ticker.C:
			connection.RefreshAssociations()
		case <-reportTicker.C:
			connection.SendReports()
		case notification, ok := <-connection.sdfNotifyC:
			if ok {
				connection.handleSDFNotification(notification)
			} else {
				connection.sdfNotifyC = nil
			}
		default:
		}
		connection.serviceTransactions(time.Now())
		connection.serviceLocalSessionReleases()
		now := time.Now()
		if !now.Before(nextDownlinkService) {
			connection.serviceDownlinkNotifications(now)
			nextDownlinkService = time.Now().Add(20 * time.Millisecond)
		}
		connection.serviceHeartbeats(time.Now())
		socket := connection.socket()
		_ = socket.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		n, addr, err := socket.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-connection.done:
				return
			default:
			}
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				continue
			}
			log.Warn().Err(err).Msg("Error reading PFCP socket")
			continue
		}
		connection.handleDatagram(buf[:n], addr, socket.LocalAddr().(*net.UDPAddr).AddrPort())
	}
}

func (connection *PfcpConnection) socket() *net.UDPConn {
	connection.socketMu.RLock()
	defer connection.socketMu.RUnlock()
	return connection.udpConn
}
func (connection *PfcpConnection) isClosed() bool {
	select {
	case <-connection.done:
		return true
	default:
		return false
	}
}
func (connection *PfcpConnection) Close() {
	connection.closeOnce.Do(func() {
		connection.stateMu.Lock()
		if connection.done != nil {
			close(connection.done)
		}
		if connection.AssociationSetupTicker != nil {
			connection.AssociationSetupTicker.Stop()
		}
		socket := connection.socket()
		connection.transport.mu.Lock()
		for _, req := range connection.transport.pending {
			connection.completeRequestLocked(req, requestResult{outcome: requestCanceled, err: net.ErrClosed})
		}
		clear(connection.transport.pending)
		connection.transport.clearResponses()
		connection.transport.pendingBytes = 0
		connection.transport.mu.Unlock()
		markerSender := connection.endMarkers
		connection.stateMu.Unlock()
		connection.closeLocalSessionReleases()
		if markerSender != nil {
			markerSender.close()
		}
		_ = socket.Close()
		connection.cleanupBeforeClose()
	})
}

func (connection *PfcpConnection) Receive(b []byte) (int, *net.UDPAddr, error) {
	return connection.socket().ReadFromUDP(b)
}

func (connection *PfcpConnection) Handle(b []byte, addr *net.UDPAddr) {
	connection.stateMu.RLock()
	local := connection.nodeAddrV4
	connection.stateMu.RUnlock()
	connection.handleDatagram(b, addr, local)
}

func (connection *PfcpConnection) handleDatagram(b []byte, addr *net.UDPAddr, local netip.AddrPort) {
	if connection.isClosed() || addr == nil || len(b) > 65535 || !connection.admitPeer(addr.IP) {
		return
	}

	if err := connection.pfcpHandlerMap.Handle(connection, b, addr, local); err != nil {
		log.Warn().Msgf("Error handling PFCP message: %s", err.Error())
	}
}

func (connection *PfcpConnection) Send(b []byte, addr *net.UDPAddr) (int, error) {
	return connection.socket().WriteTo(b, addr)
}

func (connection *PfcpConnection) SendMessage(msg message.Message, addr *net.UDPAddr) error {
	return connection.SendMessageWithTrace(msg, addr, false)
}

func IsMessageTraceable(msgType uint8) bool {
	switch msgType {
	case message.MsgTypeHeartbeatRequest,
		message.MsgTypeHeartbeatResponse:
		if !config.Conf.TraceHeartbeat {
			return false
		}
	case message.MsgTypeAssociationSetupRequest,
		message.MsgTypeAssociationSetupResponse,
		message.MsgTypeAssociationUpdateRequest,
		message.MsgTypeAssociationUpdateResponse,
		message.MsgTypeAssociationReleaseRequest,
		message.MsgTypeAssociationReleaseResponse,
		message.MsgTypeVersionNotSupportedResponse:
		if !config.Conf.TraceAssociation {
			return false
		}
	}

	return true
}

func (connection *PfcpConnection) SendMessageWithTrace(msg message.Message, addr *net.UDPAddr, trace bool) error {
	err := connection.sendMessageWithTrace(msg, addr, trace)
	var encode *ie.EncodeError
	if errors.As(err, &encode) && !msg.IsRequest() {
		// TS 29.244 V20.1.0 clause 8.2.1: an unencodable response is a system failure.
		log.Error().Err(err).Str("peer", addr.String()).Str("message", msg.MessageTypeName()).Msg("Cannot encode PFCP response")
		fallback := connection.errorResponse(msg.MessageType(), msg.SEID(), msg.Sequence(), ie.CauseSystemFailure, nil)
		if fallback != nil {
			return errors.Join(err, connection.sendMessageWithTrace(fallback, addr, trace))
		}
	}
	return err
}

func (connection *PfcpConnection) sendMessageWithTrace(msg message.Message, addr *net.UDPAddr, trace bool) error {
	var responseBytes []byte
	var err error
	socket := connection.socket()
	if msg.IsRequest() {
		responseBytes, err = connection.prepareRequest(msg, addr, trace, socket)
	} else {
		responseBytes = make([]byte, msg.MarshalLen())
		err = msg.MarshalTo(responseBytes)
	}
	if err != nil {
		return err
	}
	return connection.sendEncodedAtSocket(responseBytes, msg.MessageType(), addr, trace, socket)
}

func (connection *PfcpConnection) sendEncoded(wire []byte, typ uint8, addr *net.UDPAddr, trace bool) error {
	return connection.sendEncodedAtSocket(wire, typ, addr, trace, connection.socket())
}
func (connection *PfcpConnection) sendEncodedAtSocket(wire []byte, typ uint8, addr *net.UDPAddr, trace bool, socket *net.UDPConn) error {
	if trace && IsMessageTraceable(typ) {
		connection.traceMessageAtLocal(wire, addr, socket.LocalAddr().(*net.UDPAddr).AddrPort(), false)
	}
	if _, err := socket.WriteToUDP(wire, addr); err != nil {
		return err
	}
	// Message names come from the finite codec type catalogue, never peer values.
	PfcpMessageTx.WithLabelValues(message.MessageTypeName(typ)).Inc()
	return nil
}

func (connection *PfcpConnection) TraceMessage(b []byte, addr *net.UDPAddr, rx bool) {
	connection.stateMu.RLock()
	local := connection.nodeAddrV4
	connection.stateMu.RUnlock()
	connection.traceMessageAtLocal(b, addr, local, rx)
}

func (connection *PfcpConnection) traceMessageAtLocal(b []byte, addr *net.UDPAddr, local netip.AddrPort, rx bool) {
	if connection.dumper == nil || addr == nil {
		return
	}
	peer := addr.AddrPort()
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	if local.Addr().IsUnspecified() {
		// ReadFromUDP/WriteToUDP do not expose a wildcard socket's chosen
		// local datagram address. Record the matching-family unspecified
		// address; do not substitute a Node ID or guessed interface address.
		ip := netip.IPv6Unspecified()
		if peer.Addr().Is4() {
			ip = netip.IPv4Unspecified()
		}
		local = netip.AddrPortFrom(ip, local.Port())
	}
	if rx {
		connection.dumper.DumpRawIn(peer, local, b)
	} else {
		connection.dumper.DumpRawOut(peer, local, b)
	}
}

func (connection *PfcpConnection) RefreshAssociations() {
	connection.stateMu.RLock()
	nodes := append([]AssociationConnector(nil), connection.nodes...)
	connection.stateMu.RUnlock()
	for _, node := range nodes {
		connection.stateMu.RLock()
		exists := connection.ResourceManager.ShuttingDown() || connection.releasing || connection.associationByID(connection.connectorNodes[node.getAddress()]) != nil || time.Now().Before(connection.setupRetryAt[node.getAddress()])
		connection.stateMu.RUnlock()
		if !exists && !connection.hasOutstanding(message.MsgTypeAssociationSetupRequest, node.getAddress()) {
			node.sendAssociationSetupRequest(connection)
		}
	}
}

func (connection *PfcpConnection) DeleteAllAssociations() {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	for _, assoc := range connection.NodeAssociations {
		connection.deleteAssociation(assoc.ID)
	}
}

// DeleteAssociation removes an association and its session resources atomically
// with respect to PFCP processing and external snapshots.
func (connection *PfcpConnection) DeleteAssociation(addr string) {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	connection.deleteAssociation(addr)
}
func (connection *PfcpConnection) deleteAssociation(addr string) {
	if assoc := connection.GetAssociation(addr); assoc != nil {
		connection.beginAssociationCleanupLocked(assoc, time.Now())
	}
}

// DeleteSession removes a session through the same quiesced map journal as
// PFCP deletion. The caller holds stateMu and retains ownership on failure.
// TS 29.244 V20.1.0 clauses 6.2.8.3 and 6.3.4.
func (connection *PfcpConnection) DeleteSession(session *Session) (err error) {
	_, err = connection.deleteSessionWithUsage(session)
	return err
}

type deletedSessionUsage struct {
	reports []*ie.IE
	ready   <-chan error
}

func (connection *PfcpConnection) deleteSessionWithUsage(session *Session) (_ *deletedSessionUsage, err error) {
	draft := cloneSession(session)
	start, finish := connection.prepareSessionMutation(draft, deleteSessionMutation, true)
	defer func() { err = errors.Join(err, finish(false)) }()
	pool := NewOperationPool()
	pool.Before = start
	usage := &deletedSessionUsage{}
	context := NewPDRCreationContext(draft, connection.ResourceManager)
	if err = processDeletionRequestRules(connection, log.Logger, pool, context, draft, &usage.reports); err != nil {
		return nil, err
	}
	if draft.buffers != nil {
		connection.stagePacketBuffering(draft.buffers.owner.association, session, draft, deleteSessionMutation, false)
	}
	if err = pool.Commit(); err != nil {
		return nil, err
	}
	connection.ReleaseResources(session.LocalSEID)
	err = finish(true)
	usage.ready = connection.responseWait
	connection.responseWait = nil
	return usage, err
}

func (connection *PfcpConnection) GetSessionCount() int {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	count := 0
	for _, assoc := range connection.NodeAssociations {
		count += len(assoc.Sessions)
	}
	return count
}

func (connection *PfcpConnection) GetAssiciationCount() int {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return len(connection.NodeAssociations)
}

func (connection *PfcpConnection) ReleaseResources(seID uint64) {
	if connection.ResourceManager == nil {
		return
	}

	if connection.ResourceManager.IPAM != nil {
		connection.ResourceManager.IPAM.ReleaseIP(seID)
	}

	if connection.ResourceManager.FTEIDM != nil {
		connection.ResourceManager.FTEIDM.ReleaseTEID(seID)
	}
}

func (connection *PfcpConnection) SendReports() {
	connection.stateMu.Lock()
	type admittedReport struct {
		wire   []byte
		peer   *net.UDPAddr
		socket *net.UDPConn
		trace  bool
	}
	var admitted []admittedReport
	defer func() {
		connection.stateMu.Unlock()
		for _, r := range admitted {
			if err := connection.sendEncodedAtSocket(r.wire, message.MsgTypeSessionReportRequest, r.peer, r.trace, r.socket); err != nil {
				log.Warn().Err(err).Msg("Send admitted usage report; reliable delivery retains it")
			}
		}
	}()

	for _, association := range connection.NodeAssociations {
		for seid, session := range association.Sessions {
			for urrid, urr := range session.URRs {

				newReport, err := connection.mapOperations.GetUrr(urr.GlobalId)
				if err != nil {
					continue
				}

				uplink := newReport.UplinkVolume - urr.UrrInfo.UplinkVolume + urr.UnreportedUplink
				downlink := newReport.DownlinkVolume - urr.UrrInfo.DownlinkVolume + urr.UnreportedDownlink

				// TS 29.244 V20.1.0 clause 5.2.2.3.1: every VOLTH report
				// starts another window using the provisioned threshold. Failed
				// delivery restores the admitted octets (clause 6.3.5.2).
				if urr.UrrInfo.VolumeTrigger && urr.UrrInfo.VolumeThreshold > 0 && uplink+downlink >= urr.UrrInfo.VolumeThreshold {
					end := time.Now()
					report := message.NewSessionReportRequest(session.RemoteSEID, 0, buildSessionReportUsageIEs(connection.profile, urrid, urr.ReportSeqNumber, uplink, downlink, urr.measurementStart(), end)...)
					peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(session.controlIP(connection).String(), "8805"))
					if err != nil {
						continue
					}
					socket := connection.socket()
					entity := association.sessionEntities[seid]
					if entity == "" {
						entity = association.Addr
					}
					wire, err := connection.prepareRequestContext(report, peer, session.IsSessionTraced(), socket, entity, association, seid)
					if err != nil {
						log.Warn().Err(err).Uint64("session", seid).Uint32("urr", urrid).Msg("Retain unreported usage until report admission succeeds")
						continue
					}
					connection.bindReportUsageLocked(report, association, seid)
					urr.UnreportedUplink, urr.UnreportedDownlink = 0, 0
					urr.windowStart, urr.unreportedStart = end, time.Time{}
					admitted = append(admitted, admittedReport{wire, peer, socket, session.IsSessionTraced()})
					urr.ReportSeqNumber++
					urr.UrrInfo.UplinkVolume = newReport.UplinkVolume
					urr.UrrInfo.DownlinkVolume = newReport.DownlinkVolume
					session.URRs[urrid] = urr
				}

			}

		}

	}
}

// SDF events are diagnostics. Unsupported application/start-of-traffic URRs
// are rejected when provisioned; a tuple match must not fabricate Usage Reports.
func (connection *PfcpConnection) handleSDFNotification(notification ebpf.SdfFlowNotification) {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	for _, association := range connection.NodeAssociations {
		session := association.Sessions[notification.SessionID]
		if session == nil {
			continue
		}
		if _, exists := session.PDRs[notification.PDRID]; exists {
			log.Debug().Uint64("session", notification.SessionID).Uint32("pdr", notification.PDRID).Msg("SDF matched")
		}
		return
	}
}

func (connection *PfcpConnection) ReleaseSessionByID(seid uint64) (SessionReleaseResult, error) {
	connection.stateMu.Lock()
	if connection.isClosed() {
		connection.stateMu.Unlock()
		return SessionReleaseResult{}, net.ErrClosed
	}
	assoc := connection.sessionAssociation(seid)
	if activeAssociation(assoc) == nil {
		connection.stateMu.Unlock()
		return SessionReleaseResult{}, ErrSessionNotFound
	}
	result, err := connection.beginLocalSessionReleaseLocked(assoc, assoc.Sessions[seid])
	connection.stateMu.Unlock()
	connection.serviceLocalSessionReleases()
	return result, err
}

func (connection *PfcpConnection) ReleaseSessionByUserID(imsi, msisdn string) (SessionReleaseResult, error) {
	connection.stateMu.RLock()
	var seid uint64
	for _, assoc := range connection.NodeAssociations {
		for id, session := range assoc.Sessions {
			if imsi != "" && session.IMSI == imsi || msisdn != "" && session.MSISDN == msisdn {
				seid = id
				break
			}
		}
		if seid != 0 {
			break
		}
	}
	connection.stateMu.RUnlock()
	if seid == 0 {
		return SessionReleaseResult{}, ErrSessionNotFound
	}
	return connection.ReleaseSessionByID(seid)
}

func (connection *PfcpConnection) GetConnAddr() string {
	connection.stateMu.RLock()
	defer connection.stateMu.RUnlock()
	return connection.nodeAddrV4.String()
}

func (connection *PfcpConnection) GetAllTracingRecords() ([]tracing.TraceRecord, error) {
	return connection.tracingStorage.GetTraceRecords()
}

func (connection *PfcpConnection) GetTracingRecordByImsi(imsi string) (tracing.TraceRecord, error) {
	return connection.tracingStorage.GetTraceRecordByImsi(imsi)
}

func (connection *PfcpConnection) GetTracingRecordByMsisdn(msisdn string) (tracing.TraceRecord, error) {
	return connection.tracingStorage.GetTraceRecordByMsisdn(msisdn)
}

func (connection *PfcpConnection) NeedSessionTrace(imsi, msisdn string) bool {
	if imsi != "" {
		if _, err := connection.tracingStorage.GetTraceRecordByImsi(imsi); err == nil {
			return true
		}
	}

	if msisdn != "" {
		if _, err := connection.tracingStorage.GetTraceRecordByMsisdn(msisdn); err == nil {
			return true
		}
	}

	return false
}

func (connection *PfcpConnection) EnableTracingByImsi(imsi string) error {
	storage := connection.tracingStorage

	if err := storage.AddTraceRecordByImsi(imsi); err != nil {
		return fmt.Errorf("error adding tracing record: %w", err)
	}

	return nil
}

func (connection *PfcpConnection) EnableTracingByMsisdn(msisdn string) error {
	storage := connection.tracingStorage

	if err := storage.AddTraceRecordByMsisdn(msisdn); err != nil {
		return fmt.Errorf("error adding tracing record: %w", err)
	}

	return nil
}

func (connection *PfcpConnection) DisableTracing() ([]tracing.TraceRecord, error) {
	return connection.tracingStorage.DeleteTraceRecords()
}

func (connection *PfcpConnection) DisableTracingByImsi(imsi string) (tracing.TraceRecord, error) {
	storage := connection.tracingStorage

	if trace, err := storage.DeleteTraceRecordByImsi(imsi); err == nil {
		return trace, nil
	} else {
		return tracing.TraceRecord{}, fmt.Errorf("error deleting tracing record: %w", err)
	}
}

func (connection *PfcpConnection) DisableTracingByMsisdn(msisdn string) (tracing.TraceRecord, error) {
	storage := connection.tracingStorage

	if trace, err := storage.DeleteTraceRecordByMsisdn(msisdn); err == nil {
		return trace, nil
	} else {
		return tracing.TraceRecord{}, fmt.Errorf("error deleting tracing record: %w", err)
	}
}

func SendSessionReportUsage(conn *PfcpConnection, seid uint64, sequenceID uint32, associationAddr string,
	urrid uint32,
	reportSeq uint32,
	uplink uint64,
	downlink uint64,
	start time.Time,
	traced bool) {
	additionalIEs := buildSessionReportUsageIEs(conn.profile, urrid, reportSeq, uplink, downlink, start, time.Now())

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent Session Report Request to: %s", associationAddr)
	if err := conn.sendAssociationRequest(sessionReport, associationAddr, traced, seid); err != nil {
		log.Info().Err(err).Msg("Failed to send Session Report Request")
	}

}

func SendSessionReportADC(conn *PfcpConnection, seid uint64, sequenceID uint32, associationAddr string,
	urrid uint32,
	reportSeq uint32,
	sdfFilter string,
	traced bool) {
	additionalIEs := buildSessionReportADCIEs(conn.profile, urrid, reportSeq, sdfFilter)

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent Session Report Request to: %s", associationAddr)
	if err := conn.sendAssociationRequest(sessionReport, associationAddr, traced, seid); err != nil {
		log.Info().Err(err).Msg("Failed to send Session Report Request")
	}

}

func SendAssociationUpdate(
	conn *PfcpConnection,
	assoc *NodeAssociation,
	traced bool,
	release bool,
) error {
	if release {
		return conn.startAssociationRelease(assoc.ID, traced)
	}
	sequenceID := uint32(0)

	additionalIEs := []*ie.IE{
		conn.profile.NodeID(conn.localNodeID()), // its Node ID;
	}

	pfcpMsg := message.NewAssociationUpdateRequest(sequenceID, additionalIEs...)

	return conn.sendAssociationRequest(pfcpMsg, assoc.ID, traced, 0)

}

func SendDownlinkNotificationReport(
	conn *PfcpConnection,
	seid uint64,
	sequenceID uint32,
	associationAddr string,
	pdrID uint16,
	traced bool,
	vendorSpecificIEs ...*ie.IE,
) {
	additionalIEs := []*ie.IE{
		ie.NewReportType(0, 0, 0, 1),
		ie.NewDownlinkDataReport(
			ie.NewPDRID(pdrID),
		),
	}

	additionalIEs = append(additionalIEs, vendorSpecificIEs...)

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent DLDR Session Report Request to: %s", associationAddr)
	if err := conn.sendAssociationRequest(sessionReport, associationAddr, traced, seid); err != nil {
		log.Info().Err(err).Msg("Failed to send Session Report Request")
	}

}

type DefaultAssociationConnector struct {
	address string
}

func NewDefaultAssociationConnector(address string) (*DefaultAssociationConnector, error) {
	resolvedAddr, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote node address %s: %w", address, err)
	}

	return &DefaultAssociationConnector{
		address: resolvedAddr.String(),
	}, nil
}

func (connector *DefaultAssociationConnector) getAddress() string {
	return connector.address
}

func (connector *DefaultAssociationConnector) sendAssociationSetupRequest(connection *PfcpConnection) {
	associationAddr := connector.getAddress()
	ies := buildDefaultSetupRequestIEs(connection.profile, connection.localNodeID(), connection.RecoveryTimestamp, connection.featuresOctets[:])
	AssociationSetupRequest := message.NewAssociationSetupRequest(0, ies...)
	log.Info().Msgf("Sent Default Association Setup Request to: %s", associationAddr)

	udpAddr, err := net.ResolveUDPAddr("udp", connection.peerAddress(associationAddr))
	if err != nil {
		log.Error().Msgf("Failed to resolve udp address from PFCP peer address %s. Error: %s\n", associationAddr, err.Error())
		return
	}
	if err := connection.SendMessageWithTrace(AssociationSetupRequest, udpAddr, true); err != nil {
		log.Info().Msgf("Failed to send Association Setup Request: %s\n", err.Error())
	}
}

type SxaAssociationConnector struct {
	address     string
	s1uAddress  string
	s5s8Address string
}

func NewSxaAssociationConnector(address string, s1uAddress string, s5s8Address string) (*SxaAssociationConnector, error) {
	resolvedAddr, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote node address %s: %w", address, err)
	}

	return &SxaAssociationConnector{
		address:     resolvedAddr.String(),
		s1uAddress:  s1uAddress,
		s5s8Address: s5s8Address,
	}, nil
}

func (connector *SxaAssociationConnector) getAddress() string {
	return connector.address
}

func (connector *SxaAssociationConnector) sendAssociationSetupRequest(connection *PfcpConnection) {
	associationAddr := connector.getAddress()
	ies, err := buildSxaSetupRequestIEs(connection.profile, connection.localNodeID(), connection.RecoveryTimestamp, connector.s1uAddress, connector.s5s8Address, connection.featuresOctets)
	if err != nil {
		log.Error().Msgf("failed to build Sxa setup request IEs: %v", err)
		return
	}
	AssociationSetupRequest := message.NewAssociationSetupRequest(0, ies...)
	log.Info().Msgf("Sent Sxa Association Setup Request to: %s", associationAddr)

	udpAddr, err := net.ResolveUDPAddr("udp", connection.peerAddress(associationAddr))
	if err != nil {
		log.Error().Msgf("Failed to resolve udp address from PFCP peer address %s. Error: %s\n", associationAddr, err.Error())
		return
	}
	if err := connection.SendMessageWithTrace(AssociationSetupRequest, udpAddr, true); err != nil {
		log.Info().Msgf("Failed to send Association Setup Request: %s\n", err.Error())
	}
}

type SxbAssociationConnector struct {
	address   string
	paAddress string
}

func NewSxbAssociationConnector(address string, paAddress string) (*SxbAssociationConnector, error) {
	resolvedAddr, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve remote node address %s: %w", address, err)
	}

	return &SxbAssociationConnector{
		address:   resolvedAddr.String(),
		paAddress: paAddress,
	}, nil
}

func (connector *SxbAssociationConnector) getAddress() string {
	return connector.address
}

func (connector *SxbAssociationConnector) sendAssociationSetupRequest(connection *PfcpConnection) {
	associationAddr := connector.getAddress()
	ies, err := buildSxbSetupRequestIEs(connection.profile, connection.localNodeID(), connection.RecoveryTimestamp, connector.paAddress, connection.featuresOctets)
	if err != nil {
		log.Error().Msgf("failed to build Sxb setup request IEs: %v", err)
		return
	}
	AssociationSetupRequest := message.NewAssociationSetupRequest(0, ies...)
	log.Info().Msgf("Sent Sxb Association Setup Request to: %s", associationAddr)

	udpAddr, err := net.ResolveUDPAddr("udp", connection.peerAddress(associationAddr))
	if err != nil {
		log.Error().Msgf("Failed to resolve udp address from PFCP peer address %s. Error: %s\n", associationAddr, err.Error())
		return
	}
	if err := connection.SendMessageWithTrace(AssociationSetupRequest, udpAddr, true); err != nil {
		log.Info().Msgf("Failed to send Association Setup Request: %s\n", err.Error())
	}
}

type NeValidator struct {
	reAllowed *regexp.Regexp
	reDenied  *regexp.Regexp
}

func NewNeValidator(allowed string, denied string) (*NeValidator, error) {

	reAllowed, err := regexp.Compile(allowed)
	if err != nil {
		return nil, fmt.Errorf("network instance validator allowed pattern is invalid: %w", err)
	}

	reDenied, err := regexp.Compile(denied)
	if err != nil {
		return nil, fmt.Errorf("network instance validator denied pattern is invalid: %w", err)
	}

	return &NeValidator{reAllowed: reAllowed, reDenied: reDenied}, nil
}

func (v *NeValidator) IsNeAllowed(networkInstance string) bool {
	return len(v.reAllowed.String()) == 0 || v.reAllowed.MatchString(networkInstance)
}

func (v *NeValidator) IsNeDenied(networkInstance string) bool {
	return len(v.reDenied.String()) > 0 && v.reDenied.MatchString(networkInstance)
}

func (v *NeValidator) Validate(networkInstance string) bool {
	return v.IsNeAllowed(networkInstance) && !v.IsNeDenied(networkInstance)
}

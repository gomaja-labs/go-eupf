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
	socketMu  sync.RWMutex
	closeOnce sync.Once
	done      chan struct{}

	stateMu           sync.RWMutex // Owns all associations, sessions and their indexes.
	nextSessionID     uint64       // UPF-wide SEID allocator, also owned by stateMu.
	transport         transportState
	requestTimeout    time.Duration
	requestRetries    uint32
	heartbeatTimeout  time.Duration
	heartbeatRetries  uint32
	responseRetention time.Duration
	maxTransactions   uint32
	maxAssociations   uint32
	allowedPeers      []netip.Prefix
	heartbeatEvery    time.Duration
	setupEvery        time.Duration
	heartbeatGrace    time.Duration

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

	featuresOctets := []uint8{0, 0, 0x40} // BUNDL: IE octet 7 (payload byte 2), TS 29.244 V20.1.0 table 8.2.25-1
	featuresOctets[1] = setBit(featuresOctets[1], 0)
	if config.Conf.FeatureFTUP {
		featuresOctets[0] = setBit(featuresOctets[0], 4)
	}
	if config.Conf.FeatureUEIP {
		featuresOctets[2] = setBit(featuresOctets[2], 2)
	}

	validator, err := NewNeValidator(config.Conf.AllowedApns, config.Conf.DeniedApns)
	if err != nil {
		return nil, fmt.Errorf("failed to init network instance validator: %s", err.Error())
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Warn().Msgf("Can't listen UDP address: %s", err.Error())
		return nil, err
	}

	pccRule, pccRulesNameLinkURRID := buildPCCRuleMap()

	return &PfcpConnection{
		udpConn:               udpConn,
		done:                  make(chan struct{}),
		pfcpHandlerMap:        pfcpHandlers,
		NodeAssociations:      map[string]*NodeAssociation{},
		nodeId:                nodeId,
		nodeAddrV4:            udpConn.LocalAddr().(*net.UDPAddr).AddrPort(),
		n3Address:             n3Addr,
		n9Address:             n9Addr,
		mapOperations:         mapOperations,
		RecoveryTimestamp:     time.Now(),
		featuresOctets:        featuresOctets,
		ResourceManager:       resourceManager,
		sdfNotifyC:            sdfNotifyC,
		nodes:                 []AssociationConnector{},
		neValidator:           validator,
		tracingStorage:        tracing.NewSimpleTraceRecordStorage(),
		dumper:                dumper,
		PCCRules:              pccRule,
		PCCRulesNameLinkURRID: pccRulesNameLinkURRID,
		profile:               profile,
		requestTimeout:        defaultDuration(config.Conf.PfcpRequestTimeout, 5), requestRetries: config.Conf.PfcpRequestRetries,
		responseRetention: defaultDuration(config.Conf.PfcpResponseRetention, 60), maxTransactions: config.Conf.PfcpMaxTransactions, maxAssociations: config.Conf.PfcpMaxAssociations, allowedPeers: allowedPeers, heartbeatGrace: time.Duration(config.Conf.HeartbeatFailureGrace) * time.Second,
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
		replacement, err = net.ListenUDP("udp", udpAddr)
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
		clear(connection.transport.pending)
		clear(connection.transport.responses)
		clear(connection.transport.responseBudgets)
		connection.transport.responseExpiry = nil
		connection.transport.bytes = 0
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
	return connection.mapOperations
}

func (connection *PfcpConnection) GetResourceManager() *service.ResourceManager {
	return connection.ResourceManager
}

func (connection *PfcpConnection) GetDumper() utils.Dumper {
	return connection.dumper
}

func (connection *PfcpConnection) GetAssociation(assocAddr string) *NodeAssociation {
	if assoc, ok := connection.NodeAssociations[assocAddr]; ok {
		return assoc
	}
	return nil
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
}

func (connection *PfcpConnection) SendAssociationReleaseRequest() {
	log.Info().Msgf("Send AssociationUpdate with release request for node: %s", connection.localNodeID())

	for _, assoc := range connection.AssociationSnapshots() {
		err := SendAssociationUpdate(connection, assoc, false, true)
		if err != nil {
			log.Warn().Msg(err.Error())

			continue
		}
	}
}

func (connection *PfcpConnection) Run() {
	ticker := connection.associationTicker()
	defer ticker.Stop()
	reportTicker := time.NewTicker(5 * time.Second)
	defer reportTicker.Stop()
	// A reassembled UDP payload can exceed the link MTU. Reading the maximum
	// non-jumbo UDP size avoids silently truncating valid PFCP messages.
	buf := make([]byte, 65535)
	for {
		select {
		case <-connection.done:
			return
		case <-ticker.C:
			connection.RefreshAssociations()
		case <-reportTicker.C:
			connection.SendReports()
		case notification, ok := <-connection.sdfNotifyC:
			if ok {
				connection.SendReportsSDF(notification.GetURRID(), notification.GetSdfFilter())
			} else {
				connection.sdfNotifyC = nil
			}
		default:
		}
		connection.serviceTransactions(time.Now())
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
		connection.Handle(buf[:n], addr)
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
		connection.stateMu.Unlock()
		_ = socket.Close()
		connection.DeleteAllAssociations()
		connection.transport.mu.Lock()
		clear(connection.transport.pending)
		clear(connection.transport.responses)
		clear(connection.transport.responseBudgets)
		connection.transport.responseExpiry = nil
		connection.transport.bytes = 0
		connection.transport.pendingBytes = 0
		connection.transport.mu.Unlock()
	})
}

func (connection *PfcpConnection) Receive(b []byte) (int, *net.UDPAddr, error) {
	return connection.socket().ReadFromUDP(b)
}

func (connection *PfcpConnection) Handle(b []byte, addr *net.UDPAddr) {
	if connection.isClosed() || addr == nil || len(b) > 65535 || !connection.admitPeer(addr.IP) {
		return
	}

	if err := connection.pfcpHandlerMap.Handle(connection, b, addr); err != nil {
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
		connection.TraceMessage(wire, addr, false)
	}
	if _, err := socket.WriteToUDP(wire, addr); err != nil {
		return err
	}
	// Message names come from the finite codec type catalogue, never peer values.
	PfcpMessageTx.WithLabelValues(message.MessageTypeName(typ)).Inc()
	return nil
}

func (connection *PfcpConnection) TraceMessage(b []byte, addr *net.UDPAddr, rx bool) {
	if connection.dumper == nil {
		return
	}
	connection.stateMu.RLock()
	local := connection.nodeAddrV4
	connection.stateMu.RUnlock()
	if rx {
		connection.dumper.DumpRawIn(addr.AddrPort(), local, b)
	} else {
		connection.dumper.DumpRawOut(addr.AddrPort(), local, b)
	}
}

func (connection *PfcpConnection) RefreshAssociations() {
	connection.stateMu.RLock()
	nodes := append([]AssociationConnector(nil), connection.nodes...)
	connection.stateMu.RUnlock()
	for _, node := range nodes {
		connection.stateMu.RLock()
		exists := connection.GetAssociation(node.getAddress()) != nil
		connection.stateMu.RUnlock()
		if !exists && !connection.hasOutstanding(message.MsgTypeAssociationSetupRequest, node.getAddress()) {
			node.sendAssociationSetupRequest(connection)
		}
	}
}

func (connection *PfcpConnection) DeleteAllAssociations() {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	for addr := range connection.NodeAssociations {
		connection.deleteAssociation(addr)
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
	assoc := connection.NodeAssociations[addr]
	if assoc == nil {
		return
	}
	for id, session := range assoc.Sessions {
		connection.DeleteSession(session)
		connection.ReleaseResources(session.LocalSEID)
		delete(assoc.Sessions, id)
	}
	delete(connection.NodeAssociations, addr)
	connection.forgetPeer(addr)
}

// DeleteSession removes the forwarding rules of a session, including usage rules.
// TS 29.244 V20.1.0 clause 6.2.8.3: association release deletes all session contexts.
func (connection *PfcpConnection) DeleteSession(session *Session) {
	for _, urr := range session.URRs {
		if _, err := connection.mapOperations.DeleteUrr(urr.GlobalId); err != nil {
			log.Error().Err(err).Uint32("urr", urr.GlobalId).Msg("Delete association usage rule")
		}
	}
	for _, far := range session.FARs {
		if err := connection.mapOperations.DeleteFar(far.GlobalId); err != nil {
			log.Error().Err(err).Uint32("far", far.GlobalId).Msg("Delete association forwarding rule")
		}
	}
	for _, qer := range session.QERs {
		if err := connection.mapOperations.DeleteQer(qer.GlobalId); err != nil {
			log.Error().Err(err).Uint32("qer", qer.GlobalId).Msg("Delete association QoS rule")
		}
	}
	pdrContext := NewPDRCreationContext(session, connection.ResourceManager)
	for _, PDR := range session.PDRs {
		if err := pdrContext.deletePDR(PDR, connection.mapOperations); err != nil {
			log.Error().Err(err).Uint32("pdr", PDR.PdrID).Msg("Delete association detection rule")
		}
	}
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
	var outgoing []queuedMessage
	defer func() { connection.stateMu.Unlock(); connection.sendQueued(outgoing) }()

	for _, association := range connection.NodeAssociations {
		for _, session := range association.Sessions {
			for urrid, urr := range session.URRs {

				newReport, err := connection.mapOperations.GetUrr(urr.GlobalId)
				if err != nil {
					continue
				}

				uplink := newReport.UplinkVolume - urr.UrrInfo.UplinkVolume
				downlink := newReport.DownlinkVolume - urr.UrrInfo.DownlinkVolume

				if uplink+downlink > 0 { //we have usage increment
					if urr.UrrInfo.VolumeThreshold > 0 && urr.UrrInfo.VolumeThreshold <= uplink+downlink {
						urr.ReportSeqNumber += 1
						session.URRSequence += 1
						outgoing = append(outgoing, queuedMessage{message.NewSessionReportRequest(session.RemoteSEID, 0, buildSessionReportUsageIEs(connection.profile, urrid, session.URRSequence, urr.ReportSeqNumber, uplink, downlink)...), association.endpoint, session.IsSessionTraced()})
					}

					urr.UrrInfo.UplinkVolume = newReport.UplinkVolume
					urr.UrrInfo.DownlinkVolume = newReport.DownlinkVolume
					session.URRs[urrid] = urr
				}
			}

			for pdrID, pdr := range session.PDRs {
				internalFarID := pdr.PdrInfo.FarId
				currentFar, err := connection.mapOperations.GetFar(internalFarID)
				if err != nil {
					continue
				}

				if currentFar.Action&0x08 == 0 { // todo maxim: const
					continue
				}

				if currentFar.Trigger == 1 {
					currentFar.Trigger = 2
					err := connection.mapOperations.UpdateFar(internalFarID, currentFar)
					if err != nil {
						log.Warn().Uint32("farID", internalFarID).Msgf("can`t update far")

						continue
					}

					traced := session.IsSessionTraced()
					session.URRSequence++
					outgoing = append(outgoing, queuedMessage{message.NewSessionReportRequest(session.RemoteSEID, 0, ie.NewReportType(0, 0, 0, 1), ie.NewDownlinkDataReport(ie.NewPDRID(uint16(pdrID)))), association.endpoint, traced})
				}
			}
		}

	}
}

func (connection *PfcpConnection) SendReportsSDF(referenceID uint32, sdfFilter string) {
	connection.stateMu.Lock()
	var outgoing []queuedMessage
	defer func() { connection.stateMu.Unlock(); connection.sendQueued(outgoing) }()

	log.Info().Msgf("SendReportsSDF: ref=%d filter=%s", referenceID, sdfFilter)

	if sdfFilter == "" {
		return
	}

	for _, association := range connection.NodeAssociations {
		for _, session := range association.Sessions {

			for _, pdr := range session.PDRs {
				if pdr.Teid != referenceID /*|| pdr.Ipv4 != referenceID*/ { //FIXME: add IPv4 reference
					continue
				}
			}

			for urrid, urr := range session.URRs {
				if urrid != 16733 {
					continue
				}

				urr.ReportSeqNumber += 1
				session.URRSequence += 1
				outgoing = append(outgoing, queuedMessage{message.NewSessionReportRequest(session.RemoteSEID, 0, buildSessionReportADCIEs(connection.profile, urrid, session.URRSequence, urr.ReportSeqNumber, sdfFilter)...), association.endpoint, session.IsSessionTraced()})

				return
			}
		}
	}
}

func (connection *PfcpConnection) ReleaseSessionByID(seid uint64) bool {
	for _, association := range connection.AssociationSnapshots() {
		if session, ok := association.Sessions[seid]; ok {
			pdrList := []uint16{}
			for pdrID := range session.PDRs {
				pdrList = append(pdrList, uint16(pdrID))
			}
			SendSessionReportSessionRelease(
				connection,
				session.RemoteSEID,
				0,
				association.Addr,
				session.IsSessionTraced(),
				pdrList)

			return true
		}
	}

	return false
}

func (connection *PfcpConnection) ReleaseSessionByUserID(imsi string, msisdn string) bool {
	for _, association := range connection.AssociationSnapshots() {
		for _, session := range association.Sessions {
			if session.IMSI == imsi || session.MSISDN == msisdn {
				pdrList := []uint16{}
				for pdrID := range session.PDRs {
					pdrList = append(pdrList, uint16(pdrID))
				}
				SendSessionReportSessionRelease(
					connection,
					session.RemoteSEID,
					0,
					association.Addr,
					session.IsSessionTraced(),
					pdrList)
				return true
			}
		}
	}
	return false
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
	sessionSeq uint32,
	reportSeq uint32,
	uplink uint64,
	downlink uint64,
	traced bool) {
	additionalIEs := buildSessionReportUsageIEs(conn.profile, urrid, sessionSeq, reportSeq, uplink, downlink)

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent Session Report Request to: %s", associationAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(associationAddr))
	if err == nil {
		if err := conn.SendMessageWithTrace(sessionReport, udpAddr, traced); err != nil {
			log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
		}
	} else {
		log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
	}
}

func SendSessionReportADC(conn *PfcpConnection, seid uint64, sequenceID uint32, associationAddr string,
	urrid uint32,
	sessionSeq uint32,
	reportSeq uint32,
	sdfFilter string,
	traced bool) {
	additionalIEs := buildSessionReportADCIEs(conn.profile, urrid, sessionSeq, reportSeq, sdfFilter)

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent Session Report Request to: %s", associationAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(associationAddr))
	if err == nil {
		if err := conn.SendMessageWithTrace(sessionReport, udpAddr, traced); err != nil {
			log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
		}
	} else {
		log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
	}
}

func SendAssociationUpdate(
	conn *PfcpConnection,
	assoc *NodeAssociation,
	traced bool,
	release bool,
) error {
	sequenceID := uint32(0)

	additionalIEs := []*ie.IE{
		conn.profile.NodeID(conn.localNodeID()), // its Node ID;
	}

	if release {
		additionalIEs = append(additionalIEs, ie.NewPFCPAssociationReleaseRequest(1, 0))
	}

	pfcpMsg := message.NewAssociationUpdateRequest(sequenceID, additionalIEs...)

	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(assoc.Addr))
	if err != nil {
		log.Error().Err(err).Msgf("Failed to resolve address for CP node: %s", assoc.ID)
		return err
	}

	if err := conn.SendMessageWithTrace(pfcpMsg, udpAddr, traced); err != nil {
		log.Error().Err(err).Msgf("Failed to send PFCP message to: %s", assoc.ID)
		return err
	}

	return nil
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
	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(associationAddr))
	if err == nil {
		if err := conn.SendMessageWithTrace(sessionReport, udpAddr, traced); err != nil {
			log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
		}
	} else {
		log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
	}
}

func SendSessionReportSessionRelease(conn *PfcpConnection, seid uint64, sequenceID uint32, associationAddr string, traced bool, pdrList []uint16) {
	additionalIEs := buildSessionReportReleaseIEs(conn.profile, pdrList)

	sessionReport := message.NewSessionReportRequest(seid, sequenceID, additionalIEs...)
	log.Debug().Msgf("Sent Session Report Request to: %s", associationAddr)
	udpAddr, err := net.ResolveUDPAddr("udp", conn.peerAddress(associationAddr))
	if err == nil {
		if err := conn.SendMessageWithTrace(sessionReport, udpAddr, traced); err != nil {
			log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
		}
	} else {
		log.Info().Msgf("Failed to send Session Report Request: %s\n", err.Error())
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
	ies, err := buildSxaSetupRequestIEs(connection.profile, connection.localNodeID(), connection.RecoveryTimestamp, connector.s1uAddress, connector.s5s8Address)
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
	ies, err := buildSxbSetupRequestIEs(connection.profile, connection.localNodeID(), connection.RecoveryTimestamp, connector.paAddress)
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

package core

import (
	"net"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/rs/zerolog/log"
)

const (
	enhancedPreparing uint8 = iota + 1
	enhancedDraining
	enhancedWaiting
)

// TS 29.244 V20.1.0 clauses 5.18.1, 6.2.7.3.1 and 8.2.120.
// PARPS precedes local release; URSS follows all terminal session reports.
func (conn *PfcpConnection) prepareEnhancedAssociationRequestLocked(assoc *NodeAssociation, preparing bool, now time.Time, trace bool) (*admittedRequest, error) {
	if conn.ResourceManager.ShuttingDown() && assoc.enhancedDeadline.IsZero() {
		interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
		assoc.enhancedDeadline = now.Add(interval*time.Duration(retries+1) + conn.releasePeriod())
	}
	assoc.releaseRetryAt = now.Add(100 * time.Millisecond)
	children := []*ie.IE{conn.profile.NodeID(conn.nodeId)}
	if preparing {
		children = append(children, ie.NewPFCPAUReqFlags(1))
	} else {
		children = append(children, ie.NewPFCPAssociationReleaseRequest(0, 1))
	}
	request := message.NewAssociationUpdateRequest(0, children...)
	endpoint := assoc.endpoint
	if endpoint == "" {
		endpoint = net.JoinHostPort(assoc.Addr, "8805")
	}
	peer, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return nil, err
	}
	socket := conn.socket()
	wire, err := conn.prepareRequestContext(request, peer, trace, socket, assoc.Addr, assoc, 0)
	if err != nil {
		return nil, err
	}
	conn.transport.mu.Lock()
	pending := conn.transport.pending[request.Sequence()]
	pending.enhancedPrepare = preparing
	if !preparing {
		pending.releasePeriod = conn.releasePeriod()
	}
	conn.transport.mu.Unlock()
	assoc.releaseRequestSent = true
	if !preparing {
		interval, retries := conn.requestPolicy(message.MsgTypeAssociationUpdateRequest)
		assoc.releaseDeadline = now.Add(interval*time.Duration(retries+1) + conn.releasePeriod())
		assoc.enhancedRelease = enhancedWaiting
	}
	return &admittedRequest{wire, request.MessageType(), peer, socket, trace}, nil
}

func (conn *PfcpConnection) serviceEnhancedAssociationLocked(assoc *NodeAssociation, now time.Time) []admittedRequest {
	if !assoc.enhancedDeadline.IsZero() && !now.Before(assoc.enhancedDeadline) {
		if assoc.enhancedRelease == enhancedWaiting && len(assoc.Sessions) == 0 {
			conn.beginAssociationCleanupLocked(assoc, now)
			return nil
		}
		// Shutdown is bounded even when the CP refuses or never answers. Do
		// not return unreclaimed IDs or silently report successful shutdown.
		assoc.cleanupError = errRequestTimeout
		conn.cleanupFailedLocked(assoc)
		return nil
	}
	if assoc.cleaning {
		if !now.Before(assoc.cleanupNext) {
			conn.cleanupAssociationLocked(assoc, now)
		}
		return nil
	}
	if assoc.enhancedRelease == enhancedWaiting {
		if !now.Before(assoc.releaseDeadline) {
			conn.beginAssociationCleanupLocked(assoc, now)
		}
		return nil
	}
	if assoc.enhancedRelease == enhancedPreparing {
		if assoc.releaseRequestSent || now.Before(assoc.releaseRetryAt) {
			return nil
		}
		request, err := conn.prepareEnhancedAssociationRequestLocked(assoc, true, now, true)
		if err != nil {
			log.Warn().Err(err).Str("node", assoc.ID).Msg("Enhanced release preparation awaits delivery capacity")
			return nil
		}
		return []admittedRequest{*request}
	}
	if len(assoc.Sessions) != 0 && !now.Before(assoc.cleanupNext) {
		conn.cleanupAssociationLocked(assoc, now)
	}
	if len(assoc.Sessions) != 0 || conn.terminalError != nil {
		return nil
	}
	for _, release := range conn.localReleases {
		if release.association == assoc {
			return nil
		}
	}
	request, err := conn.prepareEnhancedAssociationRequestLocked(assoc, false, now, true)
	if err != nil {
		log.Warn().Err(err).Str("node", assoc.ID).Msg("Enhanced release completion awaits delivery capacity")
		return nil
	}
	return []admittedRequest{*request}
}

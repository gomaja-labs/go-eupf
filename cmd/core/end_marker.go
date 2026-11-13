package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

const maxPendingEndMarkers = 1024

var endMarkerFailures = promauto.NewCounter(prometheus.CounterOpts{
	Name: "upf_gtp_end_marker_failures_total", Help: "End Markers canceled or not transmitted after a committed path switch",
})

type endMarker struct {
	source, destination net.IP
	teid                uint32
}
type endMarkerSender struct {
	mu         sync.Mutex
	closed     bool
	send       func(endMarker) error
	slots      chan struct{}
	jobs       chan *endMarkerBatch
	stop, done chan struct{}
}
type endMarkerBatch struct {
	sender  *endMarkerSender
	packets []endMarker
	once    sync.Once
}

func newEndMarkerSender() *endMarkerSender {
	s := &endMarkerSender{slots: make(chan struct{}, maxPendingEndMarkers), jobs: make(chan *endMarkerBatch, maxPendingEndMarkers), stop: make(chan struct{}), done: make(chan struct{}), send: sendEndMarker}
	go s.run()
	return s
}
func (s *endMarkerSender) reserve(packets []endMarker) (*endMarkerBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, net.ErrClosed
	}
	b := &endMarkerBatch{sender: s}
	for _, packet := range packets {
		select {
		case s.slots <- struct{}{}:
			b.packets = append(b.packets, packet)
		default:
			b.release()
			return nil, ebpf.ErrRuleCapacity
		}
	}
	return b, nil
}
func (b *endMarkerBatch) release() {
	b.once.Do(func() {
		for range b.packets {
			<-b.sender.slots
		}
	})
}
func (b *endMarkerBatch) submit() error {
	s := b.sender
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		endMarkerFailures.Add(float64(len(b.packets)))
		b.release()
		return nil
	}
	// Each job owns at least one reserved slot, so this bounded send cannot block.
	s.jobs <- b
	return nil
}
func (s *endMarkerSender) run() {
	defer func() {
		for {
			select {
			case b := <-s.jobs:
				endMarkerFailures.Add(float64(len(b.packets)))
				b.release()
			default:
				close(s.done)
				return
			}
		}
	}()
	for {
		select {
		case <-s.stop:
			return
		case b := <-s.jobs:
			for index, packet := range b.packets {
				select {
				case <-s.stop:
					endMarkerFailures.Add(float64(len(b.packets) - index))
					b.release()
					return
				default:
				}
				if err := s.send(packet); err != nil {
					endMarkerFailures.Inc()
					log.Warn().Err(err).Uint32("teid", packet.teid).Msg("Send End Marker after path switch")
				}
			}
			b.release()
		}
	}
}
func (s *endMarkerSender) close() {
	s.mu.Lock()
	s.closed = true
	close(s.stop)
	s.mu.Unlock()
	<-s.done
}

// TS 29.281 V19.2.0 clauses 4.4.2.6, 4.4.3.6 and 7.3.2:
// use the old tunnel's addresses/ports and TEID, with no T-PDU or Private IE.
// Ordinary N3/N9/EPC End Markers have no PDU Session Container.
func sendEndMarker(packet endMarker) error {
	listen := net.ListenConfig{Control: reuseGTPSourcePort}
	socket, err := listen.ListenPacket(context.Background(), "udp4", net.JoinHostPort(packet.source.String(), fmt.Sprint(gtpTunnelSourcePort(packet.teid))))
	if err != nil {
		return fmt.Errorf("open End Marker source: %w", err)
	}
	defer func() { _ = socket.Close() }()
	if err := socket.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		return fmt.Errorf("bound End Marker send: %w", err)
	}
	wire := [8]byte{0x30, 254}
	binary.BigEndian.PutUint32(wire[4:], packet.teid)
	if _, err := socket.WriteTo(wire[:], &net.UDPAddr{IP: packet.destination, Port: 2152}); err != nil {
		return fmt.Errorf("transmit End Marker: %w", err)
	}
	return nil
}

// TS 29.244 V20.1.0 table 7.5.4.3-1: SNDEM belongs to the
// updated FAR, rather than the top-level Session Modification flags.
func (conn *PfcpConnection) prepareEndMarkers(request *message.SessionModificationRequest, old, next *Session) (*endMarkerBatch, error) {
	var packets []endMarker
	seen := make(map[string]bool)
	for _, update := range request.UpdateFAR {
		fields, err := update.UpdateFAR()
		if err != nil {
			return nil, err
		}
		if fields.UpdateForwardingParameters == nil {
			continue
		}
		forwarding, err := fields.UpdateForwardingParameters.UpdateForwardingParameters()
		if err != nil {
			return nil, err
		}
		if !forwarding.PFCPSMReqFlags.HasSNDEM() {
			continue
		}
		id, err := fields.FARID.FARID()
		if err != nil {
			return nil, err
		}
		before, exists := old.FARs[id]
		after, remains := next.FARs[id]
		if !exists || !remains || before.FarInfo.OuterHeaderCreation&1 == 0 || after.FarInfo.OuterHeaderCreation&1 == 0 {
			continue
		}
		if before.InterfaceTypePresent {
			switch before.InterfaceType {
			case ie.TGPPInterfaceTypeN19, ie.TGPPInterfaceTypeN19mb:
				continue // TS 29.281 V19.2.0 clause 7.3.2.3.
			case ie.TGPPInterfaceTypeN3ForDataForwarding, ie.TGPPInterfaceTypeN9DataForwarding:
				// Inter-system data forwarding requires E-RAB/QFI context;
				// do not send a container-free marker on such a tunnel.
				return nil, &ruleFailure{ie.RuleIDTypeFAR, id, unsupportedRuleIE(ie.PFCPSMReqFlags)}
			}
		}
		a, b := before.FarInfo, after.FarInfo
		if a.Teid == b.Teid && a.RemoteIP == b.RemoteIP {
			continue
		}
		destination := make(net.IP, 4)
		binary.LittleEndian.PutUint32(destination, a.RemoteIP)
		sources, err := conn.oldTunnelSources(old, id, before)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			key := fmt.Sprintf("%s/%s/%d", source, destination, a.Teid)
			if seen[key] {
				continue
			}
			seen[key] = true
			packets = append(packets, endMarker{source, destination, a.Teid})
		}
	}
	if len(packets) == 0 {
		return nil, nil
	}
	if conn.endMarkers == nil {
		conn.endMarkers = newEndMarkerSender()
	}
	return conn.endMarkers.reserve(packets)
}

func (conn *PfcpConnection) commitEndMarkers(batch *endMarkerBatch) {
	if batch == nil {
		return
	}
	// Publication is committed before this barrier is enqueued. No old-path
	// XDP invocation remains when submit runs. TS 29.281 clause 7.3.2.2/.3.
	if graced, ok := conn.mapOperations.(interface{ AfterRuleGrace(func() error) error }); ok {
		if err := graced.AfterRuleGrace(batch.submit); err != nil {
			batch.release()
			endMarkerFailures.Add(float64(len(batch.packets)))
			log.Error().Err(err).Msg("Schedule End Marker grace period")
		}
		return
	}
	// Controllers without asynchronous reclamation still obey the barrier.
	if err := conn.mapOperations.SynchronizeRules(); err != nil {
		batch.release()
		endMarkerFailures.Add(float64(len(batch.packets)))
		log.Error().Err(err).Msg("Synchronize End Marker path")
		return
	}
	_ = batch.submit()
}

// TS 29.244 V20.1.0 clause 5.6.3: a null interface label removes it.
func retainFarInterfaceType(value *ie.IE, far *SFarInfo) error {
	if value == nil {
		return nil
	}
	if isNullIE(value) {
		far.InterfaceType, far.InterfaceTypePresent = 0, false
		return nil
	}
	typ, err := value.TGPPInterfaceType()
	if err != nil {
		return err
	}
	// TS 29.244 V20.1.0 table 8.2.118-1: 32..63 are spare.
	// Clause 7.6.8 continues processing without applying spare values.
	if typ >= 32 {
		return nil
	}
	far.InterfaceType, far.InterfaceTypePresent = typ, true
	return nil
}

// Match the existing data-plane source selection for each old ingress path:
// native N6 and CP-originated re-encapsulation use N3; ordinary GTP relay
// uses N9 unless forwarding towards the CP function. A shared FAR can serve
// both paths, requiring one marker for each distinct old local endpoint.
// TS 29.281 V19.2.0 clause 4.4.3.6 requires the tunnel's same source address.
func (conn *PfcpConnection) oldTunnelSources(session *Session, id uint32, far SFarInfo) ([]net.IP, error) {
	native, relay := false, false
	for _, pdr := range session.PDRs {
		if pdr.FARID != nil {
			if *pdr.FARID != id {
				continue
			}
		} else if far.GlobalId == 0 || pdr.PdrInfo.FarId != far.GlobalId {
			continue
		}
		toCP := far.FarInfo.DestinationInterfacePresent && far.FarInfo.DestinationInterface == ie.DstInterfaceCPFunction
		if pdr.Teid != 0 && pdr.SourceInterface != ie.SrcInterfaceCPFunction && !toCP {
			relay = true
		} else {
			native = true
		}
	}
	if !native && !relay {
		// An inactive FAR has no old readers; retain its configured local role.
		relay = far.FarInfo.DestinationInterfacePresent && far.FarInfo.DestinationInterface == ie.DstInterfaceCore
		native = !relay
	}
	var sources []net.IP
	n3, n9, err := conn.mapOperations.TunnelSourceAddresses()
	if err != nil {
		return nil, err
	}
	if native {
		sources = append(sources, n3)
	}
	if relay {
		sources = append(sources, n9)
	}
	return sources, nil
}

// TS 29.281 V19.2.0 clauses 4.4.2.0 and 4.4.2.6: the same
// per-tunnel source port is used by XDP forwarding and End Markers.
func gtpTunnelSourcePort(teid uint32) uint16 { return 49152 | uint16(teid&0x3fff) }

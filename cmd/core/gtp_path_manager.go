// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/rs/zerolog/log"
)

var errEchoRateLimited = errors.New("GTP Echo path is within the 60-second minimum interval (TS 29.281 V19.2.0 clause 7.2.1)")

type GtpPathManager struct {
	mu            sync.Mutex // Owns configuration, peers and sequence state; never held for I/O.
	runOnce       sync.Once
	updates       chan struct{}
	generation    uint64
	localAddress  string
	peers         map[string]uint16
	checkInterval time.Duration
	lastEcho      map[string]time.Time
	ctx           context.Context
	cancelCtx     context.CancelFunc

	ticker *time.Ticker
}

func NewGtpPathManager(localAddress string, interval time.Duration) *GtpPathManager {
	ctx, cancelCtx := context.WithCancel(context.Background())
	return &GtpPathManager{
		localAddress:  localAddress,
		peers:         map[string]uint16{},
		lastEcho:      map[string]time.Time{},
		checkInterval: interval,
		ctx:           ctx,
		cancelCtx:     cancelCtx,
		updates:       make(chan struct{}, 1),
	}
}

func (gtpPathManager *GtpPathManager) AddGtpPath(gtpPeerAddress string) {
	gtpPathManager.mu.Lock()
	defer gtpPathManager.mu.Unlock()
	if _, exists := gtpPathManager.peers[gtpPeerAddress]; !exists {
		gtpPathManager.peers[gtpPeerAddress] = 0
		gtpPathManager.generation++
	}
}

func (gtpPathManager *GtpPathManager) UpdateGtpPath(gtpPeerAddresses []string) {
	gtpPathManager.mu.Lock()
	defer gtpPathManager.mu.Unlock()
	// Keep recent sends across removal and re-addition, but discard expired history.
	for peer, sent := range gtpPathManager.lastEcho {
		if time.Since(sent) >= time.Minute {
			delete(gtpPathManager.lastEcho, peer)
		}
	}
	newPeers := make(map[string]uint16, len(gtpPeerAddresses))

	for _, peerAddress := range gtpPeerAddresses {
		newPeers[peerAddress] = gtpPathManager.peers[peerAddress]
	}

	gtpPathManager.peers = newPeers
	gtpPathManager.generation++
}

func (gtpPathManager *GtpPathManager) UpdateCheckTicker(newTicker *time.Ticker) {
	if newTicker == nil {
		return
	}
	gtpPathManager.mu.Lock()
	old := gtpPathManager.ticker
	gtpPathManager.ticker = newTicker
	select {
	case <-gtpPathManager.ctx.Done():
		newTicker.Stop()
	default:
	}
	gtpPathManager.mu.Unlock()
	if old != nil {
		old.Stop()
	}
	select {
	case gtpPathManager.updates <- struct{}{}:
	default:
	}
}

func (gtpPathManager *GtpPathManager) UpdateLocalAddress(newLocalAddress string) {
	gtpPathManager.mu.Lock()
	defer gtpPathManager.mu.Unlock()
	gtpPathManager.localAddress = newLocalAddress
}

func (manager *GtpPathManager) Run() {
	manager.runOnce.Do(func() { go manager.run() })
}
func (manager *GtpPathManager) run() {
	manager.mu.Lock()
	if manager.ticker == nil {
		interval := manager.checkInterval
		if interval <= 0 {
			interval = time.Minute
		}
		manager.ticker = time.NewTicker(interval)
	}
	manager.mu.Unlock()
	defer func() { manager.mu.Lock(); manager.ticker.Stop(); manager.mu.Unlock() }()
	for {
		manager.mu.Lock()
		ticker := manager.ticker
		manager.mu.Unlock()
		select {
		case <-manager.ctx.Done():
			return
		case <-manager.updates:
			continue
		case <-ticker.C:
			manager.mu.Lock()
			peers := make(map[string]uint16, len(manager.peers))
			for peer, seq := range manager.peers {
				peers[peer] = seq
			}
			generation := manager.generation
			manager.mu.Unlock()
			for peer, seq := range peers {
				select {
				case <-manager.ctx.Done():
					return
				default:
				}
				if _, err := manager.sendEcho(peer, seq); err != nil {
					if !errors.Is(err, errEchoRateLimited) {
						log.Warn().Err(err).Msg("GTP path probe failed")
					}
					continue
				}
				manager.mu.Lock()
				if manager.generation == generation {
					manager.peers[peer] = seq + 1
				}
				manager.mu.Unlock()
			}
		}
	}
}
func (manager *GtpPathManager) Stop() {
	manager.cancelCtx()
	manager.mu.Lock()
	if manager.ticker != nil {
		manager.ticker.Stop()
	}
	manager.mu.Unlock()
}

func (gtpPathManager *GtpPathManager) sendEcho(gtpPeerAddress string, seq uint16) (time.Duration, error) {
	gtpEchoRequest := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(gtpEchoRequest, gopacket.SerializeOptions{},
		&layers.GTPv1U{
			Version:            1,
			MessageType:        1, // GTPU_ECHO_REQUEST
			MessageLength:      4,
			TEID:               0,
			SequenceNumberFlag: true,
			SequenceNumber:     seq,
		},
	); err != nil {
		return 0, fmt.Errorf("serializing input packet failed: %w", err)
	}

	gtpPathManager.mu.Lock()
	localAddress := gtpPathManager.localAddress
	gtpPathManager.mu.Unlock()
	udpLocalAddr, err := net.ResolveUDPAddr("udp", localAddress)
	if err != nil {
		return 0, fmt.Errorf("can't resolve local UDP address: %w", err)
	}
	udpRemoteAddr, err := net.ResolveUDPAddr("udp", gtpPeerAddress)
	if err != nil {
		return 0, fmt.Errorf("can't resolve remote UDP address: %w", err)
	}
	conn, err := net.DialUDP("udp", udpLocalAddr, udpRemoteAddr)
	if err != nil {
		return 0, fmt.Errorf("can't create UDP connection: %w", err)
	}
	defer func() { _ = conn.Close() }()

	receiveBuffer := make([]byte, 1500)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))

	sendTime := time.Now()
	// TS 29.281 V19.2.0 clause 7.2.1: enforce spacing on each path,
	// including failed probes and ticks queued before a runtime interval edit.
	// No T3-RESPONSE retransmissions are scheduled by this manager.
	path := udpRemoteAddr.String()
	gtpPathManager.mu.Lock()
	if previous, exists := gtpPathManager.lastEcho[path]; exists && sendTime.Sub(previous) < time.Minute {
		gtpPathManager.mu.Unlock()
		return 0, errEchoRateLimited
	}
	gtpPathManager.lastEcho[path] = sendTime
	gtpPathManager.mu.Unlock()
	if _, err := conn.Write(gtpEchoRequest.Bytes()); err != nil {
		return 0, fmt.Errorf("can't send echo request: %w", err)
	}

	n, err := conn.Read(receiveBuffer)
	if err != nil {
		return 0, fmt.Errorf("can't read echo response: %w", err)
	}
	elapsedTime := time.Since(sendTime)

	response := gopacket.NewPacket(receiveBuffer[:n], layers.LayerTypeGTPv1U, gopacket.Default)
	if gtpLayer := response.Layer(layers.LayerTypeGTPv1U); gtpLayer != nil {
		gtp, _ := gtpLayer.(*layers.GTPv1U)

		if gtp.MessageType != 2 { //GTPU_ECHO_RESPONSE
			return 0, fmt.Errorf("unexpected gtp echo response: %d", gtp.MessageType)
		}
		//if gtp.SequenceNumberFlag && gtp.SequenceNumber != seq {
		//	return 0, fmt.Errorf("unexpected gtp echo response sequence: %d", gtp.SequenceNumber)
		//}
		if gtp.TEID != 0 {
			return 0, fmt.Errorf("unexpected gtp echo response TEID: %d", gtp.TEID)
		}
	} else {
		return 0, errors.New("unexpected gtp echo response")
	}

	return elapsedTime, nil
}

package core

import (
	"fmt"
	"net"
)

// listenPFCP leaves room for bursts while final-usage replies complete in
// batches. The OS may clamp this request to its configured receive-buffer limit;
// reliable PFCP delivery still relies on retransmission (TS 29.244 V20.1.0 6.4).
func listenPFCP(address *net.UDPAddr) (*net.UDPConn, error) {
	socket, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, err
	}
	if err := socket.SetReadBuffer(4 << 20); err != nil {
		_ = socket.Close()
		return nil, fmt.Errorf("set PFCP receive buffer: %w", err)
	}
	return socket, nil
}

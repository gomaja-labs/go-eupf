package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestPFCPReceiveSocketHoldsAQueuedHeartbeatBurst(t *testing.T) {
	conn := newProtocolConnection(t)
	peer := identityPeer(t, "127.0.0.43", 0)
	if err := peer.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	const burst = 256
	for sequence := uint32(1); sequence <= burst; sequence++ {
		wire := protocolWire(t, message.NewHeartbeatRequest(sequence, ie.NewRecoveryTimeStamp(time.Now())))
		if _, err := peer.WriteToUDP(wire, conn.socket().LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatal(err)
		}
	}
	// Queue first, then start receiving: a small socket buffer otherwise drops
	// the tail even though the connection never waits for kernel reclamation.
	go conn.Run()
	seen := make(map[uint32]bool)
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for len(seen) < burst {
		buffer := make([]byte, 65535)
		n, _, err := peer.ReadFromUDP(buffer)
		if err != nil {
			t.Fatalf("received %d/%d queued responses: %v", len(seen), burst, err)
		}
		response, err := message.ParseHeartbeatResponse(buffer[:n])
		if err != nil || seen[response.Sequence()] {
			t.Fatalf("invalid or repeated burst response: %v", err)
		}
		seen[response.Sequence()] = true
	}
}

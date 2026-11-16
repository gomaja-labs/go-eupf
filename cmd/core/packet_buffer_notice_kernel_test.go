//go:build linux

package core

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

// TS 29.244 V20.1.0 clause 5.2.3.1: NOCP observes the first DL packet.
// This private fixture bypasses capability admission to isolate packet credits.
func TestDownlinkNotificationWithZeroPacketCount(t *testing.T) {
	for _, count := range []uint8{1, 0} {
		t.Run(map[uint8]string{1: "one_credit_control", 0: "zero_credit"}[count], func(t *testing.T) {
			plane, _, conn, assoc, before, peer := publishPacketBufferFixture(t)
			conn.stateMu.Lock()
			after := cloneSession(before)
			if err := createBAR(after, ie.NewCreateBAR(ie.NewBARID(0), ie.NewSuggestedBufferingPacketsCount(count))); err != nil {
				t.Fatal(err)
			}
			barID := uint8(0)
			far := after.FARs[1]
			far.BARID = &barID
			after.FARs[1] = far
			start, finish := conn.prepareSessionMutation(after, updateSessionMutation, true)
			conn.stagePacketBuffering(assoc, before, after, updateSessionMutation, false)
			if err := start(); err != nil {
				t.Fatal(err)
			}
			if err := finish(true); err != nil {
				t.Fatal(err)
			}
			assoc.Sessions[after.LocalSEID] = after
			conn.stateMu.Unlock()
			capture := startBufferPFCPCapture(t)
			go conn.Run()
			action, _, err := plane.UpfIpEntrypointFunc.Test(bufferKernelPacket(t, 100))
			if err != nil || action != 1 {
				t.Fatalf("first packet action=%d error=%v", action, err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, 65535)
			n, _, readErr := peer.ReadFromUDP(data)
			capture.close()
			if capture.err != nil {
				t.Fatal(capture.err)
			}
			dir := os.Getenv("EUPF_BUFFER_CAPTURE_DIR")
			if dir == "" {
				dir = t.TempDir()
			}
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, t.Name()[len("TestDownlinkNotificationWithZeroPacketCount/"):]+".pcap"), capture.data, 0600); err != nil {
				t.Fatal(err)
			}
			cycle := after.buffers.cycles[1]
			state, err := plane.BufferControl(ebpf.BufferCommand{SessionID: 11, Cookie: cycle.cookie, Lane: cycle.lane, Operation: 3})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("BAR count=%d produced=%d peer_read_error=%v", count, state.Produced, readErr)
			if readErr != nil {
				t.Fatalf("first DL packet produced no NOCP report: %v", readErr)
			}
			parsed, err := message.Parse(data[:n])
			if err != nil {
				t.Fatal(err)
			}
			report, ok := parsed.(*message.SessionReportRequest)
			if !ok || report.DownlinkDataReport == nil {
				t.Fatalf("unexpected report %T", parsed)
			}
			if !peer.LocalAddr().(*net.UDPAddr).IP.Equal(net.ParseIP("127.0.0.92")) {
				t.Fatal("wrong fixture peer")
			}
		})
	}
}

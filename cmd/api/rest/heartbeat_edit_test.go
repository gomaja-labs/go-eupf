package rest

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestRESTHeartbeatTimeoutChangesRetransmission(t *testing.T) {
	t.Chdir(t.TempDir())
	old := config.Conf
	config.Conf = config.UpfConfig{HeartbeatTimeout: 5, HeartbeatRetries: 1, HeartbeatInterval: 5}
	defer func() { config.Conf = old }()
	conn, err := core.NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, testResources(t), nil, nil, core.DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { defer close(stopped); conn.Run() }()
	defer func() { conn.Close(); <-stopped }()
	h := NewApiHandler(nil, map[string]*core.PfcpConnection{"n4": conn}, nil, validEditConfigPtr(), nil, nil, nil)
	r := gin.New()
	r.POST("/timers", h.editPFCPTimersConfig)
	out := httptest.NewRecorder()
	r.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/timers", strings.NewReader(`{"association_setup_timeout":5,"heartbeat_timeout":1}`)))
	if out.Code != 200 {
		t.Fatalf("status=%d body=%s", out.Code, out.Body)
	}
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	// TS 29.244 V20.1.0 clause 6.4: the retry uses the edited T1 interval
	// and retains the original request bytes and sequence number.
	if err = conn.SendMessageWithTrace(message.NewHeartbeatRequest(0, ie.NewRecoveryTimeStamp(time.Unix(1700000000, 0))), peer.LocalAddr().(*net.UDPAddr), false); err != nil {
		t.Fatal(err)
	}
	read := func() []byte {
		t.Helper()
		if err := peer.SetReadDeadline(time.Now().Add(2500 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1500)
		n, _, err := peer.ReadFromUDP(b)
		if err != nil {
			t.Fatal(err)
		}
		return b[:n]
	}
	first := read()
	msg, err := message.Parse(first)
	if err != nil || msg.MessageType() != message.MsgTypeHeartbeatRequest {
		t.Fatalf("heartbeat=%v error=%v", msg, err)
	}
	start := time.Now()
	retry := read()
	elapsed := time.Since(start)
	if !bytes.Equal(first, retry) {
		t.Fatal("retransmission changed request")
	}
	if elapsed < 800*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatalf("edited timeout not observed: %v", elapsed)
	}
}

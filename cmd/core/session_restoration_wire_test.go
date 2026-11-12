//go:build linux

package core

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestSessionRestorationWireInputs(t *testing.T) {
	old := config.Conf
	config.Conf = config.UpfConfig{FeatureUEIP: true, UEIPPool: "192.0.2.0/30"}
	t.Cleanup(func() { config.Conf = old })
	resources, err := service.NewResourceManager("192.0.2.0/30", 0)
	if err != nil {
		t.Fatal(err)
	}
	address := "127.0.0.1:0"
	captureDir := os.Getenv("EUPF_PFCP_CAPTURE_DIR")
	if captureDir != "" {
		address = "127.0.0.1:8805"
	}
	conn, err := NewPfcpConnection(address, "127.0.0.1", "127.0.0.1", "127.0.0.1", &MapOperationsMock{}, resources, nil, nil, DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if captureDir != "" {
		captureRestorationPFCP(t, captureDir)
	}
	setup := message.NewAssociationSetupRequest(1, ie.NewNodeIDFQDN("synthetic.example"), ie.NewRecoveryTimeStamp(time.Unix(100, 0)))
	if reply := exchangeProtocolDatagram(t, conn, protocolWire(t, setup)); reply == nil {
		t.Fatal("no setup response")
	}
	request := func(seq uint32, stamp int64, chosen string, restoration bool) *message.SessionEstablishmentRequest {
		var addressIE *ie.IE
		if chosen == "" {
			addressIE = ie.NewUEIPAddress(20, "", "", 0, 0)
		} else {
			addressIE = ie.NewUEIPAddress(6, chosen, "", 0, 0)
		}
		req := message.NewSessionEstablishmentRequest(0, seq, ie.NewNodeIDFQDN("synthetic.example"), ie.NewFSEID(uint64(seq), net.ParseIP("127.0.0.1"), nil), ie.NewRecoveryTimeStamp(time.Unix(stamp, 0)), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(1)), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), addressIE), ie.NewFARID(1)))
		if restoration {
			req.PFCPSEReqFlags = ie.NewPFCPSEReqFlags(1)
		}
		return req
	}
	first := exchangeProtocolDatagram(t, conn, protocolWire(t, request(10, 10, "", false))).(*message.SessionEstablishmentResponse)
	if cause, _ := first.Cause.Cause(); cause != 1 {
		t.Fatal(cause)
	}
	original, _ := first.UPFSEID.FSEID()
	fields, _ := first.CreatedPDR[0].CreatedPDR()
	chosen, _ := fields.UEIPAddress[0].UEIPAddress()
	collision := exchangeProtocolDatagram(t, conn, protocolWire(t, request(20, 10, chosen.IPv4Address.String(), true))).(*message.SessionEstablishmentResponse)
	if cause, _ := collision.Cause.Cause(); cause != ie.CauseSessionRestorationResourceUnavailable {
		t.Fatalf("occupied restoration cause=%d", cause)
	}
	if reply := exchangeProtocolDatagram(t, conn, protocolWire(t, request(30, 9, "", false))); reply != nil {
		t.Fatal("stale timestamp was not discarded")
	}
	restored := exchangeProtocolDatagram(t, conn, protocolWire(t, request(40, 11, chosen.IPv4Address.String(), true))).(*message.SessionEstablishmentResponse)
	if cause, _ := restored.Cause.Cause(); cause != 1 {
		t.Fatalf("available restoration cause=%d", cause)
	}
	current, _ := restored.UPFSEID.FSEID()
	assoc := conn.GetAssociation("127.0.0.1")
	if current.SEID == original.SEID || len(assoc.Sessions) != 1 || assoc.Sessions[original.SEID] != nil || assoc.Sessions[current.SEID] == nil {
		t.Fatal("restart failed to replace the entity's old session")
	}
}

func captureRestorationPFCP(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0750); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "tcpdump.log")
	output, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	capture := exec.Command("tcpdump", "-U", "--immediate-mode", "-i", "lo", "-w", filepath.Join(directory, "restoration.pcap"), "udp", "port", "8805")
	capture.Stdout, capture.Stderr = output, output
	if err := capture.Start(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = capture.Process.Signal(syscall.SIGINT)
		if err := capture.Wait(); err != nil {
			t.Error(err)
		}
		_ = output.Close()
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "listening on lo") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tcpdump did not become ready")
}

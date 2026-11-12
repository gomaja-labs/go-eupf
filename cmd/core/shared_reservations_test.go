package core

import (
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type reservationBarrierMaps struct {
	MapOperationsMock
	started chan struct{}
	release <-chan struct{}
}

func (m *reservationBarrierMaps) BeginRuleTransaction(id uint64) (ebpf.RuleTransaction, error) {
	close(m.started)
	<-m.release
	return m.MapOperationsMock.BeginRuleTransaction(id)
}
func TestPFCPInterfacesSerializeSharedReservationViews(t *testing.T) {
	old := config.Conf
	config.Conf.FeatureUEIP = true
	t.Cleanup(func() { config.Conf = old })
	resources, _ := service.NewResourceManager("192.0.2.0/29", 0)
	release := make(chan struct{})
	started := []chan struct{}{make(chan struct{}), make(chan struct{})}
	results := make(chan net.IP, 2)
	run := func(index int) {
		maps := &reservationBarrierMaps{started: started[index], release: release}
		conn, peer := PreparePfcpConnectionWithMock(t, maps, config.UpfConfig{FeatureUEIP: true})
		conn.ResourceManager = resources
		req := message.NewSessionEstablishmentRequest(0, uint32(index+1), ie.NewNodeIDFQDN("test"), ie.NewFSEID(uint64(index+1), net.ParseIP(peer), nil), ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(2), ie.NewForwardingParameters(ie.NewDestinationInterface(0), ie.NewOuterHeaderCreation(0x100, 100, "198.51.100.1", "", 0, 0, 0))), ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), ie.NewPDI(ie.NewSourceInterface(1), ie.NewUEIPAddress(20, "", "", 0, 0)), ie.NewFARID(1)))
		conn.stateMu.Lock()
		reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, req, peer)
		conn.stateMu.Unlock()
		if err != nil {
			t.Error(err)
			results <- nil
			return
		}
		response := reply.(*message.SessionEstablishmentResponse)
		if len(response.CreatedPDR) == 0 {
			t.Errorf("no allocation: %+v", response)
			results <- nil
			return
		}
		f, _ := response.CreatedPDR[0].CreatedPDR()
		address, _ := f.UEIPAddress[0].UEIPAddress()
		results <- address.IPv4Address
	}
	go run(0)
	select {
	case <-started[0]:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first request did not begin")
	}
	go run(1)
	// The second request must wait outside its reservation snapshot. An unfixed
	// implementation reaches Begin with a snapshot of the same free address.
	select {
	case <-started[1]:
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	var addresses []net.IP
	for range 2 {
		select {
		case ip := <-results:
			addresses = append(addresses, ip)
		case <-time.After(time.Second):
			t.Fatal("request remained blocked")
		}
	}
	if addresses[0] == nil || addresses[1] == nil || addresses[0].Equal(addresses[1]) {
		t.Fatalf("interfaces allocated the same UE address: %v", addresses)
	}
}

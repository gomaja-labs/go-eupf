package core

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
)

func TestAssociationSetupUsesStartupTimeout(t *testing.T) {
	old := config.Conf
	config.Conf.AssociationSetupTimeout = 1
	defer func() { config.Conf = old }()
	conn, err := NewPfcpConnection("127.0.0.1:0", "127.0.0.1", "127.0.0.1", "127.0.0.1", nil, emptyResources(t), nil, nil, DefaultProfile{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-conn.associationTicker().C:
	case <-time.After(1600 * time.Millisecond):
		t.Fatal("startup association_setup_timeout was ignored")
	}
}

func TestInterfaceEditUsesCandidateAdvertisedAddresses(t *testing.T) {
	old := config.Conf
	t.Cleanup(func() { config.Conf = old })
	conn := newProtocolConnection(t)
	conn.UpdateN3Address(net.ParseIP("198.51.100.1"))
	conn.UpdateN9Address(net.ParseIP("198.51.100.2"))
	sxa, sxb := newProtocolConnection(t), newProtocolConnection(t)
	sxa.UpdateN3Address(net.ParseIP("198.51.100.3"))
	sxa.UpdateN9Address(net.ParseIP("198.51.100.4"))
	sxb.UpdateN3Address(net.ParseIP("198.51.100.5"))
	manager := NewGtpPathManager("127.0.0.1:2152", time.Minute)
	defer manager.Stop()
	next := &config.UpfConfig{N3Address: "192.0.2.1", N9Address: "192.0.2.2", N3AdvertisedAddress: "192.0.2.1", N9AdvertisedAddress: "198.51.100.2"}
	if err := UpdateDataPlaneAddresses(map[string]*PfcpConnection{N4PFCPKeyName: conn, SxaPFCPKeyName: sxa, SxbPFCPKeyName: sxb}, manager, next); err != nil {
		t.Fatal(err)
	}
	if conn.GetN3Addr() != "192.0.2.1" || conn.GetN9Addr() != "198.51.100.2" {
		t.Fatal("interface edit did not follow the candidate advertised addresses")
	}
	if sxa.GetN3Addr() != "198.51.100.3" || sxa.GetN9Addr() != "198.51.100.4" || sxb.GetN3Addr() != "198.51.100.5" {
		t.Fatal("N3/N9 edit changed Sxa/Sxb advertised addresses")
	}
}
func TestEndpointPersistenceFailurePreservesState(t *testing.T) {
	conn := newProtocolConnection(t)
	before := conn.GetLocalAddr()
	sentinel := errors.New("cannot persist")
	err := UpdatePFCPConnectionsAndPersist(map[string]*PfcpConnection{"n4": conn}, "n4", "127.0.0.1:0", "changed.example", nil, func() error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("error=%v", err)
	}
	if conn.GetLocalAddr() != before || conn.nodeId == "changed.example" {
		t.Fatal("failed persistence changed endpoint or identity")
	}
}
func TestEndpointConnectorFailurePreservesState(t *testing.T) {
	conn := newProtocolConnection(t)
	before := conn.GetLocalAddr()
	err := UpdatePFCPConnections(map[string]*PfcpConnection{"n4": conn}, "n4", "127.0.0.1:0", "changed.example", []string{"bad host name"})
	if err == nil {
		t.Fatal("invalid connector accepted")
	}
	if conn.GetLocalAddr() != before || conn.nodeId == "changed.example" {
		t.Fatal("failed preparation changed endpoint or identity")
	}
}

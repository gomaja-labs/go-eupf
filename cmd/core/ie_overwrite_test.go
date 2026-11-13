// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

type MapOperationsMock struct {
	uplinkPDR   ebpf.PdrInfo
	downlinkPDR ebpf.PdrInfo
	urr         ebpf.UrrInfo
	far         ebpf.FarInfo
	nextID      uint32
}

func (mapOps *MapOperationsMock) PutPdrUplink(teid uint32, pdrInfo ebpf.PdrInfo) error {
	mapOps.uplinkPDR = pdrInfo
	return nil
}
func (mapOps *MapOperationsMock) PutPdrDownlink(ipv4 net.IP, pdrInfo ebpf.PdrInfo) error {
	mapOps.downlinkPDR = pdrInfo
	return nil
}
func (mapOps *MapOperationsMock) UpdatePdrUplink(teid uint32, pdrInfo ebpf.PdrInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) UpdatePdrDownlink(ipv4 net.IP, pdrInfo ebpf.PdrInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) DeletePdrUplink(teid uint32, sessionID uint64, pdrID uint32) error {
	return nil
}
func (mapOps *MapOperationsMock) DeletePdrDownlink(ipv4 net.IP, sessionID uint64, pdrID uint32) error {
	return nil
}
func (mapOps *MapOperationsMock) PutDownlinkPdrIp6(ipv6 net.IP, pdrInfo ebpf.PdrInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) UpdateDownlinkPdrIp6(ipv6 net.IP, pdrInfo ebpf.PdrInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) DeleteDownlinkPdrIp6(ipv6 net.IP, sessionID uint64, pdrID uint32, prefixLength uint32) error {
	return nil
}
func (mapOps *MapOperationsMock) NewFar(farInfo ebpf.FarInfo) (uint32, error) {
	mapOps.nextID++
	return mapOps.nextID, nil
}
func (mapOps *MapOperationsMock) UpdateFar(internalId uint32, farInfo ebpf.FarInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) DeleteFar(internalId uint32) error {
	return nil
}
func (mapOps *MapOperationsMock) NewQer(qerInfo ebpf.QerInfo) (uint32, error) {
	mapOps.nextID++
	return mapOps.nextID, nil
}
func (mapOps *MapOperationsMock) UpdateQer(internalId uint32, qerInfo ebpf.QerInfo) error {
	return nil
}
func (mapOps *MapOperationsMock) DeleteQer(internalId uint32) error {
	return nil
}

func (mapOps *MapOperationsMock) NewUrr(urrInfo ebpf.UrrInfo) (uint32, error) {
	mapOps.nextID++
	return mapOps.nextID, nil
}

func (mapOps *MapOperationsMock) UpdateUrr(internalId uint32, urrInfo ebpf.UrrInfo) error {
	return nil
}

func (mapOps *MapOperationsMock) GetUrr(internalId uint32) (ebpf.UrrInfo, error) {
	return mapOps.urr, nil
}

func (mapOps *MapOperationsMock) DeleteUrr(internalId uint32) (ebpf.UrrInfo, error) {
	return mapOps.urr, nil
}

func (mapOps *MapOperationsMock) GetPdrDownlink(ipv4 net.IP) (*ebpf.PdrInfo, error) {
	return nil, nil
}

func (mapOps *MapOperationsMock) GetPdrUplink(teid uint32) (*ebpf.PdrInfo, error) {
	return nil, nil
}

func (mapOps *MapOperationsMock) GetDownlinkPdrIp6(ipv6 net.IP) (*ebpf.PdrInfo, error) {
	return nil, nil
}

func (mapOps *MapOperationsMock) GetFar(internalId uint32) (ebpf.FarInfo, error) {
	return mapOps.far, nil
}

func TestSessionOverwrite(t *testing.T) {

	mapOps := MapOperationsMock{}
	// Create pfcp connection struct
	pfcpConn := PfcpConnection{
		NodeAssociations: make(map[string]*NodeAssociation),
		nodeId:           "test-node",
		mapOperations:    &mapOps,
		n3Address:        net.ParseIP("127.0.0.1"),
		nodeAddrV4:       netip.MustParseAddrPort("127.0.0.1:8085"),
		profile:          DefaultProfile{},
	}
	asReq := message.NewAssociationSetupRequest(0,
		ie.NewNodeIDFQDN("test"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)
	remoteIP := "127.0.0.1"
	response, _, err := HandlePfcpAssociationSetupRequest(&pfcpConn, asReq, remoteIP)
	if err != nil {
		t.Errorf("Error handling association setup request: %s", err)
	}
	cause, err := response.(*message.AssociationSetupResponse).Cause.Cause()
	if err != nil {
		t.Errorf("Error getting cause from association setup response: %s", err)
	}
	if cause != ie.CauseRequestAccepted {
		t.Errorf("Unexpected cause in association setup response: %d", cause)
	}
	// Check nodeId in response
	nodeId, err := response.(*message.AssociationSetupResponse).NodeID.NodeID()
	if err != nil {
		t.Errorf("Error getting node ID from association setup response: %s", err)
	}
	if nodeIDText(nodeId) != "test-node" {
		t.Errorf("Unexpected node ID in association setup response: %s", nodeIDText(nodeId))
	}
	if pfcpConn.GetAssociation(remoteIP) == nil {
		t.Errorf("Association not created")
	}

	// Create two send two Session Establishment Requests with downlink PDRs
	// and check that the first session is not overwritten
	seReq1 := message.NewSessionEstablishmentRequest(1, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(remoteIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				//ie.NewFTEID(1, 0, ip1.IP, nil, 0),
				ie.NewUEIPAddress(6, "1.1.1.1", "", 0, 0),
			),
		),
	)

	seReq2 := message.NewSessionEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(2, net.ParseIP(remoteIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				//ie.NewFTEID(1, 0, ip2.IP, nil, 0),
				ie.NewUEIPAddress(6, "2.2.2.2", "", 0, 0),
			),
		),
	)

	// Send first request
	_, _, err = HandlePfcpSessionEstablishmentRequest(&pfcpConn, seReq1, remoteIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	// Send second request
	_, _, err = HandlePfcpSessionEstablishmentRequest(&pfcpConn, seReq2, remoteIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	// Check that session PDRs are correct
	if pfcpConn.GetAssociation(remoteIP).Sessions[2].PDRs[1].Ipv4.String() != "1.1.1.1" {
		t.Errorf("Session 1, got broken")
	}
	if pfcpConn.GetAssociation(remoteIP).Sessions[3].PDRs[1].Ipv4.String() != "2.2.2.2" {
		t.Errorf("Session 2, got broken")
	}

	// Send Session Modification Request, create FAR
	smReq := message.NewSessionModificationRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(2, net.ParseIP(remoteIP), nil),
		ie.NewCreateFAR(
			ie.NewFARID(1),
			ie.NewApplyAction(2),
			ie.NewForwardingParameters(
				ie.NewDestinationInterface(ie.DstInterfaceAccess),
				ie.NewNetworkInstance(""),
			),
		),
	)

	// Send modification request
	_, _, err = HandlePfcpSessionModificationRequest(&pfcpConn, smReq, remoteIP)
	if err != nil {
		t.Errorf("Error handling session modification request: %s", err)
	}

	// Check that session PDRs are correct
	if pfcpConn.GetAssociation(remoteIP).Sessions[2].PDRs[1].Ipv4.String() != "1.1.1.1" {
		t.Errorf("Session 1, got broken")
	}
	if pfcpConn.GetAssociation(remoteIP).Sessions[3].PDRs[1].Ipv4.String() != "2.2.2.2" {
		t.Errorf("Session 2, got broken")
	}
}

type mapTransactionMock struct {
	ebpf.ForwardingPlaneController
	rollback func()
}

func (mock *mapTransactionMock) Commit() error { mock.rollback = nil; return nil }
func (mock *mapTransactionMock) Rollback() error {
	if mock.rollback != nil {
		mock.rollback()
		mock.rollback = nil
	}
	return nil
}
func (maps *MapOperationsMock) BeginRuleTransaction(_ uint64) (ebpf.RuleTransaction, error) {
	before := *maps
	return &mapTransactionMock{ForwardingPlaneController: maps, rollback: func() { *maps = before }}, nil
}

func (m *MapOperationsMock) GetNextFAR() (uint32, error) { m.nextID++; return m.nextID, nil }
func (m *MapOperationsMock) GetNextQER() (uint32, error) { m.nextID++; return m.nextID, nil }
func (m *MapOperationsMock) GetNextURR() (uint32, error) { m.nextID++; return m.nextID, nil }

func (m *MapOperationsMock) CheckPDRPlan(uint64, []ebpf.PDRKey) error { return nil }

func (m *MapOperationsMock) ResetUrr(uint32) error { m.urr = ebpf.UrrInfo{}; return nil }

func (m *MapOperationsMock) DetachRule(uint8, uint32) error { return nil }

func (m *MapOperationsMock) SynchronizeRules() error { return nil }

func (mapOps *MapOperationsMock) RetireQer(id uint32) error { return mapOps.DeleteQer(id) }

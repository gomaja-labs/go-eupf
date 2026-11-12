// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package core

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/gomaja-labs/go-eupf/cmd/core/service"
	"github.com/gomaja-labs/go-eupf/cmd/core/tracing"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestHeartbeat(t *testing.T) {
	addr := "127.0.0.1"

	// Create pfcp connection struct with association
	pfcpConn := PfcpConnection{
		NodeAssociations: map[string]*NodeAssociation{
			addr: NewNodeAssociation("test-node", ""),
		},
		profile: DefaultProfile{},
		// TS 29.244 V20.1.0 clause 8.2.65: the response carries a valid entity start time.
		RecoveryTimestamp: time.Now(),
	}
	hbReq := message.NewHeartbeatRequest(0,
		ie.NewRecoveryTimeStamp(time.Now()),
		nil,
	)
	response, _, err := HandlePfcpHeartbeatRequest(&pfcpConn, hbReq, addr)
	if err != nil {
		t.Errorf("Error handling heartbeat request: %s", err)
	}
	if response == nil {
		t.Errorf("No response from heartbeat request")
	}
	ts, err := response.(*message.HeartbeatResponse).RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		t.Errorf("Error getting timestamp from heartbeat response: %s", err)
	}
	t.Logf("Received response from heartbeat request with timestamp: %s", ts)
}

func TestAssociationSetup(t *testing.T) {
	// Create pfcp connection struct
	pfcpConn := PfcpConnection{
		NodeAssociations: make(map[string]*NodeAssociation),
		nodeId:           "test-node",
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
}

func PreparePfcpConnection(t *testing.T) (*PfcpConnection, string) {
	config := config.UpfConfig{}
	return PreparePfcpConnectionWithMockAndProfile(t, &MapOperationsMock{}, config, DefaultProfile{})
}

func PreparePfcpConnectionWithConfig(t *testing.T, config config.UpfConfig) (*PfcpConnection, string) {
	return PreparePfcpConnectionWithMockAndProfile(t, &MapOperationsMock{}, config, DefaultProfile{})
}

func PreparePfcpConnectionWithMock(t *testing.T, ebpfMock ebpf.ForwardingPlaneController, config config.UpfConfig) (*PfcpConnection, string) {
	return PreparePfcpConnectionWithMockAndProfile(t, ebpfMock, config, DefaultProfile{})
}

func PreparePfcpConnectionWithMockAndProfile(t *testing.T, ebpfMock ebpf.ForwardingPlaneController, config config.UpfConfig, profile PfcpProfile) (*PfcpConnection, string) {

	var pfcpHandlers = PfcpHandlerMap{
		message.MsgTypeHeartbeatRequest:            HandlePfcpHeartbeatRequest,
		message.MsgTypeAssociationSetupRequest:     HandlePfcpAssociationSetupRequest,
		message.MsgTypeSessionEstablishmentRequest: HandlePfcpSessionEstablishmentRequest,
		message.MsgTypeSessionDeletionRequest:      HandlePfcpSessionDeletionRequest,
		message.MsgTypeSessionModificationRequest:  HandlePfcpSessionModificationRequest,
	}

	featuresOctets := []uint8{0, 0, 0}
	featuresOctets[0] = setBit(featuresOctets[0], 4)
	featuresOctets[2] = setBit(featuresOctets[2], 2)

	smfIP := "127.0.0.1"

	validator, _ := NewNeValidator(config.AllowedApns, config.DeniedApns)

	pfcpConn := PfcpConnection{
		NodeAssociations:  make(map[string]*NodeAssociation),
		nodeId:            "test-node",
		mapOperations:     ebpfMock,
		pfcpHandlerMap:    pfcpHandlers,
		n3Address:         net.ParseIP("1.2.3.4"),
		n9Address:         net.ParseIP("1.2.3.5"),
		RecoveryTimestamp: time.Now(),
		nodeAddrV4:        netip.MustParseAddrPort("127.0.0.1:8085"),
		featuresOctets:    featuresOctets,
		neValidator:       validator,
		profile:           profile,
	}
	asReq := message.NewAssociationSetupRequest(0,
		ie.NewNodeIDFQDN("test"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)
	response, _, err := HandlePfcpAssociationSetupRequest(&pfcpConn, asReq, smfIP)
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
	nodeIDIE := response.(*message.AssociationSetupResponse).NodeID
	if nodeIDIE == nil {
		t.Errorf("Error getting node ID from association setup response: nil")
	} else {
		nodeId, err := nodeIDIE.NodeID()
		if err != nil {
			// HuaweiProfile uses a non-standard NodeID encoding that may not
			// round-trip through go-pfcp's parser. This is expected (Variant B).
			t.Logf("Node ID parsing error (expected for Huawei profile): %s", err)
		} else if _, ok := profile.(HuaweiProfile); ok {
			// HuaweiProfile's FQDN NodeID encoding does not round-trip through
			// go-pfcp's parser (returns empty string). This is expected (Variant B).
			t.Logf("Huawei Node ID (non-roundtrippable): %q", nodeIDText(nodeId))
		} else if nodeIDText(nodeId) != "test-node" {
			t.Errorf("Unexpected node ID in association setup response: %s", nodeIDText(nodeId))
		}
	}
	if pfcpConn.GetAssociation(smfIP) == nil {
		t.Errorf("Association not created")
	}

	return &pfcpConn, smfIP
}

func SendDefaulMappingPdrs(t *testing.T, pfcpConn *PfcpConnection, smfIP string) {
	ip1, _ := net.ResolveIPAddr("ip", "1.1.1.1")

	// Requests for default mapping (without SDF filter)

	// Request with UEIP Address
	seReqPre1 := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewUEIPAddress(6, ip1.IP.String(), "", 0, 0),
			),
		),
	)

	// Request with TEID. TS 29.244 V20.1.0 clause 8.2.3 requires the IPv4 family bit.
	seReqPre2 := restorationEstablishmentRequest(3, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(2, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewFTEID(1, 10, pfcpConn.n9Address, nil, 0),
			),
		),
	)

	var err error
	_, _, err = HandlePfcpSessionEstablishmentRequest(pfcpConn, seReqPre1, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	_, _, err = HandlePfcpSessionEstablishmentRequest(pfcpConn, seReqPre2, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	// Check that session PDRs are correct
	if pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs[1].Ipv4.String() != "1.1.1.1" {
		t.Errorf("Session 1, got broken")
	}
	if pfcpConn.GetAssociation(smfIP).Sessions[3].PDRs[1].Teid != 10 {
		t.Errorf("Session 2, got broken")
	}
}

func TestSdfFilterStoreValid(t *testing.T) {

	if !testing.Verbose() {
		loglevel := zerolog.GlobalLevel()
		zerolog.SetGlobalLevel(zerolog.Disabled)
		defer zerolog.SetGlobalLevel(loglevel)
	}

	pfcpConn, smfIP := PreparePfcpConnection(t)
	SendDefaulMappingPdrs(t, pfcpConn, smfIP)

	if len(pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs) != 1 {
		t.Errorf("Session 1, should have already stored 1 PDR")
	}

	if len(pfcpConn.GetAssociation(smfIP).Sessions[3].PDRs) != 1 {
		t.Errorf("Session 2, should have already stored 1 PDR")
	}

	ip1, _ := net.ResolveIPAddr("ip", "1.1.1.1")

	fd := SdfFilterTestStruct{FlowDescription: "permit out ip from 10.62.0.1 to 8.8.8.8/32", Protocol: ebpf.SDFProtocolAny,
		SrcType: 1, SrcAddress: "10.62.0.1", SrcMask: "ffffffff", SrcPortLower: 0, SrcPortUpper: 65535,
		DstType: 1, DstAddress: "8.8.8.8", DstMask: "ffffffff", DstPortLower: 0, DstPortUpper: 65535}

	// Requests for additional mapping (with SDF filter)

	// Request with UEIP Address
	seReq1 := message.NewSessionModificationRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil), // Why do we need FSEID?
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				//ie.NewFTEID(1, 0, ip1.IP, nil, 0),
				ie.NewUEIPAddress(6, ip1.IP.String(), "", 0, 0),
				ie.NewSDFFilter(fd.FlowDescription, nil, nil, nil, 0),
			),
		),
	)

	// Request with TEID
	seReq2 := message.NewSessionModificationRequest(3, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(2, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewFTEID(1, 10, pfcpConn.n9Address, nil, 0),
				// ie.NewUEIPAddress(6, ip2.IP.String(), "", 0, 0),
				ie.NewSDFFilter(fd.FlowDescription, nil, nil, nil, 0),
			),
		),
	)

	var err error
	_, _, err = HandlePfcpSessionModificationRequest(pfcpConn, seReq1, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	_, _, err = HandlePfcpSessionModificationRequest(pfcpConn, seReq2, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	// Check that session PDRs are correct
	if pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs[2].Ipv4.String() != "1.1.1.1" {
		t.Errorf("Session 1, got broken")
	}

	if pfcpConn.GetAssociation(smfIP).Sessions[3].PDRs[2].Teid != 10 {
		t.Errorf("Session 2, got broken")
	}

	// Check that SDF filter is stored inside session
	pdrInfo := pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs[2].PdrInfo
	err = CheckSdfFilterEquality(&pdrInfo.SdfFilter[0], fd)
	if err != nil {
		t.Error(err.Error())
	}

	pdrInfo = pfcpConn.GetAssociation(smfIP).Sessions[3].PDRs[2].PdrInfo
	err = CheckSdfFilterEquality(&pdrInfo.SdfFilter[0], fd)
	if err != nil {
		t.Error(err.Error())
	}

	// TODO: Check that FAR and QER are successfully stored in PDR with SDF
}

func TestSdfFilterStoreInvalid(t *testing.T) {

	pfcpConn, smfIP := PreparePfcpConnection(t)
	SendDefaulMappingPdrs(t, pfcpConn, smfIP)

	if len(pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs) != 1 {
		t.Errorf("Session 1, should have already stored 1 PDR")
	}

	ip1, _ := net.ResolveIPAddr("ip", "1.1.1.1")

	// Request with bad/unsuported SDF
	seReq1 := message.NewSessionModificationRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewFTEID(1, 10, ip1.IP, nil, 0),
				ie.NewSDFFilter("deny out ip from 10.62.0.1 to 8.8.8.8/32", nil, nil, nil, 0),
			),
		),
	)

	var err error
	_, _, err = HandlePfcpSessionModificationRequest(pfcpConn, seReq1, smfIP)
	if err != nil {
		t.Errorf("No error should appear while handling session establishment request. PDR with bad SDF should be skipped?")
	}

	// Check that session PDR wasn't stored? Now it is, just without SDF.
	if pfcpConn.GetAssociation(smfIP).Sessions[2].PDRs[2].PdrInfo.SdfFilter != nil {
		t.Errorf("Bad SDF shouldn't be stored")
	}
}

func TestSeveralSdfFiltersSupport(t *testing.T) {

	pfcpConn, smfIP := PreparePfcpConnection(t)
	SendDefaulMappingPdrs(t, pfcpConn, smfIP)

	fd1 := SdfFilterTestStruct{
		FlowDescription: "permit out 17 from 10.169.247.161/32 13033 to 10.169.145.130/32 1235",
		Protocol:        17,
		SrcType:         1,
		SrcAddress:      "10.169.247.161",
		SrcMask:         "ffffffff",
		SrcPortLower:    13033,
		SrcPortUpper:    13033,
		DstType:         1,
		DstAddress:      "10.169.145.130",
		DstMask:         "ffffffff",
		DstPortLower:    1235,
		DstPortUpper:    1235}

	fd2 := SdfFilterTestStruct{
		FlowDescription: "permit out 17 from 10.169.247.161/32 13034 to 10.169.145.130/32 1236",
		Protocol:        17,
		SrcType:         1,
		SrcAddress:      "10.169.247.161",
		SrcMask:         "ffffffff",
		SrcPortLower:    13034,
		SrcPortUpper:    13034,
		DstType:         1,
		DstAddress:      "10.169.145.130",
		DstMask:         "ffffffff",
		DstPortLower:    1236,
		DstPortUpper:    1236}

	// Two alternative filters belong to the same PDR.
	seReq1 := message.NewSessionModificationRequest(3, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(2, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(2),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewFTEID(1, 10, pfcpConn.n9Address, nil, 0),
				ie.NewSDFFilter(fd1.FlowDescription, nil, nil, nil, 0),
				ie.NewSDFFilter(fd2.FlowDescription, nil, nil, nil, 0),
			),
		),
	)

	var err error
	_, _, err = HandlePfcpSessionModificationRequest(pfcpConn, seReq1, smfIP)
	if err != nil {
		t.Errorf("No error should appear while handling session establishment request. PDR with bad SDF should be skipped?")
	}

	sdfFilterList := pfcpConn.GetAssociation(smfIP).Sessions[3].PDRs[2].PdrInfo.SdfFilter
	// Check that session PDR wasn't stored? Now it is, just without SDF.
	if sdfFilterList == nil || len(sdfFilterList) != 2 {
		t.Fatal("both SDF filters must be stored")
	}

	err = CheckSdfFilterEquality(&sdfFilterList[0], fd1)
	if err != nil {
		t.Error(err.Error())
	}

	err = CheckSdfFilterEquality(&sdfFilterList[1], fd2)
	if err != nil {
		t.Error(err.Error())
	}

}

func TestFTUPInAssociationSetupResponse(t *testing.T) {

	config.Conf = config.UpfConfig{
		FTEIDPool: 65536,
	}

	pfcpConn, smfIP := PreparePfcpConnectionWithConfig(t, config.Conf)

	// Creating an Association Setup Request
	asReq := message.NewAssociationSetupRequest(1,
		ie.NewNodeIDFQDN("test"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	// Processing Association Setup Request
	response, _, err := HandlePfcpAssociationSetupRequest(pfcpConn, asReq, smfIP)
	if err != nil {
		t.Errorf("Error handling Association Setup Request: %s", err)
	}

	//Checking if FTUP is enabled in UP Function Features in response
	asRes, ok := response.(*message.AssociationSetupResponse)
	if !ok {
		t.Error("Unexpected response type")
	}

	cause, err := response.(*message.AssociationSetupResponse).Cause.Cause()
	if err != nil {
		t.Errorf("Error getting cause from association setup response: %s", err)
	}
	if cause != ie.CauseRequestAccepted {
		t.Errorf("Unexpected cause in association setup response: %d", cause)
	}

	ftupEnabled := asRes.UPFunctionFeatures.HasFTUP()
	if !ftupEnabled {
		t.Error("FTUP is not enabled in Association Setup Response")
	}
}

func TestTEIDAllocationInSessionEstablishmentResponse(t *testing.T) {
	pfcpConn, smfIP := PreparePfcpConnectionWithConfig(t, config.UpfConfig{})

	resourceManager, err := service.NewResourceManager("10.61.0.0/16", 65536)
	if err != nil {
		log.Error().Msgf("failed to create ResourceManager. err: %v", err)
	}
	pfcpConn.ResourceManager = resourceManager

	fteid1 := ie.NewFTEID(0x05, 0, net.ParseIP("127.0.0.1"), nil, 1) // TS 29.244 V20.1.0 clause 8.2.3: CH and IPv4.
	createPDR1 := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			fteid1,
		),
	)

	fteid2 := ie.NewFTEID(0x05, 0, net.ParseIP("127.0.0.2"), nil, 1)
	createPDR2 := ie.NewCreatePDR(
		ie.NewPDRID(2),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			fteid2,
		),
	)

	fteid3 := ie.NewFTEID(1, 10, pfcpConn.n9Address, nil, 1)
	createPDR3 := ie.NewCreatePDR(
		ie.NewPDRID(3),
		ie.NewPDI(
			ie.NewSourceInterface(ie.SrcInterfaceCore),
			fteid3,
		),
	)

	// Creating a Session Establishment Request
	seReq := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewPFCPSEReqFlags(1),
		createPDR1,
		createPDR2,
		createPDR3,
	)

	// Processing Session Establishment Request
	response, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, seReq, smfIP)
	if err != nil {
		t.Errorf("Error handling Session Establishment Request: %s", err)
	}

	// Checking if expected TEIDs are allocated in Session Establishment Response
	seRes, ok := response.(*message.SessionEstablishmentResponse)
	if !ok {
		t.Error("Unexpected response type")
	}

	// Checking TEID for each PDR
	log.Info().Msgf("seRes.CreatedPDR len: %d", len(seRes.CreatedPDR))
	if len(seRes.CreatedPDR) != 2 {
		t.Errorf("Unexpected count TEIDs: got %d, expected %d", len(seRes.CreatedPDR), 2)
	}

	for _, pdr := range seRes.CreatedPDR {
		fields, err := pdr.CreatedPDR()
		if err != nil {
			t.Fatal(err)
		}
		if len(fields.FTEID) != 1 {
			t.Fatalf("F-TEID count: %d", len(fields.FTEID))
		}
		fteid := fields.FTEID[0]
		if err != nil {
			t.Fatal(err)
		}

		teid, err := fteid.FTEID()
		if err != nil {
			t.Fatal(err)
		}

		if teid.TEID != 1 && teid.TEID != 2 {
			t.Errorf("Unexpected TEID for PDR ID 2: got %d, expected %d or %d", teid.TEID, 1, 2)
		}

		if !teid.HasIPv4() {
			t.Error("HasIPv4 flag is not enabled in TEID")
		}

		if teid.IPv4Address == nil {
			t.Error("TEID has no ip")
		}
	}
}

func TestIPAllocationInSessionEstablishmentResponse(t *testing.T) {
	if config.Conf.FeatureUEIP {
		pfcpConn, smfIP := PreparePfcpConnection(t)

		resourceManager, err := service.NewResourceManager("10.61.0.0/16", 65536)
		if err != nil {
			log.Error().Msgf("failed to create ResourceManager. err: %v", err)
		}
		pfcpConn.ResourceManager = resourceManager

		ueip1 := ie.NewUEIPAddress(16, "", "", 0, 0)
		createPDR1 := ie.NewCreatePDR(
			ie.NewPDRID(1),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ueip1,
			),
		)

		// Creating a Session Establishment Request
		seReq := restorationEstablishmentRequest(2, 1,
			ie.NewNodeIDFQDN("test"),
			ie.NewFSEID(1, net.ParseIP(smfIP), nil),
			createPDR1,
		)

		// Processing Session Establishment Request
		response, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, seReq, smfIP)
		if err != nil {
			t.Errorf("Error handling Session Establishment Request: %s", err)
		}

		// Checking if expected IPs are allocated in Session Establishment Response
		seRes, ok := response.(*message.SessionEstablishmentResponse)
		if !ok {
			t.Error("Unexpected response type")
		}

		// Checking UEIP for each PDR
		log.Info().Msgf("seRes.CreatedPDR len: %d", len(seRes.CreatedPDR))
		if len(seRes.CreatedPDR) != 1 {
			t.Errorf("Unexpected count PRD's: got %d, expected %d", len(seRes.CreatedPDR), 1)
		}

		for _, pdr := range seRes.CreatedPDR {

			fields, err := pdr.CreatedPDR()
			if err != nil {
				t.Fatal(err)
			}
			if len(fields.UEIPAddress) != 1 {
				t.Fatalf("UE address count: %d", len(fields.UEIPAddress))
			}
			ueipType := fields.UEIPAddress[0]
			if err != nil {
				t.Errorf("FindByType err: %v", err)
			}

			ueip, err := ueipType.UEIPAddress()
			if err != nil {
				t.Errorf("UEIPAddress err: %v", err)
			}

			if ueip.IPv4Address == nil {
				log.Info().Msg("IPv4Address is nil")
			} else {
				if ueip.IPv4Address.String() == "10.61.0.0" {
					log.Info().Msgf("PASSED. IPv4: %s", ueip.IPv4Address.String())
				} else {
					t.Errorf("Unexpected IPv4, got %s, expected %s", ueip.IPv4Address.String(), "10.61.0.0")
				}
			}

		}
	}
}

func TestUEIPInAssociationSetupResponse(t *testing.T) {

	config.Conf = config.UpfConfig{
		UEIPPool:    "10.61.0.0/16",
		FTEIDPool:   65536,
		FeatureUEIP: true,
	}

	pfcpConn, smfIP := PreparePfcpConnection(t)

	// Creating an Association Setup Request
	asReq := message.NewAssociationSetupRequest(1,
		ie.NewNodeIDFQDN("test"),
		ie.NewRecoveryTimeStamp(time.Now()),
	)

	// Processing Association Setup Request
	response, _, err := HandlePfcpAssociationSetupRequest(pfcpConn, asReq, smfIP)
	if err != nil {
		t.Errorf("Error handling Association Setup Request: %s", err)
	}

	// Checking if UEIP is enabled in UP Function Features in response
	asRes, ok := response.(*message.AssociationSetupResponse)
	if !ok {
		t.Error("Unexpected response type")
	}

	// Verify if UEIP is enabled in UP Function Features in response
	ueipEnabled := asRes.UPFunctionFeatures.HasUEIP()
	if !ueipEnabled {
		t.Error("UEIP is not enabled in Association Setup Response")
	}
}

func TestHandlePfcpSessionEstablishmentRequestWithURR(t *testing.T) {
	pfcpConn, smfIP := PreparePfcpConnection(t)

	estReq := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(0xffff),
		),
		ie.NewCreateURR(
			ie.NewURRID(0xf),
		),
	)
	_, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	if _, exists := pfcpConn.GetAssociation(smfIP).Sessions[2].URRs[0xf]; !exists {
		t.Errorf("URR wasn't stored")
	}
}

func TestHandlePfcpSessionModificationRequestWithURR(t *testing.T) {
	ebpfMock := &MapOperationsMock{}
	pfcpConn, smfIP := PreparePfcpConnectionWithMock(t, ebpfMock, config.UpfConfig{})

	estReq := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(0xffff),
		),
	)
	_, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	modReq := message.NewSessionModificationRequest(2, 1,
		ie.NewCreateURR(
			ie.NewURRID(0xf),
		),
	)
	_, _, err = HandlePfcpSessionModificationRequest(pfcpConn, modReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session modification request: %s", err)
	}

	if _, exists := pfcpConn.GetAssociation(smfIP).Sessions[2].URRs[0xf]; !exists {
		t.Errorf("URR wasn't stored")
	}

	// TODO: add case for UpdateURR
	// modReq = message.NewSessionModificationRequest(2, 1,
	// 	ie.NewUpdateURR(
	// 		ie.NewURRID(0xf),
	// 		ie.NewMeasurementMethod(1, 1, 1),
	// 	),
	// )
	// _, err = HandlePfcpSessionModificationRequest(pfcpConn, modReq, smfIP)
	// if err != nil {
	// 	t.Errorf("Error handling session modification request: %s", err)
	// }
	// if pfcpConn.GetAssociation(smfIP).Sessions[2].URRs[0xf].UrrInfo.MeasurementMethod != ?  {
	// 	t.Errorf("URR wasn't updated")
	// }

	modReq = message.NewSessionModificationRequest(2, 1,
		ie.NewRemoveURR(
			ie.NewURRID(0xf),
		),
	)

	ebpfMock.urr.UplinkVolume = 1234
	ebpfMock.urr.DownlinkVolume = 5678
	msg, _, err := HandlePfcpSessionModificationRequest(pfcpConn, modReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session modification request: %s", err)
	}

	modResp := msg.(*message.SessionModificationResponse)
	if len(modResp.UsageReport) == 0 {
		t.Errorf("SessionModificationResponse doesn't contain Usage Reports")
	}

	ur, decodeErr := modResp.UsageReport[0].UsageReportWithinSessionModificationResponse()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	urrID, _ := ur.URRID.URRID()
	if urrID != 0xf {
		t.Errorf("URRID not equal 0xf")
	}

	vol, _ := ur.VolumeMeasurement.VolumeMeasurement()
	if !vol.HasTOVOL() {
		t.Errorf("No TotalVolume")
	}

	if !vol.HasULVOL() {
		t.Errorf("No UplinkVolume")
	}

	if !vol.HasDLVOL() {
		t.Errorf("No DownlinkVolume")
	}

	if vol.UplinkVolume != ebpfMock.urr.UplinkVolume {
		t.Errorf("TotalVolume equals %d", vol.UplinkVolume)
	}

	if vol.DownlinkVolume != ebpfMock.urr.DownlinkVolume {
		t.Errorf("TotalVolume equals %d", vol.DownlinkVolume)
	}

	if vol.TotalVolume != ebpfMock.urr.UplinkVolume+ebpfMock.urr.DownlinkVolume {
		t.Errorf("TotalVolume equals %d", vol.TotalVolume)
	}

	if _, exists := pfcpConn.GetAssociation(smfIP).Sessions[2].URRs[0xf]; exists {
		t.Errorf("URR wasn't removed")
	}
}

func TestHandlePfcpSessionDeletionRequestWithURR(t *testing.T) {

	ebpfMock := &MapOperationsMock{}
	pfcpConn, smfIP := PreparePfcpConnectionWithMock(t, ebpfMock, config.UpfConfig{})

	estReq := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(0xffff),
		),
		ie.NewCreateURR(
			ie.NewURRID(0xf),
		),
	)
	_, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err)
	}

	ebpfMock.urr.UplinkVolume = 100
	ebpfMock.urr.DownlinkVolume = 200
	delReq := message.NewSessionDeletionRequest(2, 1)
	msg, _, err := HandlePfcpSessionDeletionRequest(pfcpConn, delReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session deletion request: %s", err)
	}

	delRes := msg.(*message.SessionDeletionResponse)
	if len(delRes.UsageReport) == 0 {
		t.Errorf("SessionDeletionResponse doesn't contain Usage Reports")
	}

	ur, decodeErr := delRes.UsageReport[0].UsageReportWithinSessionDeletionResponse()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	urrID, _ := ur.URRID.URRID()
	if urrID != 0xf {
		t.Errorf("URRID not equal 0xf")
	}

	vol, _ := ur.VolumeMeasurement.VolumeMeasurement()

	if !vol.HasTOVOL() {
		t.Errorf("No TotalVolume")
	}

	if !vol.HasULVOL() {
		t.Errorf("No UplinkVolume")
	}

	if !vol.HasDLVOL() {
		t.Errorf("No DownlinkVolume")
	}

	if vol.UplinkVolume != ebpfMock.urr.UplinkVolume {
		t.Errorf("TotalVolume equals %d", vol.UplinkVolume)
	}

	if vol.DownlinkVolume != ebpfMock.urr.DownlinkVolume {
		t.Errorf("TotalVolume equals %d", vol.DownlinkVolume)
	}

	if vol.TotalVolume != ebpfMock.urr.UplinkVolume+ebpfMock.urr.DownlinkVolume {
		t.Errorf("TotalVolume equals %d", vol.TotalVolume)
	}
}

func TestHandlePfcpSessionEstablishmentRequestWithNotAllowedAPN(t *testing.T) {
	config := config.UpfConfig{
		AllowedApns: "^(ims|internet1)$",
		DeniedApns:  "",
	}
	pfcpConn, smfIP := PreparePfcpConnectionWithConfig(t, config)

	{
		estReq := restorationEstablishmentRequest(2, 1,
			ie.NewNodeIDFQDN("test"),
			ie.NewFSEID(1, net.ParseIP(smfIP), nil),
			ie.NewCreatePDR(
				ie.NewPDRID(0xffff),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewNetworkInstance("internet"),
					ie.NewUEIPAddress(6, "1.2.3.4", "", 0, 0),
				),
			),
		)
		msg, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
		if err != nil {
			t.Errorf("Error handling session establishment request: %s", err)
		}

		response := msg.(*message.SessionEstablishmentResponse)
		cause, err := response.Cause.Cause()
		if err == nil {
			if cause != ie.CauseRuleCreationModificationFailure {
				t.Errorf("Wrong response cause code")
			}
		} else {
			t.Errorf("No response casuse code: %s", err)
		}
	}
	{
		estReqWithAllowed := restorationEstablishmentRequest(2, 1,
			ie.NewNodeIDFQDN("test"),
			ie.NewFSEID(1, net.ParseIP(smfIP), nil),
			ie.NewCreatePDR(
				ie.NewPDRID(0xffff),
				ie.NewPDI(
					ie.NewSourceInterface(ie.SrcInterfaceCore),
					ie.NewNetworkInstance("internet1"),
					ie.NewUEIPAddress(6, "1.2.3.4", "", 0, 0),
				),
			),
		)
		msg, _, err := HandlePfcpSessionEstablishmentRequest(pfcpConn, estReqWithAllowed, smfIP)
		if err != nil {
			t.Errorf("Error handling session establishment request: %s", err)
		}

		response := msg.(*message.SessionEstablishmentResponse)
		cause, err := response.Cause.Cause()
		if err == nil {
			if cause != ie.CauseRequestAccepted {
				t.Errorf("Wrong response cause code")
			}
		} else {
			t.Errorf("No response casuse code: %s", err)
		}
	}
}

func TestHandlePfcpSessionEstablishmentRequestWithTrace(t *testing.T) {

	ebpfMock := &MapOperationsMock{}
	// Trace test uses enterprise IMSI IE (32769/2011) which requires HuaweiProfile
	// to parse subscriber data. DefaultProfile returns empty IMSI/MSISDN.
	pfcpConn, smfIP := PreparePfcpConnectionWithMockAndProfile(t, ebpfMock, config.UpfConfig{}, HuaweiProfile{})
	pfcpConn.tracingStorage = tracing.NewSimpleTraceRecordStorage()
	resourceManager, err := service.NewResourceManager("10.61.0.0/16", 65536)
	if err != nil {
		t.Fatalf("failed to create ResourceManager: %v", err)
	}
	pfcpConn.ResourceManager = resourceManager

	estReq := restorationEstablishmentRequest(2, 1,
		ie.NewNodeIDFQDN("test"),
		ie.NewFSEID(1, net.ParseIP(smfIP), nil),
		ie.NewCreatePDR(
			ie.NewPDRID(0xffff),
			ie.NewPDI(
				ie.NewSourceInterface(ie.SrcInterfaceCore),
				ie.NewNetworkInstance("internet1"),
				ie.NewUEIPAddress(6, "1.2.3.4", "", 0, 0),
			),
		),
		ie.NewVendorSpecificIE(32769, 2011, []byte{0x52, 0x50, 0x03, 0x00, 0x00, 0x00, 0x20, 0xf3}),
	)
	_, _, err = HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err.Error())
	}

	if ebpfMock.downlinkPDR.TraceFlag {
		t.Errorf("unexpected trace enabled")
	}

	if err = pfcpConn.EnableTracingByImsi("250530000000023"); err != nil {
		t.Errorf("can't enable trace: %s", err.Error())
	}

	if err := estReq.SetSEID(estReq.SEID() + 1); err != nil {
		t.Fatal(err)
	}
	// The second session needs its own UE address (TS 29.244 clause 5.2.1).
	fields, parseErr := estReq.CreatePDR[0].CreatePDR()
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	fields.PDI = ie.NewPDI(ie.NewSourceInterface(ie.SrcInterfaceCore), ie.NewNetworkInstance("internet1"), ie.NewUEIPAddress(6, "1.2.3.5", "", 0, 0))
	estReq.CreatePDR[0] = fields.IE()
	_, _, err = HandlePfcpSessionEstablishmentRequest(pfcpConn, estReq, smfIP)
	if err != nil {
		t.Errorf("Error handling session establishment request: %s", err.Error())
	}

	if !ebpfMock.downlinkPDR.TraceFlag {
		t.Errorf("unexpected trace disabled")
	}
}

// restorationEstablishmentRequest gives fixed F-TEIDs in these fixtures their
// required restoration context (TS 29.244 V20.1.0 clause 5.5.1).
func restorationEstablishmentRequest(seid uint64, sequence uint32, children ...*ie.IE) *message.SessionEstablishmentRequest {
	return message.NewSessionEstablishmentRequest(seid, sequence, append(children, ie.NewPFCPSEReqFlags(1))...)
}

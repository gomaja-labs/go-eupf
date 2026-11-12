// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC

package core

import (
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestGetTransportLevelMarking(t *testing.T) {
	// TS 29.244 V20.1.0 Table 7.5.2.3-2: marking belongs inside Forwarding Parameters.
	CreateFAR := ie.NewCreateFAR(
		ie.NewFARID(10),
		ie.NewForwardingParameters(ie.NewTransportLevelMarking([]byte{0, 55})),
	)

	tlm, err := GetTransportLevelMarking(CreateFAR)
	if err != nil {
		t.Errorf("Error getting TransportLevelMarking: %s", err.Error())
	}
	if tlm != 55 {
		t.Errorf("Expected TransportLevelMarking to be 55, got %d", tlm)
	}
}

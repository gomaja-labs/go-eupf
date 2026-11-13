package domain_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cli/domain"
	"github.com/gomaja-labs/go-eupf/cmd/core"
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestSessionFARJSONPreservesServerFields(t *testing.T) {
	server := core.SFarInfo{
		InterfaceType: 15, InterfaceTypePresent: true, GlobalId: 8,
		FarInfo: ebpf.FarInfo{Action: 2, OuterHeaderCreation: 1, Teid: 200,
			RemoteIP: 0x010200c0, TransportLevelMarking: 0xfc00,
			DestinationInterface: 3, DestinationInterfacePresent: true},
	}
	wire, err := json.Marshal(server)
	if err != nil {
		t.Fatal(err)
	}
	var far domain.SFarInfo
	if err := json.Unmarshal(wire, &far); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := json.Marshal(far)
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	if err := json.Unmarshal(wire, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(roundtrip, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("CLI FAR JSON differs from server: got %s want %s", roundtrip, wire)
	}
}

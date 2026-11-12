package core

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"github.com/gomaja-labs/go-pfcp/ie"
)

func TestPDRPreservesEveryQERBinding(t *testing.T) {
	session := NewSession(9, 42, "", "", false)
	session.NewQer(11, 101, ebpf.QerInfo{})
	session.NewQer(22, 102, ebpf.QerInfo{})
	context := NewPDRCreationContext(session, nil)
	pdr := SPDRInfo{PdrID: 3}
	err := context.extractPDR(ie.NewCreatePDR(ie.NewPDRID(3), ie.NewQERID(11), ie.NewQERID(22), ie.NewPDI(ie.NewUEIPAddress(2, "192.0.2.3", "", 0, 0))), &pdr)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pdr.PdrInfo)
	if err != nil {
		t.Fatal(err)
	}
	var view struct {
		QERs []uint32 `json:"qer_ids"`
	}
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.QERs, []uint32{101, 102}) {
		t.Fatalf("QER bindings=%v, want both QERs in received order", view.QERs)
	}
}

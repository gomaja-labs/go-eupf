package core

import (
	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"testing"
)

func TestURRIdentityEndsOnlyOnRemoveCreate(t *testing.T) {
	s := NewSession(1, 2, "", "", false)
	s.NewUrr(9, 1, ebpf.UrrInfo{})
	first := s.URRs[9].generation
	if first == 0 {
		t.Fatal("zero URR generation")
	}
	s = cloneSession(s)
	s.UpdateUrr(9, ebpf.UrrInfo{VolumeThreshold: 10})
	if s.URRs[9].generation != first {
		t.Fatal("update changed URR identity")
	}
	if _, err := s.RemoveUrr(9); err != nil {
		t.Fatal(err)
	}
	s.NewUrr(9, 1, ebpf.UrrInfo{})
	if s.URRs[9].generation == first {
		t.Fatal("recreated URR reused identity")
	}
}

//go:build linux

package core

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	dataplane "github.com/gomaja-labs/go-eupf/cmd/ebpf"
)

func TestRemovingDataPlaneInterfaceClosesXDPLink(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP, License: "Apache-2.0",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 2), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = prog.Close() }()
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: iface.Index, Flags: link.XDPGenericMode})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	links := []link.Link{l}
	bpf := dataplane.NewBpfObjects()
	bpf.UpfIpEntrypointFunc = prog
	if err := BindDataPlaneInterfaces(bpf, &links, nil, "generic"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Info(); err == nil {
		t.Error("removed interface's XDP link remains open after its handle was dropped")
	}
}

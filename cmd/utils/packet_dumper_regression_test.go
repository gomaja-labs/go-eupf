package utils

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket/pcapgo"
)

func TestPacketDumperClosePreservesQueuedPackets(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator)
	dumper, err := NewPacketDumper(path, 1, 1024*1024, 100)
	if err != nil {
		t.Fatal(err)
	}
	dumper.DumpRawIn(netip.MustParseAddrPort("192.0.2.1:8805"), netip.MustParseAddrPort("192.0.2.2:8805"), []byte{1, 2, 3})
	// Exercise the same shutdown order as TestPacketDumper_RunWrite.
	dumper.Close(false)
	dumper.Write()
	f, err := os.Open(filepath.Join(path, "trace.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	r, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{WantMixedLinkType: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.ReadPacketData(); err != nil {
		t.Errorf("queued packet missing from closed capture (reported count %d): %v", dumper.GetPacketsWritten(), err)
	}
}

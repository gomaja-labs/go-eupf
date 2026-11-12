package utils

import (
	"net/netip"
	"os"
	"sync"
	"testing"
)

func TestPacketDumperProducerAfterClose(t *testing.T) {
	dumper, err := NewPacketDumper(t.TempDir()+string(os.PathSeparator), 1, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	dumper.Close(false)
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("producer panicked after capture shutdown: %v", p)
		}
	}()
	dumper.DumpRawIn(netip.MustParseAddrPort("192.0.2.1:8805"), netip.MustParseAddrPort("192.0.2.2:8805"), []byte{1})
}

func TestPacketDumperConcurrentRotationAndClose(t *testing.T) {
	dumper, err := NewPacketDumper(t.TempDir()+string(os.PathSeparator), 3, 64, 2)
	if err != nil {
		t.Fatal(err)
	}
	var producers sync.WaitGroup
	for range 4 {
		producers.Go(func() {
			for range 40 {
				dumper.DumpRawIn(netip.MustParseAddrPort("192.0.2.1:9000"), netip.MustParseAddrPort("192.0.2.2:9001"), []byte{1, 2, 3})
			}
		})
	}
	producers.Wait()
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() { dumper.Close(false) })
	}
	closers.Wait()
	if dumper.GetPacketsWritten() != 160 {
		t.Fatalf("written=%d", dumper.GetPacketsWritten())
	}
	dumper.DumpRawOut(netip.MustParseAddrPort("192.0.2.1:9000"), netip.MustParseAddrPort("192.0.2.2:9001"), []byte{1})
}

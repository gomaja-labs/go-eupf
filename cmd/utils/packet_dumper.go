package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/gopacket/gopacket"
	"github.com/rs/zerolog/log"
)

type Dumper interface {
	DumpRawIn(from netip.AddrPort, to netip.AddrPort, packet []byte)
	DumpRawOut(to netip.AddrPort, from netip.AddrPort, packet []byte)
}

type PacketDumper struct {
	f                *os.File
	w                *pcapgo.NgWriter
	sigInInterface   int
	sigOutInterface  int
	writeC           chan PacketToWrite
	packetsWritten   atomic.Uint64
	mu               sync.RWMutex
	closed           bool
	closeOnce        sync.Once
	done             chan struct{}
	reader           *perf.Reader
	maxFiles         int
	maxSizeBytes     int
	maxPackets       int
	currentFileSize  int
	currentPacketCnt int
	dumpPath         string
}

func makeNgInterface(name string, linkType layers.LinkType) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Name:                name,
		OS:                  runtime.GOOS,
		SnapLength:          0, //unlimited
		TimestampResolution: 9,
		LinkType:            linkType}
}

func NewPacketDumper(dumpPath string, maxFiles, maxSizeBytes, maxPackets int) (*PacketDumper, error) {
	if maxFiles < 0 || maxSizeBytes < 1 || maxPackets < 1 {
		return nil, fmt.Errorf("invalid capture limits: trace_files, trace_max_size and trace_max_packets")
	}
	dir := dumpPath
	if dir == "" {
		dir = "."
	}

	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("can't create directories: %w", err)
	}

	dumper := &PacketDumper{
		writeC:       make(chan PacketToWrite, 1024),
		done:         make(chan struct{}),
		maxFiles:     maxFiles,
		maxSizeBytes: maxSizeBytes,
		maxPackets:   maxPackets,
		dumpPath:     dumpPath,
	}

	if err := dumper.rotate(); err != nil {
		return nil, err
	}

	go dumper.writeLoop()
	return dumper, nil
}

func (dumper *PacketDumper) rotate() error {
	if dumper.f != nil {
		_ = dumper.w.Flush()
		_ = dumper.f.Close()
	}

	filename := filepath.Join(dumper.dumpPath, "trace.pcap")
	if _, err := os.Stat(filename); err == nil {
		newFilename := filepath.Join(dumper.dumpPath, fmt.Sprintf("trace-%d.pcap", time.Now().UnixNano()))
		if err := os.Rename(filename, newFilename); err != nil {
			log.Error().Err(err).Msgf("Can't rename trace file: %s -> %s", filename, newFilename)
		}
	}

	if files, err := filepath.Glob(filepath.Join(dumper.dumpPath, "trace-*.pcap")); err == nil {
		if len(files) > dumper.maxFiles {
			filesToRemove := len(files) - dumper.maxFiles
			for idx, file := range files[0:filesToRemove] {
				log.Info().Msgf("Remove old trace file [%d/%d]: %s", idx+1, filesToRemove, file)
				if err := os.Remove(file); err != nil {
					log.Error().Err(err).Msgf("Can't remove old trace file: %s", file)
				}
			}
		}
	} else {
		return err
	}

	dumper.currentFileSize = 0
	dumper.currentPacketCnt = 0
	return dumper.createDumpFile(filename)
}

func (dumper *PacketDumper) createDumpFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("can't create rotated pcap: %w", err)
	}
	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("can't create ng writer: %w", err)
	}

	if _, err = w.AddInterface(makeNgInterface("in", layers.LinkTypeEthernet)); err != nil {
		_ = f.Close()
		return fmt.Errorf("can't add in ng pcap interface:: %w", err)
	}

	if _, err = w.AddInterface(makeNgInterface("out", layers.LinkTypeEthernet)); err != nil {
		_ = f.Close()
		return fmt.Errorf("can't add out ng pcap interface:: %w", err)
	}

	if _, err = w.AddInterface(makeNgInterface("drop", layers.LinkTypeEthernet)); err != nil {
		_ = f.Close()
		return fmt.Errorf("can't add drop ng pcap interface:: %w", err)
	}

	sigIn, err := w.AddInterface(makeNgInterface("sig-in", layers.LinkTypeRaw))
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("can't add sig in ng pcap interface:: %w", err)
	}

	sigOut, err := w.AddInterface(makeNgInterface("sig-out", layers.LinkTypeRaw))
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("can't add sig out ng pcap interface:: %w", err)
	}

	if dumper.w == nil {
		dumper.sigInInterface = sigIn
		dumper.sigOutInterface = sigOut
	}
	dumper.f = f
	dumper.w = w

	return nil
}

func (dumper *PacketDumper) ReadTraceMap(traceMap *ebpf.Map) {
	rd, err := perf.NewReader(traceMap, 1024*4096)
	//rd, err := ringbuf.NewReader(traceMap)
	if err != nil {
		log.Error().Msgf(" can't create perf reader: %s", err.Error())
		return
	}
	dumper.mu.Lock()
	if dumper.closed {
		dumper.mu.Unlock()
		_ = rd.Close()
		return
	}
	dumper.reader = rd
	dumper.mu.Unlock()
	defer func() { _ = rd.Close() }()

	var rec perf.Record
	//var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			log.Error().Msgf(" can't read from perf map: %s", err.Error())
			return
		}

		if rec.LostSamples > 0 {
			log.Warn().Msgf(" lost samples from perf map: %d", rec.LostSamples)
			continue
		}

		if len(rec.RawSample) < 9 {
			log.Error().Msgf(" perf sample too small: %d", len(rec.RawSample))
			continue
		}

		magic := binary.LittleEndian.Uint16(rec.RawSample[:2])
		if magic != 0xdead {
			continue
		}

		packetLength := binary.LittleEndian.Uint16(rec.RawSample[2:4])
		packetIface := binary.LittleEndian.Uint32(rec.RawSample[4:8]) + 1
		if int(packetLength) > len(rec.RawSample)-8 {
			log.Error().Msg("truncated capture sample")
			continue
		}
		packet := append([]byte(nil), rec.RawSample[8:8+int(packetLength)]...)

		dumper.enqueue(PacketToWrite{
			gopacket.CaptureInfo{
				Timestamp:      time.Now(),
				Length:         int(packetLength),
				CaptureLength:  int(packetLength),
				InterfaceIndex: int(packetIface),
			},
			packet,
		})
	}
}

func (dumper *PacketDumper) DumpRawIn(from netip.AddrPort, to netip.AddrPort, packet []byte) {
	dumper.dumpRaw(from.Addr().AsSlice(), from.Port(), to.Addr().AsSlice(), to.Port(), dumper.sigInInterface, packet)
}

func (dumper *PacketDumper) DumpRawOut(to netip.AddrPort, from netip.AddrPort, packet []byte) {
	dumper.dumpRaw(from.Addr().AsSlice(), from.Port(), to.Addr().AsSlice(), to.Port(), dumper.sigOutInterface, packet)
}

type PacketToWrite struct {
	info   gopacket.CaptureInfo
	packet []byte
}

func (dumper *PacketDumper) dumpRaw(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, iface int, packet []byte) {

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(&ip)

	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options,
		&ip,
		&udp,
		gopacket.Payload(packet),
	)
	if err != nil {
		log.Error().Err(err).Msgf("can't serialize sig sample")
		return
	}
	outgoingPacket := buffer.Bytes()

	dumper.enqueue(PacketToWrite{gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		Length:         len(outgoingPacket),
		CaptureLength:  len(outgoingPacket),
		InterfaceIndex: iface,
	}, outgoingPacket})

	// if err := dumper.w.WritePacket(gopacket.CaptureInfo{
	// 	Timestamp:      time.Now(),
	// 	Length:         len(outgoingPacket),
	// 	CaptureLength:  len(outgoingPacket),
	// 	InterfaceIndex: iface,
	// }, outgoingPacket); err != nil {
	// 	log.Error().Err(err).Msgf("can't write sig sample to pcap dump")
	// }
}

// Write waits for the capture writer to finish. The constructor starts it.
func (dumper *PacketDumper) Write() { <-dumper.done }

func (dumper *PacketDumper) enqueue(pkt PacketToWrite) {
	dumper.mu.RLock()
	defer dumper.mu.RUnlock()
	if !dumper.closed {
		dumper.writeC <- pkt
	}
}

func (dumper *PacketDumper) writeLoop() {
	defer close(dumper.done)
	failed := false
	for pkt := range dumper.writeC {
		if failed {
			continue
		}
		if dumper.currentPacketCnt >= dumper.maxPackets || dumper.currentFileSize >= dumper.maxSizeBytes {
			if err := dumper.rotate(); err != nil {
				log.Error().Err(err).Msg("failed to rotate dump file")
				failed = true
				continue
			}
		}

		if err := dumper.w.WritePacket(pkt.info, pkt.packet); err != nil {
			log.Error().Err(err).Msgf("can't write sample to pcap")
			failed = true
			continue
		}

		dumper.packetsWritten.Add(1)
		dumper.currentPacketCnt++
		dumper.currentFileSize += len(pkt.packet)
	}
}

func (dumper *PacketDumper) GetPacketsWritten() uint64 {

	return dumper.packetsWritten.Load()
}

// Close stops producers, drains all accepted packets and closes the capture.
func (dumper *PacketDumper) Close(removeTrace bool) {
	dumper.closeOnce.Do(func() {
		dumper.mu.Lock()
		dumper.closed = true
		if dumper.reader != nil {
			_ = dumper.reader.Close()
		}
		close(dumper.writeC)
		dumper.mu.Unlock()
		<-dumper.done
		if dumper.w != nil {
			_ = dumper.w.Flush()
		}
		if dumper.f != nil {
			_ = dumper.f.Close()
			if removeTrace {
				_ = os.Remove(dumper.f.Name())
			}
		}
	})
}

//go:build linux

package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
	"golang.org/x/sys/unix"
)

type bufferPacketSender struct {
	mu     sync.Mutex
	plane  *ebpf.BpfObjects
	closed bool
	fd     int
	kernel *bufferKernelLink
}

func newBufferPacketSender(plane *ebpf.BpfObjects) (packetBufferSender, error) {
	return &bufferPacketSender{plane: plane, fd: -1}, nil
}

// Prepare loads output only when a BUFF lifetime is first admitted. Failures
// occur before rule publication, so no retained packet depends on a failed load.
func (sender *bufferPacketSender) Prepare() error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.closed {
		return errors.New("buffer output is closed")
	}
	if sender.fd >= 0 {
		return nil
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open buffered packet output: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_QDISC_BYPASS, 1); err != nil {
		return errors.Join(err, unix.Close(fd))
	}
	program, err := sender.plane.BufferKernelIngressProgram()
	if err != nil {
		return errors.Join(err, unix.Close(fd))
	}
	kernel, err := newBufferKernelLink(program.FD())
	if err != nil {
		return errors.Join(err, kernel.Close(), unix.Close(fd))
	}
	sender.fd, sender.kernel = fd, kernel
	return nil
}
func (sender *bufferPacketSender) Send(packet ebpf.RenderedBuffer) error {
	if len(packet.Frame) < 14 || packet.Action < 2 || packet.Action > 4 {
		return errors.New("buffered packet has no resolved route")
	}
	if packet.Action == 2 {
		if packet.IngressIfindex == 0 {
			return errors.New("kernel continuation has no ingress interface")
		}
		frame := make([]byte, len(packet.Frame)+8)
		copy(frame, packet.Frame[:14])
		binary.NativeEndian.PutUint32(frame[14:], 0x42554646)
		binary.NativeEndian.PutUint32(frame[18:], packet.IngressIfindex)
		copy(frame[22:], packet.Frame[14:])
		packet.Frame = frame
		packet.Ifindex = uint32(sender.kernel.index)
	}
	if packet.Ifindex == 0 {
		return errors.New("buffered packet has no output interface")
	}
	address := unix.SockaddrLinklayer{Ifindex: int(packet.Ifindex), Protocol: binary.NativeEndian.Uint16(packet.Frame[12:14]), Halen: 6}
	copy(address.Addr[:], packet.Frame[:6])
	if err := unix.Sendto(sender.fd, packet.Frame, unix.MSG_DONTWAIT, &address); err != nil {
		return fmt.Errorf("transmit buffered packet on interface %d: %w", packet.Ifindex, err)
	}
	return nil
}
func (sender *bufferPacketSender) Close() error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	if sender.closed {
		return nil
	}
	sender.closed = true
	var err error
	if sender.fd >= 0 {
		err = unix.Close(sender.fd)
		sender.fd = -1
	}
	return errors.Join(sender.kernel.Close(), err)
}

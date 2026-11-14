//go:build linux

package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// These rtnetlink layouts and attributes are Linux UAPI (v5.15):
// rtnetlink.h, if_link.h, veth.h and pkt_cls.h. Every mutation requires ACK.
type bufferNetlink struct {
	fd       int
	sequence uint32
}

func newBufferNetlink() (*bufferNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err == nil {
		err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	}
	if err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return &bufferNetlink{fd: fd}, nil
}
func bufferAttribute(kind uint16, value []byte) []byte {
	size := 4 + len(value)
	out := make([]byte, (size+3)&^3)
	binary.NativeEndian.PutUint16(out, uint16(size))
	binary.NativeEndian.PutUint16(out[2:], kind)
	copy(out[4:], value)
	return out
}
func bufferUint32(value uint32) []byte { return binary.NativeEndian.AppendUint32(nil, value) }
func (link *bufferNetlink) change(kind uint16, flags uint16, payload []byte) error {
	link.sequence++
	message := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(message, uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:], kind)
	binary.NativeEndian.PutUint16(message[6:], flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(message[8:], link.sequence)
	copy(message[16:], payload)
	if err := unix.Sendto(link.fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	response := make([]byte, 8192)
	for {
		n, from, err := unix.Recvfrom(link.fd, response, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		kernel, ok := from.(*unix.SockaddrNetlink)
		if !ok || kernel.Pid != 0 {
			return errors.New("rtnetlink response is not from kernel")
		}
		messages, err := syscall.ParseNetlinkMessage(response[:n])
		if err != nil {
			return err
		}
		for _, reply := range messages {
			if reply.Header.Seq != link.sequence {
				continue
			}
			if reply.Header.Type != unix.NLMSG_ERROR || len(reply.Data) < 4 {
				return errors.New("invalid rtnetlink acknowledgement")
			}
			status := int32(binary.NativeEndian.Uint32(reply.Data))
			if status == 0 {
				return nil
			}
			if status > 0 {
				return errors.New("invalid rtnetlink error")
			}
			return unix.Errno(-status)
		}
	}
}
func bufferLinkMessage(index int, up bool) []byte {
	data := make([]byte, 16)
	binary.NativeEndian.PutUint32(data[4:], uint32(index))
	if up {
		binary.NativeEndian.PutUint32(data[8:], unix.IFF_UP)
		binary.NativeEndian.PutUint32(data[12:], unix.IFF_UP)
	}
	return data
}
func bufferTCMessage(index int, handle, parent, info uint32) []byte {
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data[4:], uint32(index))
	binary.NativeEndian.PutUint32(data[8:], handle)
	binary.NativeEndian.PutUint32(data[12:], parent)
	binary.NativeEndian.PutUint32(data[16:], info)
	return data
}

type bufferKernelLink struct {
	link    *bufferNetlink
	index   int
	name    string
	address net.HardwareAddr
}

func newBufferKernelLink(programFD int) (_ *bufferKernelLink, err error) {
	link, err := newBufferNetlink()
	if err != nil {
		return nil, err
	}
	resource := &bufferKernelLink{link: link}
	defer func() {
		if err != nil {
			err = errors.Join(err, resource.Close())
		}
	}()
	var random [10]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	resource.name = fmt.Sprintf("eub%x", random[:4])
	peer := resource.name + "p"
	resource.address = net.HardwareAddr{2, random[4], random[5], random[6], random[7], random[8]}
	peerData := append(bufferLinkMessage(0, false), bufferAttribute(unix.IFLA_IFNAME, append([]byte(peer), 0))...)
	vethData := bufferAttribute(1|unix.NLA_F_NESTED, peerData) // VETH_INFO_PEER
	info := append(bufferAttribute(unix.IFLA_INFO_KIND, []byte("veth\x00")), bufferAttribute(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, vethData)...)
	data := append(bufferLinkMessage(0, false), bufferAttribute(unix.IFLA_IFNAME, append([]byte(resource.name), 0))...)
	data = append(data, bufferAttribute(unix.IFLA_ADDRESS, resource.address)...)
	data = append(data, bufferAttribute(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	if err = link.change(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("create kernel continuation veth: %w", err)
	}
	iface, err := net.InterfaceByName(resource.name)
	if err != nil {
		return nil, err
	}
	resource.index = iface.Index
	other, err := net.InterfaceByName(peer)
	if err != nil {
		return nil, err
	}
	for _, index := range []int{iface.Index, other.Index} {
		if err = link.change(unix.RTM_NEWLINK, 0, bufferLinkMessage(index, true)); err != nil {
			return nil, err
		}
	}
	data = append(bufferTCMessage(other.Index, 0xffff0000, 0xfffffff1, 0), bufferAttribute(1, []byte("clsact\x00"))...)
	if err = link.change(unix.RTM_NEWQDISC, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("create kernel continuation qdisc: %w", err)
	}
	options := append(bufferAttribute(6, bufferUint32(uint32(programFD))), bufferAttribute(7, []byte("upf_buffer_kernel\x00"))...)
	options = append(options, bufferAttribute(8, bufferUint32(1))...) // TCA_BPF_FLAG_ACT_DIRECT
	data = append(bufferTCMessage(other.Index, 1, 0xfffffff2, 1<<16|0x0300), bufferAttribute(1, []byte("bpf\x00"))...)
	data = append(data, bufferAttribute(2|unix.NLA_F_NESTED, options)...)
	if err = link.change(unix.RTM_NEWTFILTER, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("attach kernel continuation filter: %w", err)
	}
	return resource, nil
}
func (resource *bufferKernelLink) Close() error {
	if resource == nil || resource.link == nil {
		return nil
	}
	var removeErr error
	if resource.name != "" {
		iface, err := net.InterfaceByName(resource.name)
		if err == nil && iface.HardwareAddr.String() == resource.address.String() && (resource.index == 0 || resource.index == iface.Index) {
			removeErr = resource.link.change(unix.RTM_DELLINK, 0, bufferLinkMessage(iface.Index, false))
		}
	}
	closeErr := unix.Close(resource.link.fd)
	resource.link = nil
	return errors.Join(removeErr, closeErr)
}

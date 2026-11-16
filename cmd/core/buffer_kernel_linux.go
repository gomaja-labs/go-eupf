//go:build linux

package core

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"

	"github.com/gomaja-labs/go-eupf/cmd/ebpf"
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

// Read the current kernel attachment, including default-mode selection. Never
// infer it from configuration: an attached link can have a different mode.
// Linux UAPI if_link.h: IFLA_XDP_ATTACHED, XDP_ATTACHED_SKB = 2.
func bufferIngressIsGeneric(index uint32) (bool, error) {
	link, err := newBufferNetlink()
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(link.fd) }()
	// A single RTM_GETLINK (ifi_index, without NLM_F_DUMP) bounds work
	// independently of the number of interfaces. Linux rtnetlink UAPI.
	request := make([]byte, 16+unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], unix.RTM_GETLINK)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], 1)
	binary.NativeEndian.PutUint32(request[20:], index)
	if err := unix.Sendto(link.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return false, err
	}
	response := make([]byte, 65536)
	n, from, err := unix.Recvfrom(link.fd, response, 0)
	if err != nil {
		return false, err
	}
	kernel, ok := from.(*unix.SockaddrNetlink)
	if !ok || kernel.Pid != 0 {
		return false, errors.New("rtnetlink response is not from kernel")
	}
	messages, err := syscall.ParseNetlinkMessage(response[:n])
	if err != nil {
		return false, err
	}
	for _, message := range messages {
		if message.Header.Seq != 1 {
			continue
		}
		if message.Header.Type == unix.NLMSG_ERROR && len(message.Data) >= 4 {
			status := int32(binary.NativeEndian.Uint32(message.Data))
			if status < 0 {
				return false, unix.Errno(-status)
			}
			return false, errors.New("unexpected rtnetlink acknowledgement")
		}
		if message.Header.Type != unix.RTM_NEWLINK || len(message.Data) < unix.SizeofIfInfomsg || binary.NativeEndian.Uint32(message.Data[4:]) != index {
			continue
		}
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return false, err
		}
		for _, attribute := range attributes {
			if attribute.Attr.Type&0x3fff != unix.IFLA_XDP {
				continue
			}
			// ParseNetlinkRouteAttr skips an ifinfomsg; the nested payload has
			// none, so supply an empty header before its attributes.
			nested := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK}, Data: append(make([]byte, unix.SizeofIfInfomsg), attribute.Value...)}
			xdp, err := syscall.ParseNetlinkRouteAttr(&nested)
			if err != nil {
				return false, err
			}
			for _, mode := range xdp {
				if mode.Attr.Type == unix.IFLA_XDP_ATTACHED && len(mode.Value) == 1 {
					return mode.Value[0] == 2, nil
				}
			}
		}
		return false, nil
	}
	return false, fmt.Errorf("no link response for ingress interface %d", index)
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
	mu      sync.Mutex
	closed  bool
	ownerFD int
	link    *bufferNetlink
	index   int
	name    string
	address net.HardwareAddr
}

func newBufferKernelLink(programFD int, adopt func(*bufferKernelLink) error) (_ *bufferKernelLink, err error) {
	link, err := newBufferNetlink()
	if err != nil {
		return nil, err
	}
	resource := &bufferKernelLink{link: link, ownerFD: -1}
	defer func() {
		if err != nil {
			err = errors.Join(err, resource.Close())
		}
	}()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	token := hex.EncodeToString(random[:6])
	owner := "@go-eupf-buffer:" + token
	resource.ownerFD, err = unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(resource.ownerFD, &unix.SockaddrUnix{Name: owner}); err != nil {
		return nil, err
	}
	resource.name = "eub" + token
	peer := "eup" + token
	resource.address = net.HardwareAddr{2, random[4], random[5], random[6], random[7], random[8]}
	// Publish ownership before RTM_NEWLINK. Close marks the resource closed
	// under its own mutex, so no later step can create a link after shutdown.
	if err = adopt(resource); err != nil {
		return nil, err
	}
	peerData := append(bufferLinkMessage(0, false), bufferAttribute(unix.IFLA_IFNAME, append([]byte(peer), 0))...)
	// Carry the complete retained frame class, rewrite headroom and cursor.
	// Linux still applies the actual forwarding device's MTU after reinjection.
	peerData = append(peerData, bufferAttribute(unix.IFLA_MTU, bufferUint32(4096))...)

	vethData := bufferAttribute(1|unix.NLA_F_NESTED, peerData) // VETH_INFO_PEER
	info := append(bufferAttribute(unix.IFLA_INFO_KIND, []byte("veth\x00")), bufferAttribute(unix.IFLA_INFO_DATA|unix.NLA_F_NESTED, vethData)...)
	data := append(bufferLinkMessage(0, false), bufferAttribute(unix.IFLA_IFNAME, append([]byte(resource.name), 0))...)
	data = append(data, bufferAttribute(unix.IFLA_ADDRESS, resource.address)...)
	data = append(data, bufferAttribute(unix.IFLA_MTU, bufferUint32(4096))...)
	data = append(data, bufferAttribute(unix.IFLA_LINKINFO|unix.NLA_F_NESTED, info)...)
	if err = resource.change(unix.RTM_NEWLINK, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("create kernel continuation veth: %w", err)
	}
	iface, err := net.InterfaceByName(resource.name)
	if err != nil {
		return nil, err
	}
	resource.mu.Lock()
	resource.index = iface.Index
	resource.mu.Unlock()
	other, err := net.InterfaceByName(peer)
	if err != nil {
		return nil, err
	}
	for _, index := range []int{iface.Index, other.Index} {
		if err = resource.change(unix.RTM_NEWLINK, 0, bufferLinkMessage(index, true)); err != nil {
			return nil, err
		}
	}
	data = append(bufferTCMessage(other.Index, 0xffff0000, 0xfffffff1, 0), bufferAttribute(1, []byte("clsact\x00"))...)
	if err = resource.change(unix.RTM_NEWQDISC, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("create kernel continuation qdisc: %w", err)
	}
	options := append(bufferAttribute(6, bufferUint32(uint32(programFD))), bufferAttribute(7, []byte("upf_buffer_kernel\x00"))...)
	options = append(options, bufferAttribute(8, bufferUint32(1))...) // TCA_BPF_FLAG_ACT_DIRECT
	data = append(bufferTCMessage(other.Index, 1, 0xfffffff2, 1<<16|0x0300), bufferAttribute(1, []byte("bpf\x00"))...)
	data = append(data, bufferAttribute(2|unix.NLA_F_NESTED, options)...)
	if err = resource.change(unix.RTM_NEWTFILTER, unix.NLM_F_CREATE|unix.NLM_F_EXCL, data); err != nil {
		return nil, fmt.Errorf("attach kernel continuation filter: %w", err)
	}
	return resource, nil
}
func (resource *bufferKernelLink) Close() error {
	if resource == nil {
		return nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return nil
	}
	resource.closed = true
	var removeErr error
	if resource.name != "" {
		iface, err := net.InterfaceByName(resource.name)
		if err == nil && iface.HardwareAddr.String() == resource.address.String() && (resource.index == 0 || resource.index == iface.Index) {
			removeErr = resource.link.change(unix.RTM_DELLINK, 0, bufferLinkMessage(iface.Index, false))
		}
	}
	closeErr := unix.Close(resource.link.fd)
	if resource.ownerFD >= 0 {
		closeErr = errors.Join(closeErr, unix.Close(resource.ownerFD))
		resource.ownerFD = -1
	}
	resource.link = nil
	return errors.Join(removeErr, closeErr)
}

func setBufferIngressMode(plane *ebpf.BpfObjects, index uint32) error {
	generic, err := bufferIngressIsGeneric(index)
	if err != nil {
		return err
	}
	return plane.SetBufferGenericIngress(index, generic)
}

func (resource *bufferKernelLink) change(kind, flags uint16, payload []byte) error {
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.closed {
		return errors.New("kernel continuation link is closed")
	}
	return resource.link.change(kind, flags, payload)
}

// Abstract Unix sockets are scoped to the network namespace and disappear on
// process exit. Unlike PIDs, this ownership check also works across containers
// sharing a network namespace but using different PID namespaces.
func removeStaleBufferLinks() error {
	rib, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return err
	}
	var control *bufferNetlink
	defer func() {
		if control != nil {
			_ = unix.Close(control.fd)
		}
	}()
	for _, message := range messages {
		if message.Header.Type != unix.RTM_NEWLINK || len(message.Data) < unix.SizeofIfInfomsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return err
		}
		for _, attr := range attrs {
			if attr.Attr.Type != unix.IFLA_IFNAME {
				continue
			}
			name := strings.TrimRight(string(attr.Value), "\x00")
			// Both ends fit IFNAMSIZ: a reserved three-letter prefix and twelve
			// lowercase hex digits. The name and owner socket exist before any
			// post-creation step, so a crash cannot leave an unidentifiable pair.
			if len(name) != 15 || (name[:3] != "eub" && name[:3] != "eup") {
				continue
			}
			token := name[3:]
			decoded, err := hex.DecodeString(token)
			if err != nil || hex.EncodeToString(decoded) != token {
				continue
			}
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				return err
			}
			// Claim the dead owner's socket until deletion completes. Bind also
			// excludes a live creator and concurrent startup reclamation; another
			// creator cannot reuse this token between the check and deletion.
			ownerErr := unix.Bind(fd, &unix.SockaddrUnix{Name: "@go-eupf-buffer:" + token})
			if ownerErr != nil {
				closeErr := unix.Close(fd)
				if errors.Is(ownerErr, unix.EADDRINUSE) && closeErr == nil {
					continue
				}
				return errors.Join(ownerErr, closeErr)
			}
			if control == nil {
				control, err = newBufferNetlink()
				if err != nil {
					return errors.Join(err, unix.Close(fd))
				}
			}
			remove := append(bufferLinkMessage(0, false), bufferAttribute(unix.IFLA_IFNAME, append([]byte(name), 0))...)
			err = control.change(unix.RTM_DELLINK, 0, remove)
			closeErr := unix.Close(fd)
			if closeErr != nil {
				return errors.Join(err, closeErr)
			}
			// Deleting one veth also removes its peer from this dump's snapshot.
			if err != nil && !errors.Is(err, unix.ENODEV) {
				return err
			}
		}
	}
	return nil
}

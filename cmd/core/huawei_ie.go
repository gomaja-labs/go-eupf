package core

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/gomaja-labs/go-pfcp/ie"
)

// HuaweiOuterHeaderCreation reads the Huawei one-octet description dialect.
// Standard Outer Header Creation is decoded by go-pfcp in DefaultProfile.
func HuaweiOuterHeaderCreation(i *ie.IE) (*ie.OuterHeaderCreationFields, error) {
	if i == nil {
		return nil, ie.ErrIENotFound
	}
	if i.Type != ie.OuterHeaderCreation {
		return nil, &ie.InvalidTypeError{Type: i.Type}
	}
	if len(i.Payload) < 9 {
		return nil, io.ErrUnexpectedEOF
	}
	if i.Payload[0] != 0 {
		return nil, ie.ErrInvalidValue
	}
	return &ie.OuterHeaderCreationFields{
		OuterHeaderCreationDescription: uint16(i.Payload[0]),
		TEID:                           binary.BigEndian.Uint32(i.Payload[1:5]),
		IPv4Address:                    net.IP(i.Payload[5:9]),
	}, nil
}

func EncodeFQDNHuawei(fqdn string) []byte {
	b := make([]byte, 0)
	b = append(b, fqdn...)
	return b
}

func NewNodeIDHuawei(ipv4, ipv6, fqdn string) *ie.IE {
	var p []byte

	switch {
	case ipv4 != "":
		p = make([]byte, 5)
		p[0] = ie.NodeIDIPv4Address
		copy(p[1:], net.ParseIP(ipv4).To4())
	case ipv6 != "":
		p = make([]byte, 17)
		p[0] = ie.NodeIDIPv6Address
		copy(p[1:], net.ParseIP(ipv6).To16())
	case fqdn != "":
		p = make([]byte, 1+len([]byte(fqdn)))
		p[0] = ie.NodeIDFQDN
		copy(p[1:], EncodeFQDNHuawei(fqdn))
	default: // all params are empty
		return nil
	}

	return ie.New(ie.NodeID, p)
}

func newIeNodeIDHuawei(nodeID string) *ie.IE {
	ip := net.ParseIP(nodeID)
	if ip != nil {
		if ip.To4() != nil {
			return NewNodeIDHuawei(nodeID, "", "")
		}
		return NewNodeIDHuawei("", nodeID, "")
	}
	return NewNodeIDHuawei("", "", nodeID)
}

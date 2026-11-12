package core

import (
	"net"
	"net/netip"
	"testing"

	"github.com/gomaja-labs/go-pfcp/ie"
	"github.com/gomaja-labs/go-pfcp/message"
)

func TestIPv6LocalFSEIDRemainsEncodable(t *testing.T) {
	conn, peer := PreparePfcpConnection(t)
	conn.nodeAddrV4 = netip.MustParseAddrPort("[::1]:8805")
	request := message.NewSessionEstablishmentRequest(0, 1, ie.NewNodeIDFQDN("test"), ie.NewFSEID(42, net.ParseIP(peer), nil))
	reply, _, err := HandlePfcpSessionEstablishmentRequest(conn, request, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := reply.MarshalTo(make([]byte, reply.MarshalLen())); err != nil {
		t.Fatalf("accepted session produced an unencodable response: %v", err)
	}
	fseid, err := reply.(*message.SessionEstablishmentResponse).UPFSEID.FSEID()
	if err != nil || fseid.IPv4Address != nil || !fseid.IPv6Address.Equal(net.ParseIP("::1")) {
		t.Fatalf("wrong F-SEID family: %+v %v", fseid, err)
	}
}

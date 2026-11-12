package core

import (
	"net"
	"testing"
)

func TestSemanticPFCPEndpoints(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{":8805", "0.0.0.0:8805", true}, {":8805", "[::]:8805", true},
		{"0.0.0.0:8805", "[::]:8805", true}, {"[::ffff:0.0.0.0]:8805", ":8805", true},
		{"127.0.0.1:8805", "[::ffff:127.0.0.1]:8805", true},
		{"127.0.0.1:8805", "127.0.0.1:8806", false},
		{":8805", ":8806", false}, {":8805", "127.0.0.1:8805", false},
		{"192.0.2.1:8805", "192.0.2.2:8805", false},
		{"[fe80::1%eth0]:8805", "[fe80::1%eth1]:8805", false},
	} {
		t.Run(tc.a+"/"+tc.b, func(t *testing.T) {
			a, err := net.ResolveUDPAddr("udp", tc.a)
			if err != nil {
				t.Fatal(err)
			}
			b, err := net.ResolveUDPAddr("udp", tc.b)
			if err != nil {
				t.Fatal(err)
			}
			if got := samePFCPEndpoint(a, b); got != tc.same {
				t.Fatalf("equal=%v want=%v", got, tc.same)
			}
		})
	}
}

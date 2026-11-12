package core

import (
	"strings"
)

func DecodeDigitsFromBytes(buffer []byte) string {
	decoded := make([]byte, len(buffer)*2)
	for i, b := range buffer {
		decoded[2*i], decoded[2*i+1] = hexDigit(b&0x0F), hexDigit((b&0xF0)>>4)
	}

	return strings.TrimSuffix(string(decoded), "f")
}

func hexDigit(nibble byte) byte {
	if nibble < 10 {
		return '0' + nibble
	}
	return 'a' + (nibble - 10)
}

// EncodeFQDN encodes the given string as the Name Syntax defined
// in RFC 2181, RFC 1035 and RFC 1123.
func EncodeFQDN(fqdn string) []byte {
	b := make([]byte, len(fqdn)+1)

	var offset = 0
	for _, label := range strings.Split(fqdn, ".") {
		l := len(label)
		b[offset] = uint8(l)
		copy(b[offset+1:], label)
		offset += l + 1
	}

	return b
}

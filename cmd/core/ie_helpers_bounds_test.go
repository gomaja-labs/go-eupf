package core

import "testing"

func TestDecodeDigitsBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"zero", []byte{0}, "00"},
		{"two-digits", []byte{0x21}, "12"},
		{"terminal-filler", []byte{0xf1}, "1"},
		{"nonterminal-filler", []byte{0x1f}, "f1"},
		{"multiple-octets", []byte{0x21, 0xf3}, "123"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeDigitsFromBytes(tt.input); got != tt.want {
				t.Fatalf("digits = %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzDecodeDigitsFromBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x21, 0xf3})
	f.Fuzz(func(t *testing.T, input []byte) {
		got := DecodeDigitsFromBytes(input)
		wantLength := 2 * len(input)
		if len(input) > 0 && input[len(input)-1]>>4 == 0xf {
			wantLength--
		}
		if len(got) != wantLength {
			t.Fatalf("digit count = %d, want %d", len(got), wantLength)
		}
		for index, char := range []byte(got) {
			nibble := input[index/2] & 0x0f
			if index%2 != 0 {
				nibble = input[index/2] >> 4
			}
			if char != "0123456789abcdef"[nibble] {
				t.Fatalf("digit %d = %c", index, char)
			}
		}
	})
}

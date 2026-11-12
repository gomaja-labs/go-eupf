//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"math/rand/v2"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile the production C helper and compare its output with arbitrary-
// precision rational arithmetic, independent of the kernel's wall clock.
func TestRateCostAgainstRationalModel(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("C compiler is unavailable in this test environment")
	}
	probe := filepath.Join(t.TempDir(), "rate-cost")
	cc := exec.Command("cc", "-x", "c", "-I.", "-o", probe, "-")
	cc.Stdin = strings.NewReader(`#include <stdint.h>
#include <stdio.h>
#include "xdp/rate_math.h"
int main(void) {
 uint64_t bytes,rate;
 while(fread(&bytes,8,1,stdin)==1 && fread(&rate,8,1,stdin)==1) {
  uint64_t cost=packet_tx_time_ns(bytes,rate);
  if(fwrite(&cost,8,1,stdout)!=1) return 1;
 }
 return ferror(stdin) ? 1 : 0;
}
`)
	if out, err := cc.CombinedOutput(); err != nil {
		t.Fatalf("compile rate probe: %v: %s", err, out)
	}
	type input struct{ bytes, rate uint64 }
	var cases []input
	for _, size := range []uint64{0, 1, 20, 40, 1500, 65535, 65575} {
		for _, rate := range []uint64{0, 1, 1000, 999999999, 1000000000, 1000000001, 2000000000, 1<<40 - 1, 1 << 63, ^uint64(0)} {
			cases = append(cases, input{size, rate})
		}
	}
	rng := rand.New(rand.NewPCG(17, 29))
	for range 10000 {
		cases = append(cases, input{rng.Uint64N(65576), rng.Uint64()})
	}
	var in bytes.Buffer
	for _, c := range cases {
		for _, v := range []uint64{c.bytes, c.rate} {
			if err := binary.Write(&in, binary.LittleEndian, v); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := exec.Command(probe)
	run.Stdin = &in
	out, err := run.Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 8*len(cases) {
		t.Fatalf("got %d result bytes for %d cases", len(out), len(cases))
	}
	for i, c := range cases {
		want := uint64(0)
		if c.rate != 0 {
			n := new(big.Int).Mul(new(big.Int).SetUint64(c.bytes), big.NewInt(8000000000))
			n.Add(n, new(big.Int).SetUint64(c.rate-1))
			n.Div(n, new(big.Int).SetUint64(c.rate))
			want = n.Uint64()
		}
		if got := binary.LittleEndian.Uint64(out[i*8:]); got != want {
			t.Fatalf("bytes=%d rate=%d got=%d want=%d", c.bytes, c.rate, got, want)
		}
	}
}

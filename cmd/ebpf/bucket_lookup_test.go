//go:build linux

package ebpf

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPDRLookupRetriesAndValidatesSlotIdentity(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("C compiler is unavailable in this test environment")
	}
	probe := filepath.Join(t.TempDir(), "pdr-lookup")
	cmd := exec.Command("cc", "-O2", "-I.", "-o", probe, "testdata/pdr_lookup.c")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile production lookup helper: %v: %s", err, out)
	}
	if out, err := exec.Command(probe).CombinedOutput(); err != nil {
		t.Fatalf("lookup retry/key validation: %v: %s", err, out)
	}
}

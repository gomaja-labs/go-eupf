package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCaptureStartupFailure(t *testing.T) {
	if os.Getenv("EUPF_CAPTURE_STARTUP_REPRO") == "1" {
		os.Args = []string{"eupf", "--maxsessions", "1"}
		main()
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dumps"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCaptureStartupFailure$")
	command.Dir = dir
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "UPF_") && !strings.HasPrefix(entry, "PCC_") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "EUPF_CAPTURE_STARTUP_REPRO=1")
	output, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("startup succeeded after capture creation failed: %s", output)
	}
	if !strings.Contains(string(output), "initialize packet capture") {
		t.Fatalf("startup failed for a different reason: %v\n%s", err, output)
	}
}

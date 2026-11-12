package utils

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPacketDumperCreationPreservesFilesystemError(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewPacketDumper(filepath.Join(parent, "capture"), 1, 1024, 10)
	var pathError *os.PathError
	if !errors.As(err, &pathError) {
		t.Fatalf("filesystem cause lost: %v", err)
	}
}

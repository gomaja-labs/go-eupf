package file

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/gomaja-labs/go-eupf/cli/domain"
)

func TestSaveUpfConfigReportsArchiveCloseError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full is unavailable")
	}
	dir := t.TempDir()
	// The ZIP buffers this small document until Close writes the archive.
	now := time.Now().Unix()
	for delta := int64(-2); delta <= 2; delta++ {
		if err := os.Symlink("/dev/full", filepath.Join(dir, fmt.Sprintf("%d.zip", now+delta))); err != nil {
			t.Fatal(err)
		}
	}
	r := &FileRepository{backupDir: dir}
	if err := r.SaveUpfConfig(context.Background(), &domain.UpfConfig{}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("SaveUpfConfig error = %v, want ENOSPC from archive close", err)
	}
}

package file

import (
	"archive/zip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreArchiveBudgets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int
	}{
		{"entry", []int{MaxArchiveEntrySize + 1}},
		{"total", []int{MaxArchiveEntrySize, MaxArchiveEntrySize, MaxArchiveEntrySize, MaxArchiveEntrySize, 1}},
		{"count", make([]int, MaxArchiveEntries+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			f, err := os.Create(filepath.Join(dir, "bounded.zip"))
			if err != nil {
				t.Fatal(err)
			}
			w := zip.NewWriter(f)
			for i, n := range tc.sizes {
				name := fmt.Sprintf("unused-%d", i)
				if i == 0 {
					name = "config.yaml"
				}
				entry, err := w.Create(name)
				if err != nil {
					t.Fatal(err)
				}
				// YAML comments are valid even when huge; reject before parsing them.
				if _, err = entry.Write([]byte(strings.Repeat("#", n))); err != nil {
					t.Fatal(err)
				}
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
			repo := FileRepository{backupDir: dir}
			if _, err = repo.ReadUpfConfig(context.Background(), "bounded"); err == nil {
				t.Fatal("oversized archive accepted")
			}
		})
	}
}

func TestRestoreRejectsSymlinkOutsideRoot(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.zip")
	if err := os.WriteFile(outside, []byte("not an archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.zip")); err != nil {
		t.Fatal(err)
	}
	repo := FileRepository{backupDir: dir}
	_, err := repo.ReadUpfConfig(context.Background(), "link")
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("expected root confinement, got %v", err)
	}
}

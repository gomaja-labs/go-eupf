package file

import (
	"archive/zip"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreDoesNotReadOutsideBackupDirectory(t *testing.T) {
	root := t.TempDir()
	backupDir := filepath.Join(root, "backups")
	if err := os.Mkdir(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(root, "outside.zip"))
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	member, err := w.Create("config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write([]byte("logging_level: debug\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r := &FileRepository{backupDir: backupDir}
	if _, err := r.ReadUpfConfig(context.Background(), "../outside"); err == nil {
		t.Error("restore accepted an archive outside its backup directory")
	}
}

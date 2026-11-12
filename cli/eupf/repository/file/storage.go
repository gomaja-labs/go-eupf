package file

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gomaja-labs/go-eupf/cli/config"
	"github.com/gomaja-labs/go-eupf/cli/domain"
	"gopkg.in/yaml.v3"
)

// Restore budgets apply to every member, including unused members.
const (
	MaxArchiveEntries      = 32
	MaxArchiveEntrySize    = 4 << 20
	MaxArchiveExpandedSize = 16 << 20
)

type FileRepository struct {
	backupDir string
}

func NewFileRepository(cfg *config.Config) domain.EupfLocalRepository {
	return &FileRepository{
		backupDir: cfg.BackupPath,
	}
}

func (r *FileRepository) BackupList(ctx context.Context) ([]domain.BackupRecord, error) {
	entry, err := os.ReadDir(r.backupDir)
	if err != nil {
		return nil, err
	}

	var backups []domain.BackupRecord
	for _, e := range entry {
		if e.IsDir() {
			continue
		}

		if !strings.HasSuffix(e.Name(), ".zip") {
			continue
		}

		info, err := e.Info()
		if err != nil {
			return nil, fmt.Errorf("read backup info: %w", err)
		}
		name := strings.TrimSuffix(info.Name(), ".zip")

		backups = append(backups, domain.BackupRecord{
			Name:      name,
			Timestamp: info.ModTime(),
		})
	}

	return backups, nil
}

func (r *FileRepository) SaveUpfConfig(ctx context.Context, config *domain.UpfConfig) (retErr error) {
	err := os.MkdirAll(r.backupDir, os.ModePerm)
	if err != nil {
		return err
	}

	timestamp := time.Now().Unix()
	zipPath := fmt.Sprintf("%s/%d.zip", r.backupDir, timestamp)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, zipFile.Close()) }()

	zipWriter := zip.NewWriter(zipFile)
	defer func() { retErr = errors.Join(retErr, zipWriter.Close()) }()

	configFile, err := zipWriter.Create("config.yaml")
	if err != nil {
		return err
	}

	configData, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	_, err = configFile.Write(configData)
	return err
}

func (r *FileRepository) ReadUpfConfig(ctx context.Context, name string) (_ *domain.UpfConfig, retErr error) {
	if !strings.HasSuffix(name, ".zip") {
		name = name + ".zip"
	}

	if name == ".zip" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("backup name must be a filename within the backup directory")
	}
	root, err := os.OpenRoot(r.backupDir)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, root.Close()) }()
	archive, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, archive.Close()) }()
	info, err := archive.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > MaxArchiveExpandedSize {
		return nil, fmt.Errorf("backup archive exceeds %d bytes", MaxArchiveExpandedSize)
	}

	zipReader, err := zip.NewReader(archive, info.Size())
	if err != nil {
		return nil, err
	}
	if len(zipReader.File) > MaxArchiveEntries {
		return nil, fmt.Errorf("backup exceeds %d archive entries", MaxArchiveEntries)
	}
	var expanded uint64
	for _, member := range zipReader.File {
		if member.UncompressedSize64 > MaxArchiveEntrySize {
			return nil, fmt.Errorf("archive entry exceeds %d bytes", MaxArchiveEntrySize)
		}
		expanded += member.UncompressedSize64
		if expanded > MaxArchiveExpandedSize {
			return nil, fmt.Errorf("archive expands beyond %d bytes", MaxArchiveExpandedSize)
		}
	}

	var configFile *zip.File
	for _, file := range zipReader.File {
		if file.Name == "config.yaml" {
			configFile = file
			break
		}
	}

	if configFile == nil {
		return nil, fmt.Errorf("config.yaml not found in archive %s", name)
	}

	rc, err := configFile.Open()
	if err != nil {
		return nil, err
	}
	defer func() { retErr = errors.Join(retErr, rc.Close()) }()

	configData, err := io.ReadAll(io.LimitReader(rc, MaxArchiveEntrySize+1))
	if err != nil {
		return nil, err
	}

	if len(configData) > MaxArchiveEntrySize {
		return nil, fmt.Errorf("config.yaml exceeds %d bytes", MaxArchiveEntrySize)
	}
	var config domain.UpfConfig
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

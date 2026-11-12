//go:build linux

// Command mapfault freezes one named map held by an explicitly identified
// synthetic test server. It never searches unrelated processes or global maps.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 4 {
		return fmt.Errorf("usage: mapfault PID EXPECTED_EXECUTABLE MAP_NAME")
	}
	pid, err := strconv.ParseUint(os.Args[1], 10, 32)
	if err != nil || pid == 0 {
		return fmt.Errorf("invalid PID")
	}
	expected, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	process := fmt.Sprintf("/proc/%d", pid)
	executable, err := os.Readlink(filepath.Join(process, "exe"))
	if err != nil {
		return err
	}
	if executable != expected {
		return fmt.Errorf("process executable %q differs from expected %q", executable, expected)
	}
	name := os.Args[3]
	if name != "far_map" && name != "qer_map" && name != "urr_map" {
		return fmt.Errorf("unsupported fault map %q", name)
	}
	files, err := os.ReadDir(filepath.Join(process, "fdinfo"))
	if err != nil {
		return err
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(process, "fdinfo", file.Name()))
		if err != nil {
			return err
		}
		scan := bufio.NewScanner(strings.NewReader(string(data)))
		for scan.Scan() {
			fields := strings.Fields(scan.Text())
			if len(fields) != 2 || fields[0] != "map_id:" {
				continue
			}
			id, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return err
			}
			found, err := freeze(ebpf.MapID(id), name)
			if err != nil {
				return err
			}
			if found {
				return json.NewEncoder(os.Stdout).Encode(struct {
					PID   uint64
					MapID uint64
					Name  string
				}{pid, id, name})
			}
		}
		if err := scan.Err(); err != nil {
			return err
		}
	}
	return fmt.Errorf("map %q not found in specified process", name)
}
func freeze(id ebpf.MapID, name string) (bool, error) {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return false, err
	}
	defer func() { _ = m.Close() }()
	info, err := m.Info()
	if err != nil {
		return false, err
	}
	if info.Name != name {
		return false, nil
	}
	if err := m.Freeze(); err != nil {
		return false, err
	}
	return true, nil
}

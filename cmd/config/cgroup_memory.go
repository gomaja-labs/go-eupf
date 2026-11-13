package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CgroupMemoryState records the process's charge and the tightest visible
// ancestor limit. Limit zero means that no visible cgroup imposes a hard limit.
type CgroupMemoryState struct {
	Limit, Current    int64
	Path, LimitSource string
}

// CgroupMemory resolves membership and mount roots rather than assuming that
// the mount root is this process's cgroup. See the Linux kernel cgroup v2
// documentation, Memory Interface Files (memory.current and memory.max), and
// cgroup v1 Memory Resource Controller, sections 5.1 and 6 (hierarchy).
func CgroupMemory() (CgroupMemoryState, error) {
	membership, err := os.ReadFile("/proc/self/cgroup")
	if errors.Is(err, os.ErrNotExist) {
		return CgroupMemoryState{}, nil
	}
	if err != nil {
		return CgroupMemoryState{}, fmt.Errorf("read cgroup membership: %w", err)
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return CgroupMemoryState{}, fmt.Errorf("read cgroup mounts: %w", err)
	}
	return resolveCgroupMemory(string(membership), string(mounts))
}

func resolveCgroupMemory(membership, mounts string) (CgroupMemoryState, error) {
	var v1, v2 string
	for line := range strings.SplitSeq(membership, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[0] == "0" && fields[1] == "" {
			v2 = fields[2]
		}
		if containsController(fields[1], "memory") {
			v1 = fields[2]
		}
	}
	for line := range strings.SplitSeq(mounts, "\n") {
		before, after, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		left, right := strings.Fields(before), strings.Fields(after)
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		path, limitName, usageName := "", "", ""
		switch {
		case right[0] == "cgroup" && v1 != "" && containsController(right[2], "memory"):
			path, limitName, usageName = v1, "memory.limit_in_bytes", "memory.usage_in_bytes"
		case right[0] == "cgroup2" && v1 == "" && v2 != "":
			path, limitName, usageName = v2, "memory.max", "memory.current"
		default:
			continue
		}
		root, mount := unescapeMountPath(left[3]), unescapeMountPath(left[4])
		// Membership is relative to the cgroup namespace; mountinfo's root can
		// still contain its host path. Strip a matching root, otherwise use the
		// namespace-relative path (including '/' in private container namespaces).
		relative := path
		if root != "/" && (path == root || strings.HasPrefix(path, root+"/")) {
			relative = strings.TrimPrefix(path, root)
		}
		own := filepath.Join(mount, filepath.Clean("/"+relative))
		result := CgroupMemoryState{Path: own}
		var err error
		result.Current, err = readCgroupValue(filepath.Join(own, usageName), false)
		if errors.Is(err, os.ErrNotExist) && own == mount {
			continue
		} // No memory controller.
		if err != nil {
			return result, err
		}
		for dir := own; ; dir = filepath.Dir(dir) {
			file := filepath.Join(dir, limitName)
			limit, err := readCgroupValue(file, true)
			// The v2 hierarchy root has no memory.max. A v1 root can also omit it.
			if err != nil && !(dir == mount && errors.Is(err, os.ErrNotExist)) {
				return result, err
			}
			if limit > 0 && (result.Limit == 0 || limit < result.Limit) {
				result.Limit, result.LimitSource = limit, file
			}
			if dir == mount {
				break
			}
		}
		return result, nil
	}
	return CgroupMemoryState{}, nil
}

func containsController(list, controller string) bool {
	for value := range strings.SplitSeq(list, ",") {
		if value == controller {
			return true
		}
	}
	return false
}
func unescapeMountPath(path string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(path)
}
func readCgroupValue(path string, limit bool) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	value := strings.TrimSpace(string(data))
	if limit && value == "max" {
		return 0, nil
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid cgroup memory value in %s", path)
	}
	if limit && n >= 1<<60 {
		return 0, nil
	}
	return n, nil
}

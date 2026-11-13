package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCgroupMemoryResolvesMembershipAndAncestorLimits(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mountRoot := range []string{"/", "/host/container"} {
			for _, ownLimit := range []string{"max", "134217728", "536870912"} {
				t.Run(fmt.Sprintf("v%d/root=%s/limit=%s", version, mountRoot, ownLimit), func(t *testing.T) {
					root := filepath.Join(t.TempDir(), "mount with space")
					own := filepath.Join(root, "parent", "child")
					if err := os.MkdirAll(own, 0700); err != nil {
						t.Fatal(err)
					}
					limitName, usageName, member, mountType, options := "memory.max", "memory.current", "0::/parent/child", "cgroup2", "rw"
					if version == 1 {
						limitName, usageName, member, mountType, options = "memory.limit_in_bytes", "memory.usage_in_bytes", "3:cpu,memory:/parent/child", "cgroup", "rw,memory"
					}
					write := func(dir, name, value string) {
						t.Helper()
						if version == 1 && value == "max" {
							value = "9223372036854771712"
						}
						if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
							t.Fatal(err)
						}
					}
					write(root, limitName, "max")
					write(filepath.Dir(own), limitName, "268435456")
					write(own, limitName, ownLimit)
					write(own, usageName, "12345")
					write(root, usageName, "99999")
					escaped := strings.ReplaceAll(root, " ", `\040`)
					mounts := fmt.Sprintf("1 0 0:1 %s %s rw - %s cgroup %s", mountRoot, escaped, mountType, options)
					state, err := resolveCgroupMemory(member, mounts)
					expected := 256 * mib
					source := filepath.Join(filepath.Dir(own), limitName)
					if ownLimit == "134217728" {
						expected = 128 * mib
						source = filepath.Join(own, limitName)
					}
					if err != nil || state.Path != own || state.Current != 12345 || state.Limit != expected || state.LimitSource != source {
						t.Fatalf("state %+v: %v", state, err)
					}
					if mountRoot != "/" {
						member = strings.ReplaceAll(member, "/parent/child", mountRoot+"/parent/child")
						state, err = resolveCgroupMemory(member, mounts)
						if err != nil || state.Path != own || state.Limit != expected {
							t.Fatalf("host-root membership %+v: %v", state, err)
						}
					}
					write(filepath.Dir(own), limitName, "max")
					write(own, limitName, "max")
					state, err = resolveCgroupMemory(member, mounts)
					if err != nil || state.Limit != 0 || state.LimitSource != "" || state.Current != 12345 {
						t.Fatalf("unlimited %+v: %v", state, err)
					}
				})
			}
		}
	}
}

func TestCgroupMemoryMissingControllerAndInvalidCharge(t *testing.T) {
	state, err := resolveCgroupMemory("2:cpu:/child", "1 0 0:1 / /none rw - cgroup cgroup rw,cpu")
	if err != nil || state != (CgroupMemoryState{}) {
		t.Fatal(state, err)
	}
	for _, charge := range []string{"max", "-1", "bad"} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte("max"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "memory.current"), []byte(charge), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveCgroupMemory("0::/", "1 0 0:1 / "+root+" rw - cgroup2 cgroup rw"); err == nil {
			t.Fatal("accepted charge", charge)
		}
	}
}

func TestCgroupMemoryRootWithoutLimit(t *testing.T) {
	root := t.TempDir()
	mounts := "1 0 0:1 / " + root + " rw - cgroup2 cgroup rw"
	if err := os.WriteFile(filepath.Join(root, "memory.current"), []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := resolveCgroupMemory("0::/", mounts)
	if err != nil || state.Limit != 0 || state.LimitSource != "" || state.Path != root || state.Current != 12345 {
		t.Fatalf("unlimited hierarchy root %+v: %v", state, err)
	}
	if err := os.Remove(filepath.Join(root, "memory.current")); err != nil {
		t.Fatal(err)
	}
	state, err = resolveCgroupMemory("0::/", mounts)
	if err != nil || state != (CgroupMemoryState{}) {
		t.Fatalf("missing memory controller %+v: %v", state, err)
	}
}

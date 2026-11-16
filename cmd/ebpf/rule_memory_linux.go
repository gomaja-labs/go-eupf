//go:build linux

package ebpf

import "golang.org/x/sys/unix"

func mapRuleMemory(fd, size int) ([]byte, error) {
	return unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
}
func unmapRuleMemory(data []byte) error { return unix.Munmap(data) }

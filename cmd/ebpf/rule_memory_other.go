//go:build !linux

package ebpf

import "errors"

func mapRuleMemory(_, _ int) ([]byte, error) {
	return nil, errors.New("shared rule arrays require Linux")
}
func unmapRuleMemory(_ []byte) error { return nil }

//go:build !linux

package ebpf

import "github.com/cilium/ebpf"

func configureGTPRestoration(_ *ebpf.CollectionSpec) error { return nil }

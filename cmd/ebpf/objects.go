// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package ebpf

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/RoaringBitmap/roaring"
	"github.com/rs/zerolog/log"

	"github.com/cilium/ebpf"
)

//
// Supported BPF_CFLAGS:
// 	- ENABLE_LOG:
//		- enables debug output to tracepipe (`bpftool prog tracelog`)
//

//go:generate go tool bpf2go -tags linux -cflags "$BPF_CFLAGS" -target bpf IpEntrypoint 	xdp/n3n6_entrypoint.c -- -I. -O2 -Wall -g
//go:generate go tool bpf2go -tags linux -target bpf ZeroEntrypoint 	xdp/zero_entrypoint.c -- -I. -O2 -Wall
//go:generate go tool bpf2go -tags linux -target bpf N3Entrypoint 	xdp/n3_entrypoint.c -- -I. -O2 -Wall
//go:generate go tool bpf2go -tags linux -target bpf N6Entrypoint 	xdp/n6_entrypoint.c -- -I. -O2 -Wall

type BpfObjects struct {
	IpEntrypointObjects

	farIdTracker *IdTracker
	qerIdTracker *IdTracker
	urrIdTracker *IdTracker
	farMutex     sync.Mutex
	qerMutex     sync.Mutex
	urrMutex     sync.Mutex

	qerMapSize uint32
	farMapSize uint32
	pdrMapSize uint32
	urrMapSize uint32
}

func NewBpfObjects() *BpfObjects {
	return &BpfObjects{
		farMutex:   sync.Mutex{},
		qerMutex:   sync.Mutex{},
		urrMutex:   sync.Mutex{},
		qerMapSize: 1024,
		farMapSize: 1024,
		pdrMapSize: 1024,
		urrMapSize: 1024,
	}
}

func (bpfObjects *BpfObjects) SetPdrMapSize(pdrMapSize uint32) {
	bpfObjects.pdrMapSize = pdrMapSize
}

func (bpfObjects *BpfObjects) SetFarMapSize(farMapSize uint32) {
	bpfObjects.farMapSize = farMapSize
}

func (bpfObjects *BpfObjects) SetQerMapSize(qerMapSize uint32) {
	bpfObjects.qerMapSize = qerMapSize
}

func (bpfObjects *BpfObjects) SetUrrMapSize(urrMapSize uint32) {
	bpfObjects.urrMapSize = urrMapSize
}

func (bpfObjects *BpfObjects) Load() error {
	if bpfObjects.UpfIpEntrypointFunc != nil && bpfObjects.UpfIpEntrypointFunc.FD() >= 0 {
		return errors.New("BPF objects already loaded")
	}
	pinPath := "/sys/fs/bpf/upf_pipeline"
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Info().Msgf("failed to create bpf fs subpath: %+v", err)
		return err
	}

	spec, err := LoadIpEntrypoint()
	if err != nil {
		return err
	}

	desiredMapSizes := map[string]uint32{
		"qer_map":              bpfObjects.qerMapSize,
		"far_map":              bpfObjects.farMapSize,
		"pdr_map_downlink_ip4": bpfObjects.pdrMapSize,
		"pdr_map_downlink_ip6": bpfObjects.pdrMapSize,
		"pdr_map_teid_ip4":     bpfObjects.pdrMapSize,
		"urr_map":              bpfObjects.urrMapSize,
	}

	for name, size := range desiredMapSizes {
		if size == 0 {
			return errors.New("map capacity must be positive")
		}
		spec.Maps[name].MaxEntries = size
	}
	if err := spec.LoadAndAssign(&bpfObjects.IpEntrypointObjects, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}}); err != nil {
		return err
	}
	loaded := false
	defer func() {
		if !loaded {
			_ = bpfObjects.Close()
		}
	}()

	if info, err := bpfObjects.FarMap.Info(); err == nil {
		bpfObjects.farIdTracker = NewIdTracker(info.MaxEntries)

	} else {
		return err
	}

	if info, err := bpfObjects.QerMap.Info(); err == nil {
		bpfObjects.qerIdTracker = NewIdTracker(info.MaxEntries)
	} else {
		return err
	}

	if info, err := bpfObjects.UrrMap.Info(); err == nil {
		bpfObjects.urrIdTracker = NewIdTracker(info.MaxEntries)
	} else {
		return err
	}

	loaded = true
	return nil
}

func (bpfObjects *BpfObjects) Close() error {
	return CloseAllObjects(
		&bpfObjects.IpEntrypointObjects,
	)
}

type LoaderFunc func(obj interface{}, opts *ebpf.CollectionOptions) error
type Loader struct {
	LoaderFunc
	object interface{}
}

func LoadAllObjects(opts *ebpf.CollectionOptions, loaders ...Loader) error {
	for _, loader := range loaders {
		if err := loader.LoaderFunc(loader.object, opts); err != nil {
			return err
		}
	}
	return nil
}

func CloseAllObjects(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// ResizeAllMaps changes capacities before Load. Live replacement would leave
// attached programs reading old maps, so it is rejected without changing state.
func (bpfObjects *BpfObjects) ResizeAllMaps(qerMapSize, farMapSize, pdrMapSize, urrMapSize uint32) error {
	if bpfObjects.UpfIpEntrypointFunc != nil {
		return errors.New("map capacities can only change before Load")
	}
	if qerMapSize == 0 || farMapSize == 0 || pdrMapSize == 0 || urrMapSize == 0 {
		return errors.New("map capacity must be positive")
	}
	bpfObjects.qerMapSize, bpfObjects.farMapSize, bpfObjects.pdrMapSize, bpfObjects.urrMapSize = qerMapSize, farMapSize, pdrMapSize, urrMapSize
	return nil
}

func (bpfObjects *BpfObjects) GetNextQER() (uint32, error) {
	bpfObjects.qerMutex.Lock()
	defer bpfObjects.qerMutex.Unlock()
	return bpfObjects.qerIdTracker.GetNext()
}

func (bpfObjects *BpfObjects) GetNextFAR() (uint32, error) {
	bpfObjects.farMutex.Lock()
	defer bpfObjects.farMutex.Unlock()
	return bpfObjects.farIdTracker.GetNext()
}

func (bpfObjects *BpfObjects) GetNextURR() (uint32, error) {
	bpfObjects.urrMutex.Lock()
	defer bpfObjects.urrMutex.Unlock()
	return bpfObjects.urrIdTracker.GetNext()
}

func (bpfObjects *BpfObjects) ReleaseQER(qerId uint32) {
	bpfObjects.qerMutex.Lock()
	defer bpfObjects.qerMutex.Unlock()
	bpfObjects.qerIdTracker.Release(qerId)
}

func (bpfObjects *BpfObjects) ReleaseFAR(farId uint32) {
	bpfObjects.farMutex.Lock()
	defer bpfObjects.farMutex.Unlock()
	bpfObjects.farIdTracker.Release(farId)
}

func (bpfObjects *BpfObjects) ReleaseURR(urrId uint32) {
	bpfObjects.urrMutex.Lock()
	defer bpfObjects.urrMutex.Unlock()
	bpfObjects.urrIdTracker.Release(urrId)
}

type IdTracker struct {
	bitmap  *roaring.Bitmap
	maxSize uint32
}

func NewIdTracker(size uint32) *IdTracker {
	newBitmap := roaring.NewBitmap()
	newBitmap.Flip(1, uint64(size)) // Let's set 0 id as unusable

	return &IdTracker{
		bitmap:  newBitmap,
		maxSize: size,
	}
}

func (t *IdTracker) GetNext() (next uint32, err error) {

	i := t.bitmap.Iterator()
	if i.HasNext() {
		next := i.Next()
		t.bitmap.Remove(next)
		return next, nil
	}

	return 0, errors.New("pool is empty")
}

func (t *IdTracker) Release(id uint32) {
	if id == 0 || id >= t.maxSize {
		return
	}

	t.bitmap.Add(id)
}

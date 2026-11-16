// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2026 Edgecom LLC
// Copyright 2026 the go-eupf authors

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/RoaringBitmap/roaring"
	"github.com/gomaja-labs/go-eupf/cmd/config"
	"github.com/rs/zerolog/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//
// Supported BPF_CFLAGS:
// 	- ENABLE_LOG:
//		- enables debug output to tracepipe (`bpftool prog tracelog`)
//

//go:generate go tool bpf2go -tags linux -cflags "$BPF_CFLAGS" -type pdr_entry -target bpf IpEntrypoint 	xdp/n3n6_entrypoint.c -- -I. -O2 -Wall -g
//go:generate go tool bpf2go -tags linux -cflags "$BPF_CFLAGS" -target bpf BufferAdmission xdp/n3n6_entrypoint.c -- -DBUFFER_ADMISSION -I. -O2 -Wall -g
//go:generate go tool bpf2go -tags linux -cflags "$BPF_CFLAGS" -target bpf BufferEntrypoint xdp/n3n6_entrypoint.c -- -DBUFFER_CONTINUATION -I. -O2 -Wall -g
//go:generate go tool bpf2go -tags linux -target bpf ZeroEntrypoint 	xdp/zero_entrypoint.c -- -I. -O2 -Wall
//go:generate go tool bpf2go -tags linux -target bpf N3Entrypoint 	xdp/n3_entrypoint.c -- -I. -O2 -Wall
//go:generate go tool bpf2go -tags linux -target bpf N6Entrypoint 	xdp/n6_entrypoint.c -- -I. -O2 -Wall

type BpfObjects struct {
	activityMutex                    sync.RWMutex
	activityMemory                   *ebpf.Memory
	activityIDs                      *IdTracker
	renderMutex                      sync.Mutex
	prepareDone, prepareStop         chan struct{}
	prepareError                     error
	renderCollection                 *ebpf.Collection
	admissionCollection              *ebpf.Collection
	controllerCollection             *ebpf.Collection
	initialEntrypoint, initialRouter *ebpf.Program
	dataPlaneLinks                   *[]link.Link
	// UpfBufferControlFunc loads when metadata first needs serialized control.
	UpfBufferControlFunc *ebpf.Program
	// UpfBufferAdmissionFunc loads before publishing the first BUFF producer.
	UpfBufferAdmissionFunc  *ebpf.Program
	sharedConfiguration     *ebpf.Map
	renderClosed            bool
	bufferMutex             sync.Mutex
	bindingMutex            sync.Mutex
	bindingPresent          []uint64
	bufferReadClaimed       bool
	bufferReadClosed        bool
	bufferReader            *BufferReader
	bucketMutex             sync.Mutex
	bucketIDs               *IdTracker
	ruleMutex               sync.Mutex
	ruleKeys                ruleKeyIndex
	ruleImages              map[pdrMutationKey]pdrImage
	freePDRImages           [][]IpEntrypointPdrEntry // ruleMutex owns retired Go slices.
	bucketMemory, farMemory *sharedRuleMemory
	// ruleMutex serializes the synchronous map writes that borrow this buffer.
	publicationBucket IpEntrypointPdrBucket
	rulePoison        error
	ruleClosed        bool
	grace             *ruleGrace
	IpEntrypointObjects

	farIdTracker *IdTracker
	qerIdTracker *IdTracker
	urrIdTracker *IdTracker
	farMutex     sync.Mutex
	qerMutex     sync.Mutex
	urrMutex     sync.Mutex

	qerMapSize     uint32
	farMapSize     uint32
	pdrMapSize     uint32
	urrMapSize     uint32
	bufferSessions uint32
	bufferPackets  uint32
}

func NewBpfObjects() *BpfObjects {
	return &BpfObjects{
		farMutex:       sync.Mutex{},
		qerMutex:       sync.Mutex{},
		urrMutex:       sync.Mutex{},
		qerMapSize:     1024,
		farMapSize:     1024,
		pdrMapSize:     1024,
		urrMapSize:     1024,
		bufferSessions: 65535,
		bufferPackets:  4096,
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

// SetBufferCapacity sizes session metadata independently of the payload pool.
func (bpfObjects *BpfObjects) SetBufferCapacity(sessions, packets uint32) {
	if sessions == 0 {
		sessions = 65535
	}
	if packets == 0 {
		packets = 4096
	}
	bpfObjects.bufferSessions, bpfObjects.bufferPackets = sessions, packets
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
	bucketCapacity, err := PDRBucketCapacity(bpfObjects.pdrMapSize)
	if err != nil {
		return err
	}

	farCapacity, err := RuleVersionCapacity(bpfObjects.farMapSize)
	if err != nil {
		return err
	}
	qerCapacity, err := QERVersionCapacity(bpfObjects.qerMapSize)
	if err != nil {
		return err
	}
	urrCapacity, err := RuleVersionCapacity(bpfObjects.urrMapSize)
	if err != nil {
		return err
	}

	desiredMapSizes := map[string]uint32{
		"qer_map":                qerCapacity,
		"far_map":                farCapacity,
		"pdr_map_downlink_ip4":   bpfObjects.pdrMapSize,
		"pdr_map_downlink_ip6":   bpfObjects.pdrMapSize,
		"pdr_map_teid_ip4":       bpfObjects.pdrMapSize,
		"pdr_buckets":            bucketCapacity,
		"buffer_generic_ingress": config.GenericIngressCapacity,
		"urr_map":                urrCapacity,
		"buffer_anchors":         bpfObjects.bufferSessions,
		"session_activity":       bpfObjects.bufferSessions + 1,
		"buffer_bindings":        farCapacity,
		"buffer_states":          2 * farCapacity,
		"buffer_notice_ready":    bpfObjects.bufferSessions,
	}

	for name, size := range desiredMapSizes {
		if size == 0 {
			return errors.New("map capacity must be positive")
		}
		spec.Maps[name].MaxEntries = size
	}
	if err := configureGTPRestoration(spec); err != nil {
		return err
	}
	var objects struct {
		IpEntrypointObjects
		Configuration *ebpf.Map `ebpf:".bss"`
	}
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}}); err != nil {
		return err
	}
	bpfObjects.IpEntrypointObjects = objects.IpEntrypointObjects
	bpfObjects.sharedConfiguration = objects.Configuration
	bpfObjects.bindingPresent = make([]uint64, (uint64(farCapacity)+63)/64)
	// Own freshly assigned handles even if subsequent initialization fails.
	bpfObjects.ruleClosed = false
	bpfObjects.bufferMutex.Lock()
	bpfObjects.bufferReadClaimed = false
	bpfObjects.bufferReadClosed = false
	bpfObjects.bufferReader = nil
	bpfObjects.bufferMutex.Unlock()
	bpfObjects.ruleKeys = ruleKeyIndex{}
	bpfObjects.ruleImages = make(map[pdrMutationKey]pdrImage)
	bpfObjects.bucketIDs = NewIdTracker(bucketCapacity)
	loaded := false
	defer func() {
		if !loaded {
			_ = bpfObjects.Close()
		}
	}()

	if info, err := bpfObjects.FarMap.Info(); err == nil {
		bpfObjects.farIdTracker = newVersionIDTracker(bpfObjects.farMapSize, info.MaxEntries)
	} else {
		return err
	}

	if info, err := bpfObjects.QerMap.Info(); err == nil {
		bpfObjects.qerIdTracker = newVersionIDTracker(bpfObjects.qerMapSize, info.MaxEntries)
	} else {
		return err
	}

	if info, err := bpfObjects.UrrMap.Info(); err == nil {
		bpfObjects.urrIdTracker = newVersionIDTracker(bpfObjects.urrMapSize, info.MaxEntries)
	} else {
		return err
	}

	bpfObjects.bucketMemory, err = newSharedRuleMemory(bpfObjects.PdrBuckets, unsafe.Sizeof(IpEntrypointPdrBucket{}))
	if err != nil {
		return fmt.Errorf("map PDR bucket storage: %w", err)
	}
	bpfObjects.farMemory, err = newSharedRuleMemory(bpfObjects.FarMap, unsafe.Sizeof(IpEntrypointFarInfo{}))
	if err != nil {
		return fmt.Errorf("map FAR storage: %w", err)
	}
	bpfObjects.grace, err = newRuleGrace()
	if err != nil {
		return err
	}
	if err := bpfObjects.ConfigureBufferPool(bpfObjects.bufferPackets); err != nil {
		return err
	}
	if err := bpfObjects.configureBufferToken(); err != nil {
		return err
	}
	bpfObjects.renderClosed = false
	if err := bpfObjects.initSessionActivity(); err != nil {
		return err
	}
	loaded = true
	return nil
}

func (bpfObjects *BpfObjects) Close() error {
	bpfObjects.ruleMutex.Lock()
	if bpfObjects.ruleClosed {
		bpfObjects.ruleMutex.Unlock()
		return nil
	}
	bpfObjects.ruleClosed = true
	grace := bpfObjects.grace
	bpfObjects.ruleMutex.Unlock()
	bpfObjects.bufferMutex.Lock()
	reader := bpfObjects.bufferReader
	bpfObjects.bufferReader = nil
	bpfObjects.bufferReadClosed = true
	bpfObjects.bufferMutex.Unlock()
	var err error
	if reader != nil {
		err = reader.Close()
	}
	if grace != nil {
		err = errors.Join(err, grace.close())
	}
	bpfObjects.renderMutex.Lock()
	bpfObjects.renderClosed = true
	if bpfObjects.prepareStop != nil {
		close(bpfObjects.prepareStop)
		bpfObjects.prepareStop = nil
	}
	for _, program := range []*ebpf.Program{bpfObjects.initialEntrypoint, bpfObjects.initialRouter} {
		if program != nil {
			err = errors.Join(err, program.Close())
		}
	}
	bpfObjects.initialEntrypoint, bpfObjects.initialRouter = nil, nil
	bpfObjects.dataPlaneLinks = nil
	if bpfObjects.renderCollection != nil {
		bpfObjects.renderCollection.Close()
		bpfObjects.renderCollection = nil
	}
	if bpfObjects.admissionCollection != nil {
		bpfObjects.admissionCollection.Close()
		bpfObjects.admissionCollection = nil
	}
	if bpfObjects.controllerCollection != nil {
		bpfObjects.controllerCollection.Close()
		bpfObjects.controllerCollection = nil
	}
	bpfObjects.UpfBufferControlFunc = nil
	bpfObjects.UpfBufferAdmissionFunc = nil
	if bpfObjects.sharedConfiguration != nil {
		err = errors.Join(err, bpfObjects.sharedConfiguration.Close())
		bpfObjects.sharedConfiguration = nil
	}
	bpfObjects.renderMutex.Unlock()
	bpfObjects.activityMutex.Lock()
	defer bpfObjects.activityMutex.Unlock()
	err = errors.Join(err, bpfObjects.bucketMemory.close(), bpfObjects.farMemory.close())
	bpfObjects.bucketMemory, bpfObjects.farMemory = nil, nil
	bpfObjects.activityMemory = nil
	bpfObjects.activityIDs = nil
	return errors.Join(err, CloseAllObjects(
		&bpfObjects.IpEntrypointObjects,
	))
}

type (
	LoaderFunc func(obj interface{}, opts *ebpf.CollectionOptions) error
	Loader     struct {
		LoaderFunc
		object interface{}
	}
)

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
	bpfObjects.renderMutex.Lock()
	defer bpfObjects.renderMutex.Unlock()
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
	return bpfObjects.nextRuleID(bpfObjects.qerIdTracker, &bpfObjects.qerMutex, nil, true)
}

func (bpfObjects *BpfObjects) GetNextFAR() (uint32, error) {
	return bpfObjects.nextRuleID(bpfObjects.farIdTracker, &bpfObjects.farMutex, nil, true)
}

func (bpfObjects *BpfObjects) GetNextURR() (uint32, error) {
	return bpfObjects.nextRuleID(bpfObjects.urrIdTracker, &bpfObjects.urrMutex, nil, true)
}

func (b *BpfObjects) nextRuleID(ids *IdTracker, mu *sync.Mutex, deadline *time.Time, commitLive bool) (uint32, error) {
	atLiveLimit := false
	allocate := func() (uint32, error) {
		mu.Lock()
		defer mu.Unlock()
		if commitLive && ids.live != nil && ids.liveCount >= ids.liveLimit {
			atLiveLimit = true
			return 0, ErrRuleCapacity
		}
		id, err := ids.GetNext()
		if err == nil && commitLive {
			ids.markLive(id)
		}
		return id, err
	}
	id, err := allocate()
	if err == nil || b.grace == nil || atLiveLimit {
		return id, err
	}
	var local time.Time
	if deadline == nil {
		deadline = &local
	}
	if deadline.IsZero() {
		*deadline = time.Now().Add(ruleCapacityWait)
	}
	if err := b.grace.waitForCapacity(*deadline); err != nil {
		return 0, err
	}
	return allocate()
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
	bitmap               *roaring.Bitmap
	maxSize              uint32
	live                 []uint64
	liveLimit, liveCount uint32
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
	if !t.bitmap.IsEmpty() {
		next := t.bitmap.Minimum()
		t.bitmap.Remove(next)
		return next, nil
	}

	return 0, ErrRuleCapacity
}

func (t *IdTracker) Release(id uint32) {
	if id == 0 || id >= t.maxSize {
		return
	}

	t.unmarkLive(id)
	t.bitmap.Add(id)
}

// EditDataPlaneLinks serializes interface edits with first-BUFF program
// installation. The edit callback owns the link slice until it returns.
func (b *BpfObjects) EditDataPlaneLinks(links *[]link.Link, edit func(*ebpf.Program) error) error {
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.renderClosed || b.UpfIpEntrypointFunc == nil || b.UpfIpEntrypointFunc.FD() < 0 {
		return errors.New("dataplane program is not loaded")
	}
	if b.dataPlaneLinks != nil && b.dataPlaneLinks != links {
		return errors.New("dataplane link owner already registered")
	}
	b.dataPlaneLinks = links
	return edit(b.UpfIpEntrypointFunc)
}

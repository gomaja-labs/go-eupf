//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	cilium "github.com/cilium/ebpf"
)

// StartBufferPrograms verifies private forwarding away from PFCP and readiness.
// It is idempotent; a failure is final for this process. The loader owns duplicate
// descriptors so Close never waits for verification or closes its inputs.
func (b *BpfObjects) StartBufferPrograms(ctx context.Context) <-chan struct{} {
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.prepareDone != nil {
		return b.prepareDone
	}
	b.prepareDone, b.prepareStop = make(chan struct{}), make(chan struct{})
	if b.renderClosed {
		b.prepareError = errors.New("buffer output is closed")
		close(b.prepareDone)
		return b.prepareDone
	}
	snapshot, err := b.cloneBufferLoaderLocked()
	if err != nil {
		b.prepareError = err
		close(b.prepareDone)
		return b.prepareDone
	}
	go b.prepareBufferPrograms(ctx, snapshot)
	return b.prepareDone
}

func (b *BpfObjects) cloneBufferLoaderLocked() (_ *BpfObjects, err error) {
	snapshot := &BpfObjects{bufferPackets: b.bufferPackets}
	defer func() {
		if err != nil {
			snapshot.closeBufferLoader()
		}
	}()
	source, target := reflect.ValueOf(b.IpEntrypointMaps), reflect.ValueOf(&snapshot.IpEntrypointMaps).Elem()
	for i := 0; i < source.NumField(); i++ {
		original, ok := source.Field(i).Interface().(*cilium.Map)
		if !ok || original == nil {
			return nil, fmt.Errorf("missing buffer input map %s", source.Type().Field(i).Name)
		}
		cloned, cloneErr := original.Clone()
		if cloneErr != nil {
			return nil, cloneErr
		}
		target.Field(i).Set(reflect.ValueOf(cloned))
	}
	snapshot.sharedConfiguration, err = b.sharedConfiguration.Clone()
	if err != nil {
		return nil, err
	}
	// Metadata remains usable when only the forwarding program is unavailable.
	snapshot.UpfIpEntrypointFunc, snapshot.prepareError = b.UpfIpEntrypointFunc.Clone()
	return snapshot, nil
}

func (b *BpfObjects) prepareBufferPrograms(ctx context.Context, snapshot *BpfObjects) {
	defer snapshot.closeBufferLoader()
	err := snapshot.loadBufferControllerLocked()
	if err == nil {
		err = snapshot.prepareError
	}
	if err == nil {
		snapshot.admissionCollection, err = snapshot.loadSharedBufferPrograms("upf_ip_entrypoint_func", "upf_router_solicitation_func", "upf_buffer_process_func", "upf_buffer_downlink_func", "upf_buffer_admission_func")
		if err == nil {
			snapshot.UpfBufferAdmissionFunc = snapshot.admissionCollection.Programs["upf_buffer_admission_func"]
			_, err = snapshot.loadBufferRendererLocked()
		}
	}
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	// A finished verifier must never install into a closing process.
	if b.renderClosed || ctx.Err() != nil {
		err = errors.Join(err, ctx.Err(), errors.New("buffer initialization canceled"))
	} else {
		if b.controllerCollection == nil && snapshot.controllerCollection != nil {
			b.controllerCollection, snapshot.controllerCollection = snapshot.controllerCollection, nil
			b.UpfBufferControlFunc = b.controllerCollection.Programs["upf_buffer_control_func"]
		}
		if err == nil {
			admission := snapshot.admissionCollection
			// publishBufferAdmissionLocked owns (and closes on failure) it.
			snapshot.admissionCollection = nil
			err = b.publishBufferAdmissionLocked(admission)
			if err == nil {
				b.renderCollection, snapshot.renderCollection = snapshot.renderCollection, nil
			}
		}
	}
	b.prepareError = err
	close(b.prepareDone)
}

func (b *BpfObjects) closeBufferLoader() {
	for _, collection := range []*cilium.Collection{b.renderCollection, b.admissionCollection, b.controllerCollection} {
		if collection != nil {
			collection.Close()
		}
	}
	maps := reflect.ValueOf(b.IpEntrypointMaps)
	for i := 0; i < maps.NumField(); i++ {
		if m, ok := maps.Field(i).Interface().(*cilium.Map); ok && m != nil {
			_ = m.Close()
		}
	}
	_ = b.sharedConfiguration.Close()
	_ = b.UpfIpEntrypointFunc.Close()
}

func (b *BpfObjects) waitBufferPreparation() error {
	b.renderMutex.Lock()
	done, stop := b.prepareDone, b.prepareStop
	closed := b.renderClosed
	b.renderMutex.Unlock()
	if closed {
		return errors.New("buffer output is closed")
	}
	if done == nil {
		return errors.New("background buffer initialization has not started")
	}
	select {
	case <-done:
	case <-stop:
		return errors.New("buffer output is closed")
	}
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.renderClosed {
		return errors.New("buffer output is closed")
	}
	return b.prepareError
}

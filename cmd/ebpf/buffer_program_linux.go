//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"reflect"

	cilium "github.com/cilium/ebpf"
)

const bufferOutputSize = BufferFrameSize + 64

type renderKey struct {
	SessionID, Cookie, Sequence uint64
	Lane, Reserved              uint32
}
type renderResult struct {
	Status                                  uint64
	Action, Ifindex, IngressIfindex, Length uint32
	Reserved                                uint64
	Frame                                   [bufferOutputSize]byte
}

func (result *renderResult) packet() (RenderedBuffer, error) {
	if result.Action > 4 || result.Length > bufferOutputSize || result.Action >= 2 && result.Length < 14 {
		return RenderedBuffer{}, errors.New("invalid completed buffer result")
	}
	return RenderedBuffer{Frame: result.Frame[:result.Length], Action: result.Action, Ifindex: result.Ifindex, IngressIfindex: result.IngressIfindex}, nil
}

// Only rendering loads these private programs. Packet classification/routing
// is compiled from the same source with output capture, while ordinary FORW
// programs keep their existing instructions and maps.
func (b *BpfObjects) loadBufferRendererLocked() (*cilium.Collection, error) {
	if b.renderClosed || b.UpfIpEntrypointFunc == nil || b.UpfIpEntrypointFunc.FD() < 0 {
		return nil, errors.New("buffer programs are not loaded")
	}
	if err := b.loadBufferAdmissionLocked(); err != nil {
		return nil, err
	}
	if b.renderCollection != nil {
		return b.renderCollection, nil
	}
	spec, err := LoadBufferEntrypoint()
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{"upf_ip_entrypoint_func": true, "upf_router_solicitation_func": true, "upf_buffer_render_func": true, "upf_buffer_kernel_func": true, "upf_buffer_downlink_func": true, "upf_buffer_process_func": true}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	spec.Maps["jmp_table"].Contents = []cilium.MapKV{{Key: uint32(0), Value: "upf_ip_entrypoint_func"}, {Key: uint32(1), Value: "upf_router_solicitation_func"}, {Key: uint32(2), Value: "upf_buffer_process_func"}, {Key: uint32(4), Value: "upf_buffer_downlink_func"}}
	spec.Maps["buffer_rendered"].MaxEntries = b.bufferPackets
	replacements := make(map[string]*cilium.Map)
	maps := reflect.ValueOf(b.IpEntrypointMaps)
	for i := 0; i < maps.NumField(); i++ {
		name := maps.Type().Field(i).Tag.Get("ebpf")
		if name == "jmp_table" || spec.Maps[name] == nil {
			continue
		}
		m, ok := maps.Field(i).Interface().(*cilium.Map)
		if !ok || m == nil {
			return nil, fmt.Errorf("missing shared buffer map %s", name)
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		spec.Maps[name].MaxEntries = info.MaxEntries
		replacements[name] = m
	}
	replacements[".bss"] = b.sharedConfiguration
	collection, err := cilium.NewCollectionWithOptions(spec, cilium.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return nil, fmt.Errorf("load private buffer programs: %w", err)
	}
	if err := collection.Maps["jmp_table"].Put(uint32(3), b.UpfBufferAdmissionFunc); err != nil {
		collection.Close()
		return nil, err
	}
	b.renderCollection = collection
	return collection, nil
}

// BufferKernelIngressProgram waits for background initialization and returns
// an owned duplicate. Shutdown cannot close this descriptor during TC setup.
func (b *BpfObjects) BufferKernelIngressProgram() (*cilium.Program, error) {
	if err := b.waitBufferPreparation(); err != nil {
		return nil, err
	}
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.renderClosed || b.renderCollection == nil {
		return nil, errors.New("buffer output is closed")
	}
	return b.renderCollection.Programs["upf_buffer_kernel_func"].Clone()
}

func (b *BpfObjects) discardBufferRender(command BufferCommand) error {
	if b.renderCollection == nil {
		return nil
	}
	err := b.renderCollection.Maps["buffer_rendered"].Delete(renderKey{SessionID: command.SessionID, Cookie: command.Cookie, Sequence: command.Sequence, Lane: command.Lane})
	if errors.Is(err, cilium.ErrKeyNotExist) {
		return nil
	}
	return err
}

// Load and install the BUFF-capable entrypoint and its policing/admission
// continuations before publishing the first BUFF FAR. The initial program
// retains the base rejection path; both builds share all live rule maps.
func (b *BpfObjects) loadBufferAdmissionLocked() error {
	if b.renderClosed || b.UpfIpEntrypointFunc == nil || b.UpfIpEntrypointFunc.FD() < 0 {
		return errors.New("buffer programs are not loaded")
	}
	if b.admissionCollection != nil {
		return nil
	}
	if err := b.loadBufferControllerLocked(); err != nil {
		return err
	}
	collection, err := b.loadSharedBufferPrograms("upf_ip_entrypoint_func", "upf_router_solicitation_func", "upf_buffer_process_func", "upf_buffer_downlink_func", "upf_buffer_admission_func")
	if err != nil {
		return fmt.Errorf("load buffer admission: %w", err)
	}
	return b.publishBufferAdmissionLocked(collection)
}

func (b *BpfObjects) publishBufferAdmissionLocked(collection *cilium.Collection) error {
	if err := b.JmpTable.Put(uint32(4), collection.Programs["upf_buffer_downlink_func"]); err != nil {
		collection.Close()
		return err
	}
	if err := b.JmpTable.Put(uint32(3), collection.Programs["upf_buffer_admission_func"]); err != nil {
		err = errors.Join(err, b.JmpTable.Delete(uint32(4)))
		collection.Close()
		return err
	}
	if err := b.JmpTable.Put(uint32(2), collection.Programs["upf_buffer_process_func"]); err != nil {
		err = errors.Join(err, b.JmpTable.Delete(uint32(3)), b.JmpTable.Delete(uint32(4)))
		collection.Close()
		return err
	}
	if err := b.installBufferEntrypoint(collection); err != nil {
		err = errors.Join(err, b.JmpTable.Delete(uint32(2)), b.JmpTable.Delete(uint32(3)), b.JmpTable.Delete(uint32(4)))
		collection.Close()
		return err
	}
	b.UpfBufferAdmissionFunc = collection.Programs["upf_buffer_admission_func"]
	b.admissionCollection = collection
	return nil
}

func (b *BpfObjects) prepareBufferAdmission() error {
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	return b.loadBufferAdmissionLocked()
}

// Metadata operations need the controller, not packet output. In particular a
// BAR-only owner remains usable when private forwarding cannot initialize.
func (b *BpfObjects) loadBufferControllerLocked() error {
	if b.renderClosed || b.BufferPool == nil || b.BufferPool.FD() < 0 {
		return errors.New("buffer control is not loaded")
	}
	if b.controllerCollection != nil {
		return nil
	}
	collection, err := b.loadSharedBufferPrograms("upf_buffer_control_func")
	if err != nil {
		return fmt.Errorf("load buffer control: %w", err)
	}
	b.UpfBufferControlFunc = collection.Programs["upf_buffer_control_func"]
	b.controllerCollection = collection
	return nil
}

func (b *BpfObjects) bufferControlProgram() (*cilium.Program, error) {
	b.renderMutex.Lock()
	started := b.prepareDone != nil
	b.renderMutex.Unlock()
	if started {
		_ = b.waitBufferPreparation()
	}
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	if b.renderClosed {
		return nil, errors.New("buffer control is closed")
	}
	if b.controllerCollection == nil && started {
		return nil, b.prepareError
	}
	if err := b.loadBufferControllerLocked(); err != nil {
		return nil, err
	}
	if b.UpfBufferControlFunc == nil || b.UpfBufferControlFunc.FD() < 0 {
		return nil, errors.New("buffer control is not loaded")
	}
	return b.UpfBufferControlFunc, nil
}

// The deferred programs own only program FDs and cloned references to the
// primary maps; neither loading them nor changing configuration copies state.
// The caller holds renderMutex through publication of the collection.
func (b *BpfObjects) loadSharedBufferPrograms(names ...string) (*cilium.Collection, error) {
	spec, err := LoadBufferAdmission()
	if err != nil {
		return nil, err
	}
	keep := make(map[string]bool, len(names))
	for _, name := range names {
		keep[name] = true
	}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	spec.Maps["jmp_table"].Contents = nil
	replacements := map[string]*cilium.Map{".bss": b.sharedConfiguration}
	maps := reflect.ValueOf(b.IpEntrypointMaps)
	for i := 0; i < maps.NumField(); i++ {
		name := maps.Type().Field(i).Tag.Get("ebpf")
		if spec.Maps[name] == nil {
			continue
		}
		m, ok := maps.Field(i).Interface().(*cilium.Map)
		if !ok || m == nil {
			return nil, fmt.Errorf("missing shared buffer map %s", name)
		}
		info, err := m.Info()
		if err != nil {
			return nil, err
		}
		spec.Maps[name].MaxEntries = info.MaxEntries
		replacements[name] = m
	}
	return cilium.NewCollectionWithOptions(spec, cilium.CollectionOptions{MapReplacements: replacements})
}

// All existing rules still use the base actions here. Roll back a failed
// installation before the caller can publish any BUFF rule. Both versions
// share maps and have identical FORW behavior throughout the transition.
func (b *BpfObjects) installBufferEntrypoint(collection *cilium.Collection) error {
	next, router := collection.Programs["upf_ip_entrypoint_func"], collection.Programs["upf_router_solicitation_func"]
	restore := func() error {
		return errors.Join(b.JmpTable.Put(uint32(0), b.UpfIpEntrypointFunc), b.JmpTable.Put(uint32(1), b.UpfRouterSolicitationFunc))
	}
	if err := b.JmpTable.Put(uint32(1), router); err != nil {
		return err
	}
	if err := b.JmpTable.Put(uint32(0), next); err != nil {
		return errors.Join(err, restore())
	}
	if b.dataPlaneLinks != nil {
		for i, l := range *b.dataPlaneLinks {
			if err := l.Update(next); err != nil {
				failures := []error{fmt.Errorf("install buffered dataplane on link %d: %w", i, err), restore()}
				for _, previous := range (*b.dataPlaneLinks)[:i] {
					failures = append(failures, previous.Update(b.UpfIpEntrypointFunc))
				}
				return errors.Join(failures...)
			}
		}
	}
	b.initialEntrypoint, b.initialRouter = b.UpfIpEntrypointFunc, b.UpfRouterSolicitationFunc
	b.UpfIpEntrypointFunc, b.UpfRouterSolicitationFunc = next, router
	delete(collection.Programs, "upf_ip_entrypoint_func")
	delete(collection.Programs, "upf_router_solicitation_func")
	return nil
}

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
	if b.renderCollection != nil {
		return b.renderCollection, nil
	}
	spec, err := LoadBufferEntrypoint()
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{"upf_ip_entrypoint_func": true, "upf_router_solicitation_func": true, "upf_buffer_render_func": true, "upf_buffer_kernel_func": true, "upf_buffer_downlink_func": true}
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	spec.Maps["jmp_table"].Contents = []cilium.MapKV{{Key: uint32(0), Value: "upf_ip_entrypoint_func"}, {Key: uint32(1), Value: "upf_router_solicitation_func"}, {Key: uint32(3), Value: "upf_buffer_downlink_func"}}
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
	collection, err := cilium.NewCollectionWithOptions(spec, cilium.CollectionOptions{MapReplacements: replacements})
	if err != nil {
		return nil, fmt.Errorf("load private buffer programs: %w", err)
	}
	if err := collection.Maps["jmp_table"].Put(uint32(2), b.UpfBufferAdmissionFunc); err != nil {
		collection.Close()
		return nil, err
	}
	b.renderCollection = collection
	return collection, nil
}

func (b *BpfObjects) copyBufferConfiguration(collection *cilium.Collection) error {
	var config IpEntrypointDataplaneConfig
	var until uint64
	if err := b.GlobalConfig.Get(&config); err != nil {
		return err
	}
	if err := b.GtpErrorSuppressUntil.Get(&until); err != nil {
		return err
	}
	if err := collection.Variables["global_config"].Set(config); err != nil {
		return err
	}
	return collection.Variables["gtp_error_suppress_until"].Set(until)
}

// BufferKernelIngressProgram prepares all buffered forwarding programs before
// runtime readiness and returns the TC program owned by these BpfObjects.
func (b *BpfObjects) BufferKernelIngressProgram() (*cilium.Program, error) {
	b.renderMutex.Lock()
	defer b.renderMutex.Unlock()
	collection, err := b.loadBufferRendererLocked()
	if err != nil {
		return nil, err
	}
	return collection.Programs["upf_buffer_kernel_func"], nil
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

//go:build !linux

package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

type IpEntrypointObjects struct {
	BufferToken               *ebpf.Map
	BufferContinuationStat    *ebpf.Map
	BufferBindings            *ebpf.Map
	BufferStates              *ebpf.Map
	BufferPool                *ebpf.Map
	BufferNoticeReady         *ebpf.Map
	BufferRequest             *ebpf.Map
	BufferPendingPacket       *ebpf.Map
	BufferAnchors             *ebpf.Map
	BufferEvents              *ebpf.Map
	UpfIpEntrypointFunc       *ebpf.Program
	UpfRouterSolicitationFunc *ebpf.Program
	FarMap                    *ebpf.Map
	QerMap                    *ebpf.Map
	UrrMap                    *ebpf.Map
	PdrMapDownlinkIp4         *ebpf.Map
	PdrMapDownlinkIp6         *ebpf.Map
	PdrMapTeidIp4             *ebpf.Map
	PdrBuckets                *ebpf.Map
	SdfNotifyMap              *ebpf.Map
	TraceMap                  *ebpf.Map
	UpfExtStat                *ebpf.Map
	UpfPipeline               *ebpf.Map
	UpfRouteStat              *ebpf.Map
	GlobalConfig              *ebpf.Variable
	GtpErrorSuppressUntil     *ebpf.Variable
}

type IpEntrypointDataplaneConfig struct {
	N3Ipv4Address     uint32
	N9Ipv4Address     uint32
	TraceIn           uint8
	TraceOut          uint8
	TraceBlocked      uint8
	Ip6RaSupport      uint8
	Ip6RaPrefix       [16]byte /* uint128 */
	Ip6RaPrefixLength uint16
}

func (o *IpEntrypointObjects) Close() error { return nil }

type IpEntrypointPdrEntry struct {
	MatchMode uint8
	_         [3]byte
	Pdr       struct {
		FarId                      uint32
		QerId                      [4]uint32
		QerCount                   uint8
		_                          [3]byte
		UrrId                      [3]uint32
		OuterHeaderRemoval         uint8
		OuterHeaderRemovalPresent  uint8
		GtpExtensionHeaderDeletion uint8
		_                          [1]byte
	}
	ReturnPdr struct {
		FarId                      uint32
		QerId                      [4]uint32
		QerCount                   uint8
		_                          [3]byte
		UrrId                      [3]uint32
		OuterHeaderRemoval         uint8
		OuterHeaderRemovalPresent  uint8
		GtpExtensionHeaderDeletion uint8
		_                          [1]byte
	}
	ReturnNrFlag           uint8
	_                      [3]byte
	PdrId                  uint32
	Precedence             uint32
	Notify                 uint64
	UeIp4                  uint32
	UeMask4                uint32
	UeIp6                  [16]uint8
	UeMask6                [16]uint8
	UeIp4Present           uint8
	UeIp6Present           uint8
	_                      [2]byte
	AssignedIp4            uint32
	AssignedIp6            [16]uint8
	AssignedMask6          [16]uint8
	AssignedIp4Present     uint8
	AssignedIp6Present     uint8
	UeDestination          uint8
	SourceInterfacePresent uint8
	SourceInterface        uint8
	TraceFlag              uint8
	NrFlag                 uint8
	SdfCount               uint8
	QfiCount               uint8
	Qfis                   [8]uint8
	_                      [7]byte
	SdfFilters             [5]struct {
		Protocol     uint16
		PortsPresent uint8
		_            [13]byte
		SrcAddr      struct {
			Type uint8
			_    [15]byte
			Ip   [16]byte /* uint128 */
			Mask [16]byte /* uint128 */
		}
		SrcPort struct {
			LowerBound uint16
			UpperBound uint16
		}
		_       [12]byte
		DstAddr struct {
			Type uint8
			_    [15]byte
			Ip   [16]byte /* uint128 */
			Mask [16]byte /* uint128 */
		}
		DstPort struct {
			LowerBound uint16
			UpperBound uint16
		}
		_ [12]byte
	}
}

type IpEntrypointPdrInfo struct {
	SessionId uint64
	Count     uint32
	_         [4]byte
	Entries   [4]IpEntrypointPdrEntry
}

type IpEntrypointQerInfo struct {
	UlGateStatus     uint8
	DlGateStatus     uint8
	Qfi              uint8
	QfiPresent       uint8
	Rqi              uint8
	Dscp             uint8
	_                [2]byte
	UlMaximumBitrate uint64
	DlMaximumBitrate uint64
	UlStart          uint64
	DlStart          uint64
	PolicerId        uint32
	_                [4]byte
}

type IpEntrypointFarInfo struct {
	Action                      uint8
	OuterHeaderCreation         uint8
	EndMarkerSuppressed         uint8
	InsertHandoverContainer     uint8
	Teid                        uint32
	Remoteip                    uint32
	TransportLevelMarking       uint16
	DestinationInterface        uint8
	DestinationInterfacePresent uint8
}

type IpEntrypointUrrInfo struct {
	Ul uint64
	Dl uint64
}

type IpEntrypointUpfStatistic struct {
	XdpActions  [16]uint64
	UpfCounters UpfCounters
}

type IpEntrypointRouteStat struct {
	FibLookupIp4Ok        uint64
	FibLookupIp4ErrorDrop uint64
	FibLookupIp4ErrorPass uint64
	FibLookupIp6Ok        uint64
	FibLookupIp6ErrorDrop uint64
	FibLookupIp6ErrorPass uint64
}

func LoadIpEntrypoint() (*ebpf.CollectionSpec, error) {
	return nil, errors.New("ebpf generation requires Linux")
}

type IpEntrypointIpv6PdrKey struct {
	PrefixLength uint32
	Address      [16]uint8
}

type IpEntrypointPdrBucket struct {
	Key, Kind uint32
	_         [8]byte
	Info      IpEntrypointPdrInfo
}
type IpEntrypointPdrIndex struct {
	Lock struct{ Val uint32 }
	Slot uint32
}

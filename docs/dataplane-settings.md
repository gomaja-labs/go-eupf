# Data-plane configuration settings

[Configuration reference](Configuration.md) · [Advertised addresses](advertised-addresses.md) ·
[Packet behaviour and limits](dataplane.md)

[Upstream #398](https://github.com/edgecomllc/eupf/issues/398) asks for startup
configuration of eBPF behaviour, particularly local N3 IP, instead of build
options. The current program has a writable `global_config` data section;
startup populates it through `BpfObjects.GlobalConfig.Set`. N3/N9 can also be
edited through REST. This does not require recompiling for each address.
See `dataplane_config` in
[`cmd/ebpf/xdp/n3n6_entrypoint.c`](../cmd/ebpf/xdp/n3n6_entrypoint.c) and
`entrypointConfig` in [`cmd/main.go`](../cmd/main.go).

## Settings copied into the XDP global configuration

Defaults below are startup defaults from `defineFlags` in
[`cmd/config/config.go`](../cmd/config/config.go). Its `UpfConfig.Validate`
validates both startup and REST candidates before applying them.

| Key | Purpose | Default | Accepted value and validator | Change application |
| --- | --- | --- | --- | --- |
| `n3_address` | Local receive address and downlink GTP-U encapsulation source | `127.0.0.1` | IPv4 literal; `ipv4` struct tag | REST N3/N9 section or restart |
| `n9_address` | Local receive address and N9 tunnel-forwarding source | Startup `n3_address` | IPv4 literal; `ipv4` struct tag | REST N3/N9 section or restart |
| `trace_in` | Capture incoming packets selected for subscriber tracing | `true` | Boolean decoded at startup; no extra validation tag | Restart |
| `trace_out` | Capture traced packets returned as XDP_TX or XDP_REDIRECT | `true` | Boolean decoded at startup; no extra validation tag | Restart |
| `trace_blocked` | Capture packets whose final action is neither XDP_TX nor XDP_REDIRECT | `false` | Boolean decoded at startup; no extra validation tag | Restart |
| `ip6_ra_support` | Enable the Router Solicitation / Advertisement path | `false` | Boolean decoded at startup; no extra validation tag | Restart |
| `ip6_ra_prefix` | Prefix used to construct Router Advertisements when enabled | `2a03:d000:29a0:509::/64` | IPv6 CIDR, including when RA is disabled; `cidrv6` struct tag | Restart |

`trace_blocked` follows the final action check, so it can include XDP_PASS and
XDP_ABORTED as well as XDP_DROP, and does not require the subscriber trace flag
in that check. It is not a promise to capture only dropped subscriber traffic.
See `upf_ip_entrypoint_func` in the C source above. The RA toggle alone does
not establish complete IPv6 support; see [packet behaviour](dataplane.md).
The prefix validator accepts IPv6 CIDRs beyond /64; acceptance by this validator
is not proof that every accepted prefix is suitable for a deployment.

The N3/N9 REST edit preserves the other fields in the global configuration.
There is no REST configuration section for the trace switches or RA settings.
See `editDataPlaneAddressesConfig` in
[`cmd/api/rest/config.go`](../cmd/api/rest/config.go) and the section structs in
[`cmd/api/rest/schemas.go`](../cmd/api/rest/schemas.go).

## Attachment and user-space data-plane controls

| Key | Purpose | Default | Accepted value and validator | Change application |
| --- | --- | --- | --- | --- |
| `interface_name` | Interfaces on which to attach the XDP program | `[]` | List of names; no config struct tag. `BindDataPlaneInterfaces` resolves each with `net.InterfaceByName`; attachment can fail for driver/kernel/resource reasons | REST eBPF section or restart |
| `xdp_attach_mode` | Generic, driver-native or hardware-offload attachment | `generic` | `generic`, `native`, `offload`; `oneof` struct tag | REST eBPF section or restart |
| `gtp_peer` | Destinations of periodic GTP Echo Requests | `[]` | Host:port list; `omitempty,dive,hostname_port` struct tag | REST GTP path section or restart |
| `gtp_echo_interval` | Echo scheduling interval, seconds | `60` | 60..1048576; explicit lower bound and bounded-timer checks in `Validate` | REST GTP path section or restart |
| `trace_files` | Retained rotated packet-dump files | `10` | 0..1073741824; trace-limit loop in `Validate` | Restart |
| `trace_max_size` | Packet-dump rotation threshold, bytes | `10485760` | 1..1073741824; trace-limit loop in `Validate` | Restart |
| `trace_max_packets` | Packet-dump rotation threshold, packets | `100000` | 1..1073741824; trace-limit loop in `Validate` | Restart |

Echo's minimum is tied to TS 29.281 V19.2.0 clause 7.2.1. The upper limit is an
application validation ceiling. Dump thresholds are checked before the next packet is written. Size counts
captured packet bytes, excluding pcap overhead, so it is a rotation threshold,
not a hard maximum file size. See `NewPacketDumper`,
`rotate` and the packet writer in
[`cmd/utils/packet_dumper.go`](../cmd/utils/packet_dumper.go).

A live eBPF section edit must supply both `interface_name` and
`xdp_attach_mode`. To change mode while links are active, first submit an empty
interface list with the current mode, then submit the desired list and new
mode. A direct mode change with active links returns HTTP 409. This temporarily
removes XDP processing. See `editDataPlaneConfig` in
[`cmd/api/rest/config.go`](../cmd/api/rest/config.go) and
`BindDataPlaneInterfaces` in [`cmd/core/config_edit.go`](../cmd/core/config_edit.go).

The global settings above do not define per-session forwarding policy. PFCP
installs PDR/FAR/QER/URR entries separately; map capacities and rule support are
covered by the [configuration reference](Configuration.md) and
[data-plane behaviour](dataplane.md).

Debug `bpf_trace_printk` logging is still a build option (`ENABLE_LOG` via
`BPF_CFLAGS`); it is distinct from packet capture. See the generation directive
in [`cmd/ebpf/objects.go`](../cmd/ebpf/objects.go) and
[`cmd/ebpf/xdp/utils/trace.h`](../cmd/ebpf/xdp/utils/trace.h).

The startup `restoration_period` also suppresses GTP-U Error Indications for
unknown tunnels until session restoration can complete. See
[the restoration policy](pfcp-transport.md) for the
shared setting, timer and `upf_gtp_error_indications_suppressed_total` counter.

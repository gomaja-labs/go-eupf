# Data-plane configuration settings

[Configuration reference](Configuration.md) · [Advertised addresses](advertised-addresses.md) ·
[Packet behaviour and limits](dataplane.md)

The [configuration reference](Configuration.md#startup-settings) lists every
startup key, file/environment/flag/Helm name, default, accepted range and change
application. This page describes how the data-plane settings are applied.

[Upstream #398](https://github.com/edgecomllc/eupf/issues/398) asks for startup
configuration of eBPF behaviour, particularly local N3 IP, instead of build
options. Startup populates the writable `global_config` data section through
`BpfObjects.GlobalConfig.Set`; changing an address does not require recompilation.

## XDP global configuration

The global configuration receives local `n3_address` and `n9_address`, packet
capture switches `trace_in`, `trace_out`, `trace_blocked`, and Router
Advertisement controls `ip6_ra_support` and `ip6_ra_prefix`.
N3/N9 can also be edited live through the REST N3/N9 section, preserving the
other global fields. The trace switches and RA controls require restart.

`trace_in` captures incoming packets selected for subscriber tracing.
`trace_out` captures traced packets returned as XDP_TX or XDP_REDIRECT.
`trace_blocked` follows the final action check and includes XDP_PASS and
XDP_ABORTED as well as XDP_DROP; it does not require the subscriber trace flag
in that check. It is not a promise to capture only dropped subscriber traffic.
The RA toggle alone does not establish complete IPv6 support; see
[packet behaviour](dataplane.md). The prefix validator accepts IPv6 CIDRs
beyond /64; acceptance is not proof that every prefix suits a deployment.

## Attachment and user-space controls

A live REST eBPF section edit must supply both `interface_name` and
`xdp_attach_mode`. To change mode while links are active, first submit an empty
interface list with the current mode, then submit the desired list and new
mode. A direct mode change with active links returns HTTP 409. Detachment
temporarily removes XDP processing. Interface names must resolve and attachment
can fail for driver, kernel or resource reasons.

`gtp_peer` and `gtp_echo_interval` configure the GTP path manager and can be
edited through its REST section. The minimum Echo interval follows
TS 29.281 V19.2.0 clause 7.2.1.

`trace_files`, `trace_max_size` and `trace_max_packets` control packet-dump
rotation and require restart. Thresholds are checked before the next packet is
written. Size counts captured packet bytes, excluding pcap overhead, so it is
a rotation threshold rather than a hard maximum file size.

Map capacities, packet buffering, replay memory and local inactivity release
are startup controls documented in the [configuration reference](Configuration.md).
The startup `restoration_period` also suppresses GTP-U Error Indications for
unknown tunnels until session restoration can complete. See
[PFCP transport](pfcp-transport.md) for restoration, buffering and inactivity
semantics and their operational limits. PFCP installs per-session PDR/FAR/QER/URR
rules separately from the global settings.

Debug `bpf_trace_printk` logging remains a build option (`ENABLE_LOG` via
`BPF_CFLAGS`), distinct from packet capture.

# UPF Config

See [advertised-address selection](advertised-addresses.md),
[data-plane settings and restart requirements](dataplane-settings.md), and the
[documentation index](README.md).

## Description

Currently UPF have several config parameters shown below.

Parameters can be configured through command line interface, config files (YAML, JSON) or environment variables.

Parameter                                     | Description                                                                                                                                                                                                                                 | yaml                        | env                             | cli arg               | Defaults
--------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------------------------------- | --------------------- | -----------------------
Interface name `Optional`                    | List of network interfaces handling N3 (GTP) & N6 (SGi) traffic. eUPF attaches XDP hook to every interface in this list. Format: `[ifnameA, ifnameB, ...]`.                                                                                 | `interface_name`            | `UPF_INTERFACE_NAME`            | `--iface`             | `[]`
N3 address `Mandatory`                        | IPv4 address for N3 interface                                                                                                                                                                                                               | `n3_address`                | `UPF_N3_ADDRESS`                | `--n3addr`            | `127.0.0.1`
N9 address `Optional`                         | IPv4 address for N9 interface                                                                                                                                                                                                               | `n9_address`                | `UPF_N9_ADDRESS`                | `--n9addr`            | `n3_address`
N3 advertised address `Optional`             | Advertised IPv4 address for N3 interface. Falls back to `n3_address` when unset.                                                                                                                                                            | `n3_adv_address`            | `UPF_N3_ADV_ADDRESS`            | `--n3advaddr`         | `n3_address`
N3 advertised address (5G) `Optional`        | Advertised IPv4 address for N3 interface used for 5G sessions. Falls back to `n3_address` when unset.                                                                                                                                       | `n3_adv_address_5g`         | `UPF_N3_ADV_ADDRESS_5G`         | `--n3advaddr5g`       | `n3_address`
N9 advertised address `Optional`             | Advertised IPv4 address for N9 interface. Falls back to `n9_address` when unset.                                                                                                                                                            | `n9_adv_address`            | `UPF_N9_ADV_ADDRESS`            | `--n9advaddr`         | `n9_address`
XDP mode `Optional`                           | XDP attach mode: ∘ **generic** – kernel-level (evaluation) ∘ **native** – driver-level ∘ **offload** – NIC-level (direct NIC execution). Refer to [How XDP Works](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/#How-XDP-Works)          | `xdp_attach_mode`           | `UPF_XDP_ATTACH_MODE`           | `--attach`            | `generic`
API address `Optional`                        | Local address for serving [REST API](api.md) server                                                                                                                                                                                         | `api_address`               | `UPF_API_ADDRESS`               | `--aaddr`             | `127.0.0.1:8080`
PFCP address `Optional`                       | Local address that PFCP server will listen to                                                                                                                                                                                               | `pfcp_address`              | `UPF_PFCP_ADDRESS`              | `--paddr`             | `127.0.0.1:8805`
PFCP NodeID `Optional`                        | Local NodeID for PFCP protocol. Format is a hostname or IP address.                                                                                                                                                                                     | `pfcp_node_id`              | `UPF_PFCP_NODE_ID`              | `--nodeid`            | `127.0.0.1`
GTP peer `Optional`                           | List of gtp peer's address to send echo requests to. Format is `[hostnameA:portA, hostnameB:portB, ...]`.                                                                                                                                   | `gtp_peer`                  | `UPF_GTP_PEER`                  | `--peer`              | `-`
Echo request interval `Optional`               | Echo request sending interval in seconds; minimum 60 (TS 29.281 V19.2.0 clause 7.2.1).                                                                                                                                                                                           | `gtp_echo_interval`         | `UPF_GTP_ECHO_INTERVAL`         | `--echo`              | `60`
Metrics address `Optional`                    | Local address for serving Prometheus metrics endpoint.                                                                                                                                                                                      | `metrics_address`           | `UPF_METRICS_ADDRESS`           | `--maddr`             | `:9090`
QER map size `Optional`                       | Size of the QER eBPF map. Overrides value derived from `max_sessions` when set (non-zero).                                                                                                   | `qer_map_size`              | `UPF_QER_MAP_SIZE`              | `--qersize`           | `0` (derived from max_sessions)
FAR map size `Optional`                       | Size of the FAR eBPF map. Overrides value derived from `max_sessions` when set (non-zero).                                                                                                   | `far_map_size`              | `UPF_FAR_MAP_SIZE`              | `--farsize`           | `0` (derived from max_sessions)
PDR map size `Optional`                       | Size of the PDR eBPF map. Overrides value derived from `max_sessions` when set (non-zero).                                                                                                   | `pdr_map_size`              | `UPF_PDR_MAP_SIZE`              | `--pdrsize`           | `0` (derived from max_sessions)
URR map size `Optional`                       | Size of the URR eBPF map. Overrides value derived from `max_sessions` when set (non-zero).                                                                                                   | `urr_map_size`              | `UPF_URR_MAP_SIZE`              | `--urrsize`           | `0` (derived from max_sessions)
Max Sessions `Optional`                       | Maximum session contexts across N4/Sxa/Sxb, including retirement. Automatically calculates map sizes (PDR = 2×max_sessions, FAR = PDR, QER = max_sessions, URR = 2×max_sessions) when no individual (`qer_map_size`, etc.) is set. | `max_sessions`              | `UPF_MAX_SESSIONS`              | `--maxsessions`       | `65535`
Logging level `Optional`                      | Logs at or above the selected severity are written to stdout                                                                                                                                                                               | `logging_level`             | `UPF_LOGGING_LEVEL`             | `--loglvl`            | `info`
Logging caller `Optional`                    | Add the caller info (file:line) to every log line                                                                                                                                                                                           | `logging_caller`            | `UPF_LOGGING_CALLER`            | `--logcaller`         | `false`
Heartbeat retries `Optional`                 | Number of heartbeat retries before the association is considered lost                                                                                                                                                                       | `heartbeat_retries`         | `UPF_HEARTBEAT_RETRIES`         | `--hbretries`         | `3`
Heartbeat interval `Optional`                | Heartbeat sending interval. Format is seconds.                                                                                                                                                                                              | `heartbeat_interval`        | `UPF_HEARTBEAT_INTERVAL`        | `--hbinterval`        | `5`
Heartbeat timeout `Optional`                 | Heartbeat response timeout. Format is seconds.                                                                                                                                                                                              | `heartbeat_timeout`         | `UPF_HEARTBEAT_TIMEOUT`         | `--hbtimeout`         | `5`
QCI to DSCP mapping `Optional`               | Mapping of QCI values to DSCP marks, e.g. `{"9":46}`.                                                                                                                                                                                       | `qci_dscp_mapping`          | `UPF_QCI_DSCP_MAPPING`          | `--qdmap`             | `{}`
Allowed APNs `Optional`                      | Regex mask of allowed APNs                                                                                                                                                                                                                  | `allowed_apns`              | `UPF_ALLOWED_APNS`              | `--aapns`             | `.*`
Denied APNs `Optional`                       | Regex mask of denied APNs. Empty means no APN is denied.                                                                                                                                                                                    | `denied_apns`               | `UPF_DENIED_APNS`               | `--dapns`             | ``
UEIP Feature `Optional`                       | Support for IP allocation option                                                                                                                                                                                                            | `feature_ueip`              | `UPF_FEATURE_UEIP`              | `--ueip`              | `false`
UE IP Pool `Optional`                         | Pool of IP addresses, needed to allocate ip when the UEIP option is enabled                                                                                                                                                                 | `ueip_pool`                 | `UPF_UEIP_POOL`                 | `--ueippool`          | `10.60.0.0/24`
TEID Pool `Optional`                          | Pool of TEIDs for mandatory UP function allocation                                                                                                                                                                      | `teid_pool`                 | `UPF_TEID_POOL`                 | `--teidpool`          | `65535`
PFCP peers `Optional`                         | List of PFCP peers (SMF hostnames or IP addresses) which UPF will try to connect                                                                                                                                                            | `pfcp_remote_node`          | `UPF_PFCP_REMOTE_NODE`          | `--pfcprnode`         | `-`
Association Setup timeout `Optional`          | Timeout between Association Setup Requests initiated by UPF                                                                                                                                                                                 | `association_setup_timeout` | `UPF_ASSOCIATION_SETUP_TIMEOUT` | `--astimeout`         | `5`
PFCP originated requests `Optional` | Outstanding originated requests per PFCP connection; zero selects 4096, maximum 65536 | `pfcp_max_originated_requests` | `UPF_PFCP_MAX_ORIGINATED_REQUESTS` | `--pfcp-max-originated-requests` | `4096` |
PFCP replay entries `Optional` | Retained request outcomes across N4/Sxa/Sxb in one process; zero selects 131072, maximum 1048576 | `pfcp_max_replay_entries` | `UPF_PFCP_MAX_REPLAY_ENTRIES` | `--pfcp-max-replay-entries` | `131072` |
PFCP replay memory `Optional` | Process-wide replay accounting budget in MiB; zero selects 128, range 16–1024 | `pfcp_replay_memory_mib` | `UPF_PFCP_REPLAY_MEMORY_MIB` | `--pfcp-replay-memory-mib` | `128` |
Session restoration period `Optional` | Seconds after startup reserved for restoration; automatic UE IPv4 allocation waits, automatic TEIDs remain available; unknown-tunnel Error Indications are suppressed; 0 disables both holds, range 0–86400 | `restoration_period` | `UPF_RESTORATION_PERIOD` | `--restoration-period` | `60` |
PFCP profile `Optional` | PFCP dialect: "default" (standard 3GPP) or "huawei" (Huawei SPGW-C) | `pfcp_profile` | `UPF_PFCP_PROFILE` | `--pfcp_profile` | `default` |
S1-U address `Optional`                       | Address for communication over S1-U interface                                                                                                                                                                                               | `s1u_address`               | `UPF_S1U_ADDRESS`               | `--s1uaddr`           | `127.0.0.1`
S5/S8 address `Optional`                      | Address for communication over S5/S8 interface                                                                                                                                                                                              | `s5s8_address`              | `UPF_S5S8_ADDRESS`              | `--s5s8addr`          | `127.0.0.1`
PA address `Optional`                         | Address for communication over PA interface                                                                                                                                                                                                 | `pa_address`                | `UPF_PA_ADDRESS`                | `--paaddr`            | `127.0.0.1`
Sxa address `Optional`                        | Sxa Address to bind PFCP server to                                                                                                                                                                                                          | `sxa_address`               | `UPF_SXA_ADDRESS`               | `--sxaaddr`           | `""` (disabled)
List of Sxa peers `Optional`                  | Address of remote Sxa node                                                                                                                                                                                                                  | `sxa_remote_node`           | `UPF_SXA_REMOTE_NODE`           | `--sxanode`           | `-`
Sxa node id `Optional`                        | Sxa PFCP Server Node ID                                                                                                                                                                                                                     | `sxa_node_id`               | `UPF_SXA_NODE_ID`               | `--sxanodeid`         | `127.0.0.2`
Sxb address `Optional`                        | Sxb Address to bind PFCP server to                                                                                                                                                                                                          | `sxb_address`               | `UPF_SXB_ADDRESS`               | `--sxbaddr`           | `""` (disabled)
List of Sxb peers `Optional`                  | Address of remote Sxb node                                                                                                                                                                                                                  | `sxb_remote_node`           | `UPF_SXB_REMOTE_NODE`           | `--sxbnode`           | `-`
Sxb node id `Optional`                        | Sxb PFCP Server Node ID                                                                                                                                                                                                                     | `sxb_node_id`               | `UPF_SXB_NODE_ID`               | `--sxbnodeid`         | `127.0.0.3`
Trace association `Optional`                  | Trace PFCP Association messages (Establish/Modify/Release)                                                                                                                                                                                  | `trace_association`         | `UPF_TRACE_ASSOCIATION`         | `--traceassoc`        | `true`
Trace heartbeat `Optional`                    | Trace PFCP Heartbeat messages                                                                                                                                                                                                               | `trace_heartbeat`           | `UPF_TRACE_HEARTBEAT`           | `--tracehb`           | `false`
Trace incoming packets `Optional`             | Trace incoming dataplane packets                                                                                                                                                                                                            | `trace_in`                  | `UPF_TRACE_IN`                  | `--tracein`           | `true`
Trace outgoing packets `Optional`             | Trace outgoing dataplane packets                                                                                                                                                                                                            | `trace_out`                 | `UPF_TRACE_OUT`                 | `--traceout`          | `true`
Trace dropped packets `Optional`             | Trace dropped dataplane packets                                                                                                                                                                                                             | `trace_blocked`             | `UPF_TRACE_BLOCKED`             | `--traceblock`        | `false`
Trace files number `Optional`                 | Maximum number of rotated trace dump files                                                                                                                                                                                                  | `trace_files`               | `UPF_TRACE_FILES`               | `--tracefcnt`         | `10`
Trace packets in file `Optional`              | Maximum number of packets in one trace dump file                                                                                                                                                                                            | `trace_max_packets`         | `UPF_TRACE_MAX_PACKETS`         | `--tracefpackets`     | `100000`
Max trace size `Optional`                     | Maximum size (in bytes) of one trace dump file                                                                                                                                                                                              | `trace_max_size`            | `UPF_TRACE_MAX_SIZE`            | `--tracefsize`        | `10485760`
IPv6 router advertisement `Optional`          | Enable or disable IPv6 Router Advertisement support                                                                                                                                                                                         | `ip6_ra_support`            | `UPF_IP6_RA_SUPPORT`            | `--ip6ra`             | `false`
IPv6 subscriber prefix `Optional`             | Subscriber IPv6 prefix                                                                                                                                                                                                                      | `ip6_ra_prefix`             | `UPF_IP6_RA_PREFIX`             | `--ip6rapref`         | `2a03:d000:29a0:509::/64`

## PCC (predefined) rules

Predefined PCC rules are configured in a separate config file (default `./pcc.yaml`, override with `--pcc-config`). The path to the file is set with the `--pcc-config` flag; the loader accepts YAML or JSON and the PCC_ environment prefix. The file defines a list of rules under the `pcc_rules` key:

```yaml
pcc_rules:
  - pcc_name: "block_icmp"
    notify: false
    sdf_filter: "permit out ip from 192.168.1.100/32 to assigned"
    far:
      action: 2                      # bitmask: 1 = DROP, 2 = FORW, 4 = BUFF, 8 = NOCP, 16 = DUPL
      outer_header_creation: 0       # 0 = none, 1 = GTP-U/UDP/IP IPv4, 2 = GTP-U/UDP/IP IPv6, 4 = UDP/IPv4, 8 = UDP/IPv6
      teid: 0
      remote_ip: 0
      transport_level_marking: 0
    qer:
      qfi: 9                         # QoS Flow Identifier, 1..255
      max_bitrate_ul: 100000         # uplink bitrate, bit/s
      max_bitrate_dl: 100000         # downlink bitrate, bit/s
    urr:
      urrid: 0                       # URR id to report usage for
```

Rule fields:

Field             | Description                                                                                     | yaml                    | Defaults
----------------- | ----------------------------------------------------------------------------------------------- | ----------------------- | --------
Rule name         | Unique name of the predefined rule. Referenced by PDRs via Activate Predefined Rules            | `pcc_name`              | (required)
Notify            | Send a notification when the SDF filter matches                                                | `notify`                | `false`
SDF filter        | Service data flow filter, e.g. `permit out ip from 192.168.1.100/32 to assigned`                    | `sdf_filter`            | (required)
FAR action        | Forwarding action bitmask: 1 = DROP, 2 = FORW, 4 = BUFF, 8 = NOCP, 16 = DUPL                      | `far.action`            | `0`
Outer header      | Outer header creation for the FAR: 0 = none, 1 = GTP-U/UDP/IP (IPv4), 2 = GTP-U/UDP/IP (IPv6), 4 = UDP/IPv4, 8 = UDP/IPv6 | `far.outer_header_creation` | `0`
FAR TEID          | Tunnel endpoint identifier for the forwarding action                                            | `far.teid`              | `0`
FAR remote IP     | Remote (peer) IPv4 address for the forwarding action, as a 32-bit integer                       | `far.remote_ip`         | `0`
Transport marking | Transport level marking (DSCP/TC mark) applied to forwarded packets                              | `far.transport_level_marking` | `0`
QFI               | QoS Flow Identifier (1..255)                                                                    | `qer.qfi`               | (required)
Max bitrate UL    | Maximum uplink bitrate in bit/s (0 = unlimited)                                                 | `qer.max_bitrate_ul`    | `0`
Max bitrate DL    | Maximum downlink bitrate in bit/s (0 = unlimited)                                               | `qer.max_bitrate_dl`    | `0`
URR id            | URR id whose usage is reported for traffic matching the rule                                    | `urr.urrid`             | `0`

A rule is activated for a PDR when the SMF sends an Activate Predefined Rules IE referencing its `pcc_name`; Deactivate Predefined Rules removes it again.

We are using [Viper](https://github.com/spf13/viper) for configuration handling, [Viper](https://github.com/spf13/viper) uses the following precedence order. Each item takes precedence over the item below it:

- CLI argument
- environment variable
- configuration file value
- default value

Node IDs accept hostnames or IP addresses.

## Example configuration

### Default values YAML

```yaml
interface_name: []
xdp_attach_mode: generic
api_address: 127.0.0.1:8080
api_token: ""
api_allowed_origins: []
pfcp_address: 127.0.0.1:8805
pfcp_node_id: 127.0.0.1
metrics_address: :9090
n3_address: 127.0.0.1
# n9_address and advertised addresses default to the configured N3/N9 addresses.
qer_map_size: 0
far_map_size: 0
pdr_map_size: 0
urr_map_size: 0
max_sessions: 65535
feature_ueip: false
ueip_pool: 10.60.0.0/24
teid_pool: 65535
pfcp_remote_node: []
association_setup_timeout: 5
heartbeat_retries: 3
heartbeat_interval: 5
heartbeat_timeout: 5
gtp_peer: []
gtp_echo_interval: 60
logging_level: info
logging_caller: false
pfcp_profile: default
s1u_address: 127.0.0.1
s5s8_address: 127.0.0.1
sxa_address: ""
sxa_remote_node: []
sxa_node_id: 127.0.0.2
sxb_address: ""
sxb_remote_node: []
sxb_node_id: 127.0.0.3
pa_address: 127.0.0.1
trace_association: true
trace_blocked: false
trace_files: 10
trace_max_packets: 100000
trace_max_size: 10485760
trace_heartbeat: false
trace_in: true
trace_out: true
ip6_ra_support: false
ip6_ra_prefix: 2a03:d000:29a0:509::/64
```

### Environment variables

```env
UPF_INTERFACE_NAME="eth0,n6"
UPF_XDP_ATTACH_MODE=generic
UPF_API_ADDRESS=127.0.0.1:8081
UPF_PFCP_ADDRESS=:8806
UPF_METRICS_ADDRESS=:9091
UPF_PFCP_NODE_ID=10.100.50.241  # address on n4 interface
UPF_N3_ADDRESS=10.100.50.233
UPF_N9_ADDRESS=10.100.50.233
```

### CLI

```bash
eupf \
 --iface n3 \
 --iface n6 \
 --attach generic \
 --aaddr 127.0.0.1:8081 \
 --paddr :8086 \
 --nodeid 127.0.0.1 \
 --maddr :9090 \
 --n3addr 10.100.50.233
```

## Management API and validation limits

`api_token` / `UPF_API_TOKEN` / `--api-token` sets the administration bearer token. Nonempty tokens use HTTP token68 characters (`A-Z`, `a-z`, digits, `-._~+/`, with optional trailing `=` padding). A non-loopback `api_address` requires it. `api_allowed_origins` / `UPF_API_ALLOWED_ORIGINS` / `--api-allowed-origins` supplies explicit HTTP(S) browser origins; the default list is empty. The token is omitted from the REST configuration response and startup logs. See [API security](api.md).

`max_sessions` is 1..1048576. Each explicit map size is 0 (derive from max_sessions) or 1..2097152. Association setup timers are 1..1048576 seconds; GTP echo intervals are 60..1048576 seconds. Heartbeat timeout and interval are 0..3600 seconds (a zero timeout disables originated heartbeats, a zero interval selects five seconds) and heartbeat retries are 0..100; see [PFCP transport and peer liveness](pfcp-transport.md). Trace file count is 0..1073741824; trace size and packet count are 1..1073741824. Enabled UE-IP pools must be IPv4 /12 or narrower (at most 1048576 addresses); enabled TEID pools contain 1..1048576 entries. These are validation ceilings; provision memory for the actual configured maps and pools.

REST edits write the file selected by `--config`. A read-only ConfigMap cannot persist edits: the API reports HTTP 500 if the runtime edit succeeded but persistence failed. Update the Helm values and restart to make durable changes to a ConfigMap deployment.

PFCP retry, admission, capacity, response-cache and failure-grace settings are
documented in [PFCP transport and peer liveness](pfcp-transport.md).


Startup and REST edits share the configuration validator. `heartbeat_timeout`
accepts 0–3600 seconds (0 disables probes), `heartbeat_interval` accepts 0–3600
(0 selects five seconds), and `heartbeat_retries` accepts 0–100. Retention must
cover both configured retry windows and be at least 20 seconds. The association
setup interval accepts 1–1048576 seconds. See [PFCP transport](pfcp-transport.md)
for cache budgets, replay windows and request-rate sizing.

For direct management HTTPS, set `api_tls_cert_file` / `UPF_API_TLS_CERT_FILE` /
`--api-tls-cert-file` and `api_tls_key_file` / `UPF_API_TLS_KEY_FILE` /
`--api-tls-key-file` together. These are startup settings. See [API security](api.md).

## Runtime configuration edits

Each `POST /api/v1/config/<section>` replaces a complete section. Supply every
field listed in the Swagger schema; missing fields and JSON `null` return HTTP
400 naming the field. Values are checked with the startup validator before any
runtime or file change. A rejected candidate leaves the current configuration
and selected configuration file unchanged.

Use `[]` to remove all interfaces, GTP peers or PFCP remote nodes. Use `false`
to disable `logging_caller`, and an explicit `heartbeat_timeout: 0` to disable
heartbeat probing. Omitting those fields does not disable them. The CLI sends
complete sections, including empty lists and explicit zero values.

The advertised N3, 5G N3 and N9 addresses (`n3_adv_address`,
`n3_adv_address_5g`, `n9_adv_address`) each remember whether a nonempty value
was supplied in the startup file, flag or environment. Unset or empty values
derive from `n3_address` / `n9_address`, and follow subsequent interface address
edits. Explicit values stay fixed, even when they initially equal the interface
address. Sxa S1-U/S5S8 and Sxb PA addresses are independent and stay fixed.
Derived advertised values are not written into the file by interface edits, so
restarting with the same startup sources derives the same addresses.

`restoration_period` (default 60 seconds, range 0–86400) is the time after a UPF start reserved for the SMF to restore its sessions. Set it with `UPF_RESTORATION_PERIOD` or `--restoration-period`. Only automatic UE IPv4 allocation (`feature_ueip`) waits for this period; such requests receive Cause 75 while explicit RESTI reservations remain available. Zero disables this hold and permits immediate reuse of an unrestored predecessor UE IPv4 address. During this same period, the data plane silently discards G-PDUs for unknown nonzero TEIDs instead of sending GTP-U Error Indication, and counts them in `upf_gtp_error_indications_suppressed_total` (TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1A.4 and 17.1b.1). The guard starts before XDP attachment and uses the kernel monotonic clock. It expires automatically, does not suppress Echo Responses or consume the diagnostic rate budget, and has no lookup on known-tunnel forwarding. Zero disables both restoration holds. The 60-second default is an initial deployment value: size it to exceed restart detection, association establishment and the deployment's complete proactive restoration time (TS 23.527 clause 4.3.4 NOTE 2; TS 23.007 clause 16.1A.4 NOTE 3).

Automatic TEIDs are available immediately, including on the first start. For a fixed `teid_pool` size n, b = ceil(log2(n + 1)), P = 2^(32-b) - 1 seconds, and the TEID is ((1 + (Recovery Time Stamp in Unix seconds mod P)) << b) + index, with index 1..n. Generation zero is excluded so an upgrade cannot allocate the previous release's TEIDs 1..n. The same timestamp is advertised in Setup and Heartbeat on every endpoint. Two instances with the same pool size can allocate the same automatic TEID only when their integer start seconds differ by an exact multiple of P: 65,535 seconds (18 h 12 min 15 s) for the default 65,535-entry pool, or 2,047 seconds (34 min 7 s) for the maximum 1,048,576-entry pool. This includes two starts in one second. A backward or forward clock step obeys the same modulo rule; a repeated timestamp or exact-period step can reuse a generation. This is not a persistent uniqueness guarantee, and changing pool size changes the bit partition. Explicit RESTI can reserve a predecessor TEID of any generation immediately; a TEID held by another live or retiring session returns Cause 73 with its Failed PDR ID. At session capacity every establishment returns Cause 75. Cause 86 applies only to a restored local F-TEID address unavailable on its requested interface, or a restored IPv4 UE address outside the configured UPF allocation range when UPF IPv4 allocation is enabled. Only explicit reservations in the current automatic range consume free-chain indices. Within an instance, freed indices retain FIFO reuse; allocating or reserving a pool index never scans the pool. TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1b.1/17.1b.1.

The default Helm UPF limit is 512 MiB and one CPU (request: 512 MiB, 500m CPU), with `max_sessions: 1024` and a 96 MiB replay budget. Set both explicitly in ConfigMap mode. The startup memory floor includes shared replay, session state, originated queues, transient headroom, the packet-buffer pool and metadata, and per-URR measurement-window state. The default chart's minimum accounting floor is 475.3125 MiB; its measured loaded cgroup charge and growing-map reserve can raise that floor. Startup resolves the process's own v1/v2 cgroup and smallest visible ancestor limit, refuses an undersized budget, and derives a Go soft limit excluding baseline, growing buffer metadata in the kernel and transient headroom. Without a visible hard limit, startup applies neither automatic Go soft-limit selection nor this refusal check. See [PFCP transport](pfcp-transport.md) for the sizing formula, earlier workload measurements and their limits.

### Packet storage settings

These settings take effect at startup and are shared by all PFCP endpoints. BUFF and BUFF|NOCP FARs use this bounded pool; BAR parameters can reduce the shared session limit and extend downlink retention. An empty storage allowance still permits first-packet notification. See [buffering behavior](pfcp-transport.md#packet-buffering-runtime).

| File key | Flag | Environment | Default | Bounds |
| --- | --- | --- | --- | --- |
| `buffer_packets` | `--buffer-packets` | `UPF_BUFFER_PACKETS` | 4096 | 1-65536 |
| `buffer_per_session` | `--buffer-per-session` | `UPF_BUFFER_PER_SESSION` | 4 | 1-64; no larger than `buffer_packets` |
| `buffer_retention_seconds` | `--buffer-retention-seconds` | `UPF_BUFFER_RETENTION_SECONDS` | 30 | 1-86400 |

Zero selects the corresponding default. Accepting a BAR or BUFF/NOCP FAR never reserves packet storage or reduces session capacity. Compact metadata is sized to `max_sessions` and the FAR pool. Storage is taken per packet and shared across all endpoints, bounded by the global pool and the per-session limit. Fixed ring slots carry at most 2048 Ethernet-frame bytes; oversized frames, exhausted packet credit and a full ring drop the packet and increment `upf_buffer_discarded_packets_total{reason="overflow"}`. Retained expiry and cancellation are counted separately with reasons `expiry` and `cancellation`; `upf_buffer_retained_packets` includes admitted ring records as well as application storage. Notification observations use separate durable state, so every first eligible downlink packet can notify even when it cannot be stored.

BAR-associated FARs share their total and downlink-only suggested packet counts. Lowering a suggested count applies to later arrivals: existing packets stay until forwarding, discard or expiry (TS 29.244 V20.1.0 clauses 8.2.30 and 8.2.100). Extended DL duration replaces ordinary DL retention. A valid retained packet receives a bounded output window after producer grace permits forwarding. Storage and timing require workload-specific validation before enabling the capability gate.

Signalling captures use the PFCP socket's bound local address and the datagram's
peer address, with IPv4-mapped IPv6 addresses recorded as IPv4. IPv6 peers use
IPv6 records. For a wildcard PFCP bind, the UDP API does not expose the selected
local address per datagram: the record shows `0.0.0.0` for an IPv4 peer or `::`
for an IPv6 peer, with the bound PFCP port. These unspecified addresses identify
a capture limitation, not a Node ID or a guessed tunnel address.

### Inactivity release

`inactivity_release_timeout` (`--inactivity-release-timeout`,
`UPF_INACTIVITY_RELEASE_TIMEOUT`) is a startup setting in whole seconds, 0–86400.
The default 0 disables local inactivity release; any other value deletes a session
through the same transaction and final-report procedure as REST release
(TS 29.244 V20.1.0 clause 5.18.2). Helm exposes the environment variable and the
configuration-file example, and the CLI configuration schema carries the key.
The common configuration validation checks its bound for every source.

This local policy differs from a CP-provisioned User Plane Inactivity Timer:
that timer sends one UPIR and preserves the session until the CP supplies further
instructions (clause 5.11.2). Background activity sampling targets 100 ms,
with scheduler and processing delay. Each batch snapshots at most 64 sessions,
reads activity outside the PFCP state lock, and checks their current lifetimes and
timers before acting. Updated timers receive priority checks after each frame. See [PFCP transport](pfcp-transport.md) for update,
reclamation and failure semantics. Per-PDR UPINT is rejected.

Unsigned configuration values are decoded without narrowing, wrapping, fractional
truncation or boolean-to-number conversion before their common range validation.
This applies to UPF settings and PCC rule values. Decimal strings used by flags
and environment variables and comma-separated interface lists retain their normal
parsing. Invalid numeric input is rejected before it can enable a short inactivity
release timeout or change a rule identifier.

# UPF configuration

See [advertised addresses](advertised-addresses.md),
[data-plane settings](dataplane-settings.md), [PFCP transport](pfcp-transport.md)
and the [documentation index](README.md).

## Startup settings

The table is the complete startup setting inventory. File keys apply to YAML or
JSON. Precedence is CLI flag, environment, configuration file, then default.
`--config` selects the UPF file (default `./config.yml`); `--pcc-config` selects
the separate PCC file (default `./pcc.yaml`). Missing implicit default files are
allowed; an explicitly selected missing file or a malformed present file fails
startup. Lists in environment variables are comma-separated, without brackets.

Defaults here are standalone defaults. In Helm environment mode, each setting
uses `env.UPF_<KEY>`; entries in `defaultEnv` supply the chart defaults below.
In ConfigMap mode, use the file key inside `config.data["config.yml"]`; `env`
still overrides it. The Helm column identifies explicit chart defaults or special
values. `env` means no dedicated chart default. TLS paths are mounted by
`api.tls.existingSecret`; the token is supplied through `api.token` or
`api.existingSecret` in both modes. Restart the pod after Secret changes.

Creating a previously disabled Sxa/Sxb endpoint requires restart; REST PFCP
sections can update existing endpoints.

All file, flag and environment edits require restart. A row marked REST can
also be applied live through its management section; a REST edit writes the
selected UPF file. A persistence failure can follow a successful runtime edit,
including on a read-only ConfigMap; update the deployment configuration and
restart in that case. REST does not reload environment
variables or alter a higher-precedence value on the next start. See
[data-plane settings](dataplane-settings.md) for attachment sequencing and
[API documentation](api.md) for management access.

Zero is not universally a disable switch: the table specifies where it selects
an effective default. Numeric values must be integral and representable in the
setting's type; fractional, negative unsigned and overflowing values fail decoding.
Rule map sizes are admission capacities, with extra physical slots described below.

| File key | Environment | CLI flag | Default | Accepted values | Change application | Helm value / chart default | Purpose |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `buffer_packets` | `UPF_BUFFER_PACKETS` | `--buffer-packets` | `4096` | 0 selects 4096; 1–65536 | Restart | defaultEnv.UPF_BUFFER_PACKETS = 4096 | Process-wide retained Ethernet-frame slots (2048 bytes per frame). |
| `buffer_per_session` | `UPF_BUFFER_PER_SESSION` | `--buffer-per-session` | `4` | 0 selects 4; 1–64 and no greater than buffer_packets | Restart | defaultEnv.UPF_BUFFER_PER_SESSION = 4 | Retained-packet ceiling per session across its FARs. |
| `buffer_retention_seconds` | `UPF_BUFFER_RETENTION_SECONDS` | `--buffer-retention-seconds` | `30` | 0 selects 30; 1–86400 seconds | Restart | defaultEnv.UPF_BUFFER_RETENTION_SECONDS = 30 | Ordinary buffering and output-retry retention. |
| `pfcp_peer_allow_list` | `UPF_PFCP_PEER_ALLOW_LIST` | `--pfcp-peer-allow-list` | `[]` | IP address / CIDR list; empty admits all sources | Restart | env | Source-address policy applied before PFCP decoding. |
| `pfcp_request_timeout` | `UPF_PFCP_REQUEST_TIMEOUT` | `--pfcp-request-timeout` | `5` | 0 selects 5; 1–3600 seconds | Restart | env | T1 for originated requests other than heartbeats. |
| `pfcp_request_retries` | `UPF_PFCP_REQUEST_RETRIES` | `--pfcp-request-retries` | `3` | 0–100 retransmissions | Restart | env | N1 retransmissions after the initial request. |
| `pfcp_response_retention` | `UPF_PFCP_RESPONSE_RETENTION` | `--pfcp-response-retention` | `60` | 0 selects 60; 20–86400 seconds; covers both local retry windows | Restart | env | Duplicate-request outcome retention. |
| `pfcp_max_replay_entries` | `UPF_PFCP_MAX_REPLAY_ENTRIES` | `--pfcp-max-replay-entries` | `131072` | 0 selects 131072; 1–1048576 | Restart | env | Shared replay outcome count across N4/Sxa/Sxb. |
| `pfcp_max_originated_requests` | `UPF_PFCP_MAX_ORIGINATED_REQUESTS` | `--pfcp-max-originated-requests` | `4096` | 0 selects 4096; 1–65536 per connection | Restart | env | Outstanding originated requests per PFCP connection. |
| `pfcp_replay_memory_mib` | `UPF_PFCP_REPLAY_MEMORY_MIB` | `--pfcp-replay-memory-mib` | `128` | 0 selects 128; 16–1024 MiB; subject to startup memory admission | Restart | defaultEnv.UPF_PFCP_REPLAY_MEMORY_MIB = 96 | Process-wide replay accounting budget. |
| `pfcp_max_associations` | `UPF_PFCP_MAX_ASSOCIATIONS` | `--pfcp-max-associations` | `1024` | 0 selects 1024; 1–65536 per connection | Restart | env | Associations per PFCP connection. |
| `heartbeat_failure_grace` | `UPF_HEARTBEAT_FAILURE_GRACE` | `--heartbeat-failure-grace` | `0` | 0–86400 seconds | Restart | env | Extra unreachable time before failed-peer session cleanup. |
| `interface_name` | `UPF_INTERFACE_NAME` | `--iface` | `[]` | Interface-name list; names must resolve when attaching | REST section or restart | defaultEnv.UPF_INTERFACE_NAME = eth0 | Interfaces handling N3/N6 traffic; attach XDP to each. |
| `xdp_attach_mode` | `UPF_XDP_ATTACH_MODE` | `--attach` | `generic` | generic, native, offload; driver/kernel support required | REST section or restart | env | XDP attachment mode. |
| `api_tls_cert_file` | `UPF_API_TLS_CERT_FILE` | `--api-tls-cert-file` | `""` | PEM file path; both TLS paths set together, or both empty | Restart | api.tls.existingSecret | Management HTTPS certificate chain. |
| `api_tls_key_file` | `UPF_API_TLS_KEY_FILE` | `--api-tls-key-file` | `""` | PEM file path; both TLS paths set together, or both empty | Restart | api.tls.existingSecret | Management HTTPS private key. |
| `api_token` | `UPF_API_TOKEN` | `--api-token` | `""` | Empty only on loopback; otherwise HTTP token68 characters | Restart | api.token / api.existingSecret (generated when unset) | Bearer token for management and Swagger routes; health is public. |
| `api_allowed_origins` | `UPF_API_ALLOWED_ORIGINS` | `--api-allowed-origins` | `[]` | Explicit HTTP(S) origin list, no wildcards, paths, queries or credentials | Restart | env | Explicit management API CORS allow list. |
| `api_address` | `UPF_API_ADDRESS` | `--aaddr` | `127.0.0.1:8080` | host:port | Restart | defaultEnv.UPF_API_ADDRESS = :8080 | Management REST listener. |
| `pfcp_address` | `UPF_PFCP_ADDRESS` | `--paddr` | `127.0.0.1:8805` | host:port | REST PFCP section or restart | defaultEnv.UPF_PFCP_ADDRESS = :8805 | N4 PFCP listener. |
| `pfcp_node_id` | `UPF_PFCP_NODE_ID` | `--nodeid` | `127.0.0.1` | Hostname or IP address | REST PFCP section or restart | defaultEnv.UPF_PFCP_NODE_ID = pod IP | N4 Node ID. |
| `pfcp_remote_node` | `UPF_PFCP_REMOTE_NODE` | `--pfcprnode` | `[]` | Hostname / IP address list; empty starts no outgoing associations | REST PFCP section or restart | env | Remote N4 peers for UP-initiated association setup. |
| `sxa_remote_node` | `UPF_SXA_REMOTE_NODE` | `--sxanode` | `[]` | Hostname / IP address list; empty starts no outgoing associations | REST PFCP section or restart | env | Remote Sxa peers for UP-initiated association setup. |
| `sxb_remote_node` | `UPF_SXB_REMOTE_NODE` | `--sxbnode` | `[]` | Hostname / IP address list; empty starts no outgoing associations | REST PFCP section or restart | env | Remote Sxb peers for UP-initiated association setup. |
| `sxa_address` | `UPF_SXA_ADDRESS` | `--sxaaddr` | `""` | host:port, or empty to disable endpoint | REST PFCP section or restart | env | Sxa PFCP listener. |
| `sxb_address` | `UPF_SXB_ADDRESS` | `--sxbaddr` | `""` | host:port, or empty to disable endpoint | REST PFCP section or restart | env | Sxb PFCP listener. |
| `sxa_node_id` | `UPF_SXA_NODE_ID` | `--sxanodeid` | `127.0.0.2` | Hostname or IP address, or empty | REST PFCP section or restart | env | Sxa Node ID. |
| `sxb_node_id` | `UPF_SXB_NODE_ID` | `--sxbnodeid` | `127.0.0.3` | Hostname or IP address, or empty | REST PFCP section or restart | env | Sxb Node ID. |
| `association_setup_timeout` | `UPF_ASSOCIATION_SETUP_TIMEOUT` | `--astimeout` | `5` | 1–1048576 seconds | REST section or restart | env | Timeout between Association Setup Requests initiated by UPF |
| `metrics_address` | `UPF_METRICS_ADDRESS` | `--maddr` | `:9090` | host:port | Restart | defaultEnv.UPF_METRICS_ADDRESS = :9090 | Separate Prometheus listener. |
| `n3_address` | `UPF_N3_ADDRESS` | `--n3addr` | `127.0.0.1` | IPv4 literal | REST section or restart | defaultEnv.UPF_N3_ADDRESS = pod IP | Local N3 receive address and encapsulation source. |
| `n9_address` | `UPF_N9_ADDRESS` | `--n9addr` | `n3_address` | IPv4 literal | REST section or restart | env | Local N9 receive address and forwarding source. |
| `n3_adv_address` | `UPF_N3_ADV_ADDRESS` | `--n3advaddr` | `n3_address` | IPv4 literal | Restart | env | Access-side advertised F-TEID address. |
| `n3_adv_address_5g` | `UPF_N3_ADV_ADDRESS_5G` | `--n3advaddr5g` | `n3_address` | IPv4 literal | Restart | env | 5G access-side advertised F-TEID address, independently derived from N3. |
| `n9_adv_address` | `UPF_N9_ADV_ADDRESS` | `--n9advaddr` | `n9_address` | IPv4 literal | Restart | env | Core-side advertised F-TEID address. |
| `s1u_address` | `UPF_S1U_ADDRESS` | `--s1uaddr` | `127.0.0.1` | IPv4 literal, or empty | Restart | env | Sxa access-side advertised F-TEID address. |
| `s5s8_address` | `UPF_S5S8_ADDRESS` | `--s5s8addr` | `127.0.0.1` | IPv4 literal, or empty | Restart | env | Sxa core-side advertised F-TEID address. |
| `pa_address` | `UPF_PA_ADDRESS` | `--paaddr` | `127.0.0.1` | IPv4 literal, or empty | Restart | env | Sxb access/core advertised F-TEID address. |
| `gtp_peer` | `UPF_GTP_PEER` | `--peer` | `[]` | host:port list | REST section or restart | env | Destinations of periodic GTP Echo Requests. |
| `gtp_echo_interval` | `UPF_GTP_ECHO_INTERVAL` | `--echo` | `60` | 60–1048576 seconds | REST section or restart | env | GTP Echo scheduling interval (TS 29.281 V19.2.0 clause 7.2.1). |
| `qer_map_size` | `UPF_QER_MAP_SIZE` | `--qersize` | `0` | 0 derives from max_sessions; 1–2097152 | Restart | env | Committed live QER limit; default max_sessions. |
| `far_map_size` | `UPF_FAR_MAP_SIZE` | `--farsize` | `0` | 0 derives from max_sessions; 1–2097152 | Restart | env | Committed live FAR limit; default twice max_sessions. |
| `urr_map_size` | `UPF_URR_MAP_SIZE` | `--urrsize` | `0` | 0 derives from max_sessions; 1–2097152 | Restart | env | Committed live URR limit; default twice max_sessions. |
| `pdr_map_size` | `UPF_PDR_MAP_SIZE` | `--pdrsize` | `0` | 0 derives from max_sessions; 1–2097152 | Restart | env | Capacity of each PDR key map; default twice max_sessions. |
| `max_sessions` | `UPF_MAX_SESSIONS` | `--maxsessions` | `65535` | 1–1048576 | Restart | defaultEnv.UPF_MAX_SESSIONS = 1024 | Shared N4/Sxa/Sxb session-context admission limit, including retiring contexts. |
| `heartbeat_retries` | `UPF_HEARTBEAT_RETRIES` | `--hbretries` | `3` | 0–100 retransmissions | Restart | env | Heartbeat retransmissions before unreachable policy applies. |
| `heartbeat_interval` | `UPF_HEARTBEAT_INTERVAL` | `--hbinterval` | `5` | 0 selects 5; 1–3600 seconds | Restart | env | Heartbeat probe interval; no overlapping probe for one peer. |
| `heartbeat_timeout` | `UPF_HEARTBEAT_TIMEOUT` | `--hbtimeout` | `5` | 0 disables originated heartbeats; 1–3600 seconds | REST section or restart | env | Heartbeat T1. |
| `logging_level` | `UPF_LOGGING_LEVEL` | `--loglvl` | `info` | Case-insensitive trace, debug, info, warn, error, fatal, panic, disabled; or integer level -128–127 | REST logging_level or restart | env | Minimum severity written to stdout. |
| `logging_caller` | `UPF_LOGGING_CALLER` | `--logcaller` | `false` | Boolean | REST logging_caller or restart | env | Add the caller info (file:line) to every log line |
| `ueip_pool` | `UPF_UEIP_POOL` | `--ueippool` | `10.60.0.0/24` | CIDR; when allocation enabled, IPv4 /12 or narrower; otherwise cleared | Restart | env | Single automatic IPv4 allocation pool. |
| `teid_pool` | `UPF_TEID_POOL` | `--teidpool` | `65535` | 1–1048576 | Restart | env | Pool of TEIDs for mandatory UP function allocation |
| `inactivity_release_timeout` | `UPF_INACTIVITY_RELEASE_TIMEOUT` | `--inactivity-release-timeout` | `0` | 0–86400 seconds | Restart | defaultEnv.UPF_INACTIVITY_RELEASE_TIMEOUT = 0 | Local session-release policy; zero disables. Independent of CP UPIR timer. |
| `restoration_period` | `UPF_RESTORATION_PERIOD` | `--restoration-period` | `60` | 0–86400 seconds | Restart | defaultEnv.UPF_RESTORATION_PERIOD = 60 | Startup automatic UE IPv4 allocation hold and unknown-tunnel Error Indication suppression; zero disables both. |
| `feature_ueip` | `UPF_FEATURE_UEIP` | `--ueip` | `false` | Boolean | Restart | env | Enable automatic IPv4 UE allocation and advertise UEIP. |
| `qci_dscp_mapping` | `UPF_QCI_DSCP_MAPPING` | `--qdmap` | `{}` | String-to-integer map; no additional config range check | Restart | env | QCI-to-DSCP mapping. |
| `allowed_apns` | `UPF_ALLOWED_APNS` | `--aapns` | `.*` | Regular expression; empty denied mask permits all otherwise allowed APNs | Restart | env | Allowed Network Instance/APN regex. |
| `denied_apns` | `UPF_DENIED_APNS` | `--dapns` | `""` | Regular expression; empty denied mask permits all otherwise allowed APNs | Restart | env | Denied Network Instance/APN regex. |
| `pfcp_profile` | `UPF_PFCP_PROFILE` | `--pfcp_profile` | `default` | default or huawei (checked when creating PFCP connection) | Restart | env | PFCP dialect: "default" (standard 3GPP) or "huawei" (Huawei SPGW-C) |
| `trace_association` | `UPF_TRACE_ASSOCIATION` | `--traceassoc` | `true` | Boolean | Restart | env | Trace PFCP Association messages (Establish/Modify/Release) |
| `trace_heartbeat` | `UPF_TRACE_HEARTBEAT` | `--tracehb` | `false` | Boolean | Restart | env | Trace PFCP Heartbeat messages |
| `trace_in` | `UPF_TRACE_IN` | `--tracein` | `true` | Boolean | Restart | env | Trace incoming dataplane packets |
| `trace_out` | `UPF_TRACE_OUT` | `--traceout` | `true` | Boolean | Restart | env | Trace outgoing dataplane packets |
| `trace_blocked` | `UPF_TRACE_BLOCKED` | `--traceblock` | `false` | Boolean | Restart | env | Capture final actions other than XDP_TX/XDP_REDIRECT, including PASS/ABORTED. |
| `trace_files` | `UPF_TRACE_FILES` | `--tracefcnt` | `10` | 0–1073741824 | Restart | env | Retained rotated packet-dump files. |
| `trace_max_size` | `UPF_TRACE_MAX_SIZE` | `--tracefsize` | `10485760` | 1–1073741824 | Restart | env | Packet-byte rotation threshold (pcap overhead excluded); checked before the next packet. |
| `trace_max_packets` | `UPF_TRACE_MAX_PACKETS` | `--tracefpackets` | `100000` | 1–1073741824 | Restart | env | Packet-count rotation threshold; checked before the next packet. |
| `ip6_ra_support` | `UPF_IP6_RA_SUPPORT` | `--ip6ra` | `false` | Boolean | Restart | env | Enable or disable IPv6 Router Advertisement support |
| `ip6_ra_prefix` | `UPF_IP6_RA_PREFIX` | `--ip6rapref` | `2a03:d000:29a0:509::/64` | IPv6 CIDR, validated even when RA is disabled | Restart | env | Subscriber IPv6 prefix |

## PCC (predefined) rules

PCC definitions can be loaded from a separate config file (default `./pcc.yaml`, override with `--pcc-config`). The path to the file is set with the `--pcc-config` flag; the loader accepts YAML or JSON and the PCC_ environment prefix. The file defines a list of rules under the `pcc_rules` key:

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

The file is parsed and validated at startup, but PFCP activation and deactivation of predefined rules are rejected. Configuring this file does not enable predefined-rule installation; see [rule capabilities](rule-capabilities.md). Restart to change PCC definitions.

We are using [Viper](https://github.com/spf13/viper) for configuration handling, [Viper](https://github.com/spf13/viper) uses the following precedence order. Each item takes precedence over the item below it:

- CLI argument
- environment variable
- configuration file value
- default value

Node IDs accept hostnames or IP addresses.

## Example configuration

### Default values YAML

This subset illustrates standalone defaults; the startup table is the complete
inventory. Set interfaces and addresses for the deployment before forwarding traffic.

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

Automatic TEIDs are available immediately, including on the first start. For a fixed `teid_pool` size n, b = ceil(log2(n + 1)), P = 2^(32-b) - 1 seconds, and the TEID is ((1 + (Recovery Time Stamp in Unix seconds mod P)) << b) + index, with index 1..n. Generation zero is excluded so an upgrade cannot allocate the previous release's TEIDs 1..n. The same timestamp is advertised in Setup and Heartbeat on every endpoint. Two instances with the same pool size can allocate the same automatic TEID only when their integer start seconds differ by an exact multiple of P: 65,535 seconds (18 h 12 min 15 s) for the default 65,535-entry pool, or 2,047 seconds (34 min 7 s) for the maximum 1,048,576-entry pool. This includes two starts in one second. A backward or forward clock step obeys the same modulo rule; a repeated timestamp or exact-period step can reuse a generation. This is not a persistent uniqueness guarantee, and changing pool size changes the bit partition. Explicit RESTI can reserve a predecessor TEID of any generation immediately; a TEID held by another live or retiring session returns Cause 73 with its Failed PDR ID. At session capacity every establishment returns Cause 75. Cause 86 applies only to resources no session could use, such as a restored local F-TEID address unavailable on its requested interface (TS 23.527 V20.0.0 clause 4.3.2 NOTE). A CP-provisioned UE IPv4 address has the same acceptance rules during restoration and new admission; the UPF pool bounds only automatic allocation. Only explicit reservations in the current automatic range consume free-chain indices. Within an instance, freed indices retain FIFO reuse; allocating or reserving a pool index never scans the pool. TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1b.1/17.1b.1.

The default Helm UPF limit is 512 MiB and one CPU (request: 512 MiB, 500m CPU), with `max_sessions: 1024` and a 96 MiB replay budget. Set both explicitly in ConfigMap mode. The startup memory floor includes shared replay, session state, originated queues, transient headroom, the packet-buffer pool and metadata, and per-URR measurement-window state. The default chart's minimum accounting floor is 484.96875 MiB; its measured loaded cgroup charge and growing-map reserve can raise that floor. Startup resolves the process's own v1/v2 cgroup and smallest visible ancestor limit, refuses an undersized budget, and derives a Go soft limit excluding baseline, growing buffer metadata in the kernel and transient headroom. Without a visible hard limit, startup applies neither automatic Go soft-limit selection nor this refusal check. See [PFCP transport](pfcp-transport.md) for the sizing formula, earlier workload measurements and their limits.

### Packet storage settings

These settings take effect at startup and are shared by all PFCP endpoints. BUFF and BUFF|NOCP FARs use this bounded pool; BAR parameters can reduce the shared session limit and extend downlink retention. An empty storage allowance still permits first-packet notification. See [buffering behavior](pfcp-transport.md#packet-buffering-runtime).

Accepting a BAR or BUFF/NOCP FAR never reserves packet storage or reduces session capacity. Compact metadata is sized to `max_sessions` and the FAR pool. Storage is taken per packet and shared across all endpoints, bounded by the global pool and the per-session limit. Fixed ring slots carry at most 2048 Ethernet-frame bytes; oversized frames, exhausted packet credit and a full ring drop the packet and increment `upf_buffer_discarded_packets_total{reason="overflow"}`. Retained expiry and cancellation are counted separately with reasons `expiry` and `cancellation`; `upf_buffer_retained_packets` includes admitted ring records as well as application storage. Notification observations use separate durable state, so every first eligible downlink packet can notify even when it cannot be stored.

BAR-associated FARs share their total and downlink-only suggested packet counts. Lowering a suggested count applies to later arrivals: existing packets stay until forwarding, discard or expiry (TS 29.244 V20.1.0 clauses 8.2.30 and 8.2.100). Extended DL duration replaces ordinary DL retention. A valid retained packet receives a bounded output window after producer grace permits forwarding. Size the pool using the memory plan and validate retention and forwarding load for the deployment.

Signalling captures use the PFCP socket's bound local address and the datagram's
peer address, with IPv4-mapped IPv6 addresses recorded as IPv4. IPv6 peers use
IPv6 records. For a wildcard PFCP bind, the UDP API does not expose the selected
local address per datagram: the record shows `0.0.0.0` for an IPv4 peer or `::`
for an IPv6 peer, with the bound PFCP port. These unspecified addresses identify
a capture limitation, not a Node ID or a guessed tunnel address.

### Inactivity release

`inactivity_release_timeout` controls local inactivity release as described in
the startup table. When enabled, expiry deletes a session
through the same transaction and final-report procedure as REST release
(TS 29.244 V20.1.0 clause 5.18.2). Helm exposes the environment variable and the
configuration-file example, and the CLI configuration schema carries the key.
The common configuration validation checks its bound for every source.

This local policy differs from a CP-provisioned User Plane Inactivity Timer:
that timer sends one UPIR and preserves the session until the CP supplies further
instructions (clause 5.11.2). Each session's observation interval is
`I = min(5 seconds, max(100 ms, T / 40))`, where T is the smaller nonzero local
or most recently provisioned CP timer. A deadline heap visits due sessions on a
100 ms worker tick. Expiry rounding is bounded by `2I + 100 ms`, plus scheduler,
I/O, processing and capacity delay: the timer fraction is 5%, with a 200 ms floor
and ten-second ceiling before the worker tick. It never expires early.
Each batch snapshots at most 64 sessions,
reads activity outside the PFCP state lock, and checks their current lifetimes and
timers before acting. Updated timers receive priority checks after each frame. See [PFCP transport](pfcp-transport.md) for update,
reclamation and failure semantics. Per-PDR UPINT is rejected.

Unsigned configuration values are decoded without narrowing, wrapping, fractional
truncation or boolean-to-number conversion before their common range validation.
This applies to UPF settings and PCC rule values. Decimal strings used by flags
and environment variables and comma-separated interface lists retain their normal
parsing. Invalid numeric input is rejected before it can enable a short inactivity
release timeout or change a rule identifier.

The configured FAR, QER and URR sizes bound committed live rules; slot zero and
replacement headroom are additional physical slots. For live capacity L and
M = 64 rules per type per session, H = min(L, 2M): one serialized journal can
stage at most M replacement versions while another batch is retiring. FAR and
URR arrays contain L + H + 1 slots. QER contains 2L + H + 1, because each live
QER can retain its stable initial policer anchor alongside its current
configuration. Committed live-ID accounting prevents new rules from consuming
this reserve. Later retired batches wait for reclamation within the existing
one-second transaction capacity budget; exhaustion returns Cause 75 (TS 29.244
V20.1.0 table 8.2.1-1). Buffer bindings use the physical FAR capacity; buffer
states use twice that capacity for overlapping lifetimes. At the default derived sizes, FAR/QER/URR each use 2,177 physical slots for
1,024 sessions and 131,199 for 65,535 sessions. These equal counts depend on
the default QER live limit being half the FAR/URR live limits.

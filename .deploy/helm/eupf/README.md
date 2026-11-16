# eUPF Helm Chart

Deploys [eUPF](https://github.com/gomaja-labs/go-eupf) — an open-source 5G User Plane Function built on eBPF.

## Quick start

```bash
helm install eupf .deploy/helm/eupf
```

The default values configure a pod with `UPF_*` environment variables (see below), probes, resource requests/limits and an API listener on port 8080.

## Cluster prerequisites

- **Linux kernel >= 5.15** on the nodes (eBPF/XDP requirement).
- **Unsafe sysctl allowed**: the chart sets `net.ipv4.ip_forward=1` in the pod security context, which nodes must allow:

  ```
  kubelet --allowed-unsafe-sysctls 'net.ipv4.ip_forward'
  ```

- **Privileges**: the default container runs as UID/GID 1000 with NET_ADMIN, NET_RAW, SYS_RESOURCE, BPF and PERFMON capabilities. It is not privileged. Adapt capabilities and kernel policy for your cluster.
- The image provides `/dumps` owned by root:GID 1000, mode `0770`, for packet captures. Root and the default UID/GID 1000 can both write there. If you override the user, provide a writable capture directory at `/dumps`.
- eUPF uses unpinned maps and requires no BPF filesystem, writable sysfs, or hostPath volume. Map state is recreated on startup. NET_RAW is used only for downlink data buffering continuation.

## Configuration

eUPF supports configuration via CLI flags, environment variables and a YAML config file (see [docs/Configuration.md](../../../docs/Configuration.md)). Precedence: CLI > **env** > config file > defaults.

The chart supports two modes:

### ENV mode (default, `config.enabled: false`)

The chart injects a working default set of `UPF_*` variables (see `defaultEnv` in `values.yaml`), where `UPF_PFCP_NODE_ID` and `UPF_N3_ADDRESS` default to the pod IP. Override any of them via the `env` map:

```yaml
env:
  UPF_INTERFACE_NAME: eth0,n6   # comma-separated, no brackets
  UPF_LOGGING_LEVEL: debug
```

List-valued parameters (e.g. `UPF_INTERFACE_NAME`) are comma-separated strings.

### Sessions and memory

The chart sets the shared session admission limit `UPF_MAX_SESSIONS: "1024"` and limits the UPF to 512 MiB and one CPU. eUPF's standalone default is 65535 sessions, which requires a larger memory limit. In ConfigMap mode set `max_sessions: 1024` and `pfcp_replay_memory_mib: 96` in `config.data` to use the chart's sizing, because the default `UPF_*` variables are not injected there.

The default live capacities are `pdr_map_size = 2*N`, `far_map_size = 2*N`,
`urr_map_size = 2*N` and `qer_map_size = N`, where `N = max_sessions`.
Each PDR key map admits `K = pdr_map_size` keys; their shared bucket array has
`2K + min(2K, 128) + 1` slots. For each configured live FAR or URR limit `L`,
the array has `L + min(L, 128) + 1` slots. QER uses
`2L + min(L, 128) + 1`, retaining a stable policer anchor as well as the current
configuration. Slot zero is unused. At 1,024 sessions this is 4,225 PDR bucket
slots and 2,177 slots in each FAR/QER/URR array. Additional slots permit bounded
replacement and retirement; they do not increase the committed live-rule limits.
Array maps allocate at startup; PDR descriptor hashes and IPv6 trie storage
grow as rules are installed. Both are charged to the memory cgroup.

The startup floor is
`2 * replay budget + B + 32 KiB * N + 3 * (16 MiB + R) + 32 MiB + H + K + W`.
Here `B = max(64 MiB, observed loaded cgroup charge + growing-map reserve)`
includes empty buffering maps and the fixed packet ring. For the following
memory terms, let `P = buffer_packets`, `F = far_map_size` and
`U = urr_map_size` be effective live capacities, `V = F + min(F, 128)` and
`J = U + min(U, 128)`. All terms below are bytes; this use of `K` is the kernel
reserve, distinct from the PDR key capacity above:

- `R = max(16 MiB, 2048*(U + 128))`: detached final usage per endpoint.
- `H = 2*131072 + P*(2048 + 2*160) + 2*1024*N + 2*320*(2*V) + 2*4608*V`: fixed runtime, packet payloads/descriptors, session and overlapping FAR lifetime metadata, and notification identities, including replacement/GC headroom.
- `K = 11 MiB + 320*N + 1152*(2*V) + 4608*P`: growing kernel metadata and rendered-packet storage, including the 8 MiB generic-ingress authorization reserve; excluded from the Go soft limit.
- `W = 768*J`: URR measurement-window state and replacement/GC headroom.

With 1,024 sessions, **96 MiB** replay, 4,096 packets and a four-packet
per-session ceiling, `R = 16 MiB`, `H = 33.28125 MiB`, `K = 34.09375 MiB`,
`W = 1.59375 MiB`, and the minimum floor is **484.96875 MiB**. A larger measured
`B` raises it. The replay budget is shared across N4/Sxa/Sxb; the standalone
default remains 128 MiB. Buffer metadata is reserved for every admitted session
and FAR lifetime, independently of packet credits. See
[PFCP transport](../../../docs/pfcp-transport.md) for accounting details and limits.

After this admission check, the automatic Go soft limit is `container hard limit - B - 32 MiB transient headroom - K`. The replay, session, buffer, URR-window and originated-queue budgets fit within that soft limit; the full startup floor is not subtracted from it. A smaller explicit `GOMEMLIMIT` is honored only when it still fits those budgets. Without a visible cgroup hard limit, startup applies neither an automatic Go soft limit nor this refusal check. Raise map capacities and the memory limit together; forwarding load, rule populations and kernel allocation costs need their own measurements. See [PFCP transport](../../../docs/pfcp-transport.md) for the fixed-workload measurements and operational limits.

### ConfigMap mode (`config.enabled: true`)

```yaml
config:
  enabled: true
  data:
    config.yml: |
      interface_name: eth0
      max_sessions: 1024
      pfcp_replay_memory_mib: 96
      buffer_packets: 4096
      buffer_per_session: 4
      buffer_retention_seconds: 30
      restoration_period: 60
      api_address: :8080
      pfcp_address: :8805
      metrics_address: :9090
```

The chart creates a ConfigMap from `config.data`, mounts it at `/app/conf` and starts the container with `--config /app/conf/config.yml`. In this mode the default `UPF_*` env injection is **disabled**, because environment variables take precedence over the config file. You can still add env vars as targeted overrides via `env`.

### Ports

| Port | Name | Purpose |
|------|------|---------|
| 8080 | http | REST API (`service.port`, must match `UPF_API_ADDRESS` / `api_address`) |
| 9090 | metrics | Prometheus metrics |

Probes are TCP checks against the `http` port; keep `service.port` in sync with the API address if you change it.

## API access

The chart supplies a bearer token through a Secret and sets `UPF_API_TOKEN` in both ENV and ConfigMap modes. Leave `api.token` empty to generate a random token, set it explicitly from a protected values source, or set `api.existingSecret` to a Secret containing the key `api-token`. The generated token is retained across Helm upgrades through a Secret lookup. An existing Secret must contain a nonempty token. Treat rendered manifests and Helm release storage as sensitive.

Only `GET /api/v1/health` is public. Management routes and Swagger require `Authorization: Bearer <token>`. CORS defaults to an empty origins list; configure `api_allowed_origins` for browser access. Protect cross-host access with TLS at a trusted proxy or a private tunnel. Keep the separate metrics listener private.

Set `cli.enabled=true` to add the published `ghcr.io/gomaja-labs/go-eupf-cli:main` management shell. It receives `CLI_EUPF_ADDR` and `CLI_API_TOKEN` from the same release configuration and Secret. Run commands with `kubectl exec -it <pod> -c cli -- eupf <command>`.

The application image defaults to `ghcr.io/gomaja-labs/go-eupf:main`; `image.tag` overrides it. The UI image has its own tag and defaults to `main` independently. ConfigMap examples use `config.enabled=true`, so chart ENV defaults cannot override their interface and address settings. REST edits cannot persist into a read-only ConfigMap; update values and roll out the deployment instead.

The API token is read at process startup. Restart the workload after changing the token Secret so both eUPF and CLI containers reload the same value.

`restoration_period` defaults to 60 seconds (0–86400) and is exposed as `UPF_RESTORATION_PERIOD` in environment mode. Automatic UE IPv4 allocation waits for restoration, and unknown-tunnel GTP-U Error Indications are suppressed during this period. Zero disables both holds and permits immediate reuse of unrestored predecessor UE IPv4 addresses. Automatic TEIDs use recovery-timestamp generations and remain available immediately. See [PFCP transport](../../../docs/pfcp-transport.md) for sizing measurements and generation limits.

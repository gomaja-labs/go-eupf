# eUPF Helm Chart

Deploys [eUPF](https://github.com/gomaja-labs/go-eupf) — an open-source 5G User Plane Function built on eBPF.

## Quick start

```bash
helm install eupf .deploy/helm/eupf
```

The default values produce a working pod: eUPF is configured via `UPF_*` environment variables (see below), probes and resource requests/limits are set, and the API is served on port 8080.

## Cluster prerequisites

- **Linux kernel >= 5.15** on the nodes (eBPF/XDP requirement).
- **Unsafe sysctl allowed**: the chart sets `net.ipv4.ip_forward=1` in the pod security context, which nodes must allow:

  ```
  kubelet --allowed-unsafe-sysctls 'net.ipv4.ip_forward'
  ```

- **Privileges**: the default container runs as UID/GID 1000 with NET_ADMIN, NET_RAW, SYS_RESOURCE, BPF, PERFMON and DAC_OVERRIDE capabilities. It is not privileged. Adapt capabilities and kernel policy for your cluster.
- The default writable hostPath mount is `/sys/fs/bpf`, where eUPF pins maps. Nodes must provide a mounted BPF filesystem. Root-based examples mount `/sys` and use a privileged container to perform their own mounts.

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

The chart sets the shared session admission limit `UPF_MAX_SESSIONS: "1024"` and limits the UPF to 512 MiB and one CPU. eUPF's standalone default is 65535 sessions, which requires a larger memory limit. In ConfigMap mode set `max_sessions: 1024` and `pfcp_replay_memory_mib: 64` in `config.data` to use the chart's sizing, because the default `UPF_*` variables are not injected there.

eUPF derives each PDR, FAR and URR map's capacity as twice `max_sessions`, and the QER map's capacity as `max_sessions`. Array maps allocate at startup; PDR hash maps hold small slot descriptors and IPv6 trie storage grows as rules are installed; the shared PDR bucket array is preallocated with four times each hash map's capacity plus slot zero. Both are charged to the container's memory cgroup. The process measures the loaded cgroup charge and reserves growing-map capacity before checking whether the hard limit fits the configured replay, session and queue budgets.

The startup memory floor is `2 * pfcp_replay_memory_mib + B + 32 KiB * max_sessions + 48 MiB originated queues + 32 MiB transient headroom + H + K + W`, where `B = max(64 MiB, observed loaded cgroup charge + growing-map reserve)`. The empty buffering maps and packet ring contribute to `B`; growing kernel metadata is reserved separately in `K`. `H` reserves the fixed payload pool, descriptors and buffering lifetime metadata; `W` reserves per-URR measurement-window state. With the chart's 64 MiB replay budget, 1024 sessions, 4096 packets and a four-packet per-session ceiling, `H = 31.8125 MiB`, `K = 22.8125 MiB`, `W = 1.5 MiB`, and the minimum floor is 360.125 MiB. A larger measured baseline raises it. The replay budget is shared across N4, Sxa and Sxb; the standalone replay default remains 128 MiB. See [PFCP transport](../../../docs/pfcp-transport.md) for the exact terms and evidence limits.

After this admission check, the automatic Go soft limit is `container hard limit - B - 32 MiB transient headroom`. The replay, session, buffer, URR-window and originated-queue budgets fit within that soft limit; the full startup floor is not subtracted from it. A smaller explicit `GOMEMLIMIT` is honored only when it still fits those budgets. Without a visible cgroup hard limit, startup applies neither an automatic Go soft limit nor this refusal check. Raise map capacities and the memory limit together; forwarding load, rule populations and kernel allocation costs need their own measurements. See [PFCP transport](../../../docs/pfcp-transport.md) for the fixed-workload measurements and operational limits.

### ConfigMap mode (`config.enabled: true`)

```yaml
config:
  enabled: true
  data:
    config.yml: |
      interface_name: eth0
      max_sessions: 1024
      pfcp_replay_memory_mib: 64
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

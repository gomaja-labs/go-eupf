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

- **Privileges**: the default container runs as UID/GID 1000 with NET_ADMIN, SYS_RESOURCE, BPF, PERFMON and DAC_OVERRIDE capabilities. It is not privileged. Adapt capabilities and kernel policy for your cluster.
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

eUPF sizes its eBPF maps from `max_sessions`: two PDR, FAR and URR entries and one QER entry per session, allocated at startup and charged to the pod's memory. eUPF's own default is 65535 sessions, whose maps need about 115 MiB (a working set of about 140 MiB with the process, measured on a kind cluster); the chart's default memory limit is 128 Mi, so `defaultEnv` sets `UPF_MAX_SESSIONS: "1024"`, a working set of about 30 MiB. For production, raise `max_sessions` and `resources.limits.memory` together: about 1.8 MiB per 1024 sessions on top of the process's ~30 MiB, plus headroom; in ConfigMap mode set `max_sessions` in `config.data`, because the default `UPF_*` variables are not injected there.

### ConfigMap mode (`config.enabled: true`)

```yaml
config:
  enabled: true
  data:
    config.yml: |
      interface_name: eth0
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

# eUPF API Documentation

In addition to prometheus metrics (served on a separate `metrics_address` port, see the [metrics guide](metrics.md)) the eUPF API provides a set of endpoints for monitoring and managing the User Plane Function (UPF): health check, XDP/packet/route statistics, configuration display and runtime editing, uplink/downlink PDR maps, QER and FAR maps, PFCP associations and sessions, and subscriber tracing. This API is built with the Gin Web Framework and provides a Swagger API documentation for easy exploration and testing.

## Endpoints

Method | URL                    | Description                                                            | Example
------ | ---------------------- | ---------------------------------------------------------------------- | ----------------------
`GET`  | `/api/v1/health`       | Health check (liveness probe). Returns the JSON string `"OK"`                            | `/api/v1/health`
`GET`  | `/api/v1/xdp_stats`    | Displays the XDP statistics. Returns an object of `XdpStats`           | `/api/v1/xdp_stats`
`GET`  | `/api/v1/packet_stats` | Displays the PACKET statistics. Returns an object of `PacketStats`     | `/api/v1/packet_stats`
`GET`  | `/api/v1/route_stats`  | Displays FIB route lookup statistics. Returns an object of `RouteStats` | `/api/v1/route_stats`

### - QER map

Method | URL                    | Description                                                                | Example
------ | ---------------------- | -------------------------------------------------------------------------- | -------------------
`GET`  | `/api/v1/qer_map`      | Lists the QER map content. Returns a list of `QerMapElement`               | `/api/v1/qer_map`
`GET`  | `/api/v1/qer_map/{id}` | Get QER map element by id. Returns an object of `QerMapElement`            | `/api/v1/qer_map/1`
`PUT`  | `/api/v1/qer_map/{id}` | Set values for QER map element by id. Returns an object of `QerMapElement` | `/api/v1/qer_map/1`

[PUT] Example request body:

```json
{
  "id":0,
  "gate_status_ul": 0,
  "gate_status_dl": 0,
  "qfi": 0,
  "max_bitrate_ul": 200000000,
  "max_bitrate_dl": 100000000
}
```

### - Config

Method | URL                                  | Description                                                               | Example
------ | ------------------------------------ | ------------------------------------------------------------------------- | ------------------------------------
`GET`  | `/api/v1/config`                     | Displays the configuration. Returns an object of `UpfConfig`              | `/api/v1/config`
`POST` | `/api/v1/config/logging_level`       | Set logging level (e.g., `debug`, `info`, `warn`, `error`).               | `/api/v1/config/logging_level`
`POST` | `/api/v1/config/logging_caller`      | Enable or disable displaying caller info in logs.                         | `/api/v1/config/logging_caller`
`POST` | `/api/v1/config/dataplane_ebpf`      | Bind dataplane interfaces and XDP attach mode.                            | `/api/v1/config/dataplane_ebpf`
`POST` | `/api/v1/config/dataplane_addresses` | Update N3/N9 interface IP addresses.                                      | `/api/v1/config/dataplane_addresses`
`POST` | `/api/v1/config/pfcp_n4`             | Update N4 PFCP connection (PFCP address, node ID, and remote nodes list). | `/api/v1/config/pfcp_n4`
`POST` | `/api/v1/config/pfcp_sxa`            | Update Sxa PFCP connection (address, node ID, and remote nodes list).     | `/api/v1/config/pfcp_sxa`
`POST` | `/api/v1/config/pfcp_sxb`            | Update Sxb PFCP connection (address, node ID, and remote nodes list).     | `/api/v1/config/pfcp_sxb`
`POST` | `/api/v1/config/pfcp_timers`         | Update PFCP heartbeat and association setup timers.                       | `/api/v1/config/pfcp_timers`
`POST` | `/api/v1/config/gtp_path`            | Update GTP peers and GTP echo request interval.                           | `/api/v1/config/gtp_path`

[POST] Example request body:

`/api/v1/config/logging_level`

```json
{
  "logging_level": "info"
}
```

`/api/v1/config/logging_caller`

```json
{
  "logging_caller": true
}
```

`/api/v1/config/dataplane_ebpf`

```json
{
  "interface_name": [
    "eth0",
    "eth1"
  ],
  "xdp_attach_mode": "generic"
}
```

`/api/v1/config/dataplane_addresses`

```json
{
  "n3_address": "10.100.200.14",
  "n9_address": "10.100.200.14"
}
```

`/api/v1/config/pfcp_n4`

```json
{
  "pfcp_address": "10.100.200.14:8805",
  "pfcp_node_id": "n4node1",
  "pfcp_remote_node": [
    "10.100.200.15",
    "10.100.200.16"
  ]
}
```

`/api/v1/config/pfcp_sxa`

```json
{
  "sxa_address": "10.100.200.14:8805",
  "sxa_node_id": "sxanode1",
  "sxa_remote_node": [
    "10.100.200.17",
    "10.100.200.18"
  ]
}
```

`/api/v1/config/pfcp_sxb`

```json
{
  "sxb_address": "10.100.200.14:8805",
  "sxb_node_id": "sxbnode1",
  "sxb_remote_node": [
    "10.100.200.19",
    "10.100.200.20"
  ]
}
```

`/api/v1/config/pfcp_timers`

```json
{
  "association_setup_timeout": 10,
  "heartbeat_timeout": 5
}
```

`/api/v1/config/gtp_path`

```json
{
  "gtp_peer": [
    "10.100.200.30:2152",
    "10.100.200.31:2152"
  ],
  "gtp_echo_interval": 60
}
```

### - Uplink PDR

Method | URL                           | Description                                                         | Example
------ | ----------------------------- | ------------------------------------------------------------------- | --------------------------
`GET`  | `/api/v1/uplink_pdr_map/{id}` | Get Uplink PDR values by TEID. Returns an object of `PdrUplinkElement`    | `/api/v1/uplink_pdr_map/1`
`PUT`  | `/api/v1/uplink_pdr_map/{id}` | Set Uplink PDR values by TEID. Returns a new object of `PdrUplinkElement` | `/api/v1/uplink_pdr_map/1`

[PUT] Example request body:

```json
{
  "teid": 2,
  "outer_header_removal": 0,
  "far_id": 1,
  "qer_id": 1,
  "trace": true
}
```

### - Downlink PDR

Method | URL                             | Description                                                                  | Example
------ | ------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------
`GET`  | `/api/v1/downlink_pdr_map/{id}` | Get Downlink PDR values by IPv4 or IPv6\. Returns an object of `PdrDownlinkElement`    | `/api/v1/downlink_pdr_map/2a03:d000:29a0:0509:0001:0000:1f86:9ec4`
`PUT`  | `/api/v1/downlink_pdr_map/{id}` | Set Downlink PDR values by IPv4 or IPv6\. Returns a new object of `PdrDownlinkElement` | `/api/v1/downlink_pdr_map/10.45.0.2`

[PUT] Example request body:

```json
{
  "ip": "2a03:d000:29a0:509:1:0:1f86:9ec4",
  "outer_header_removal": 0,
  "far_id": 1,
  "qer_id": 1,
  "trace": true
}
```

### - FAR map

Method | URL                    | Description                                                                   | Example
------ | ---------------------- | ----------------------------------------------------------------------------- | -------------------
`GET`  | `/api/v1/far_map/{id}` | Get FAR map element by id. Returns an object of `FarMapElement`               | `/api/v1/far_map/1`
`PUT`  | `/api/v1/far_map/{id}` | Set values for FAR map element by id. Returns a new object of `FarMapElement` | `/api/v1/far_map/1`

[PUT] Example request body:

```json
{
  "action": 0,
  "outer_header_creation": 0,
  "teid": 0,
  "remote_ip": 0,
  "transport_level_marking": 0
}
```

### - PFCP associations

Method | URL                              | Description                                                                 | Example
------ | -------------------------------- | --------------------------------------------------------------------------- | --------------------------------
`GET`  | `/api/v1/pfcp_associations`      | Lists the PFCP associations. Returns a list of `NodeAssociationDescription` | `/api/v1/pfcp_associations`
`GET`  | `/api/v1/pfcp_associations/full` | Lists the full PFCP associations. Returns objects of `NodeAssociation`      | `/api/v1/pfcp_associations/full`
`POST` | `/api/v1/pfcp_associations/release` | Calls for PFCP Association Release Request for all established associations. Returns nothing      | `/api/v1/pfcp_associations/release`

### - PFCP sessions

Method   | URL                     | Description                                                                                                                                                | Example
-------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -----------------------------------------------
`GET`    | `/api/v1/pfcp_sessions` | Lists the PFCP sessions. If no parameters are given, returns all sessions. If ip or teid is given, returns filtered sessions. Returns a list of `Session`. | `/api/v1/pfcp_sessions?ip=192.168.1.1&teid=123`
`DELETE` | `/api/v1/pfcp_sessions` | Deletes a PFCP session by IMSI, MSISDN or session ID. Exactly one parameter required. Returns status message.                                             | `/api/v1/pfcp_sessions?imsi=123456789012345`

### - Subscriber tracing

Method   | URL                        | Description                                                                                                                     | Example
-------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | -----------------------------------------------
`GET`    | `/api/v1/subscriber_trace` | Lists active subscribers for trace filtered by IMSI or MSISDN. Returns a list of `TraceRecord`                                  | `/api/v1/subscriber_trace`
`POST`   | `/api/v1/subscriber_trace` | Set subscriber for tracing by its IMSI or MSISDN. Repeated request for already existed subscriber is not considered as an error | `/api/v1/subscriber_trace?imsi=255018600005299`
`DELETE` | `/api/v1/subscriber_trace` | Delete subscriber from tracing by its IMSI or MSISDN. Delete all subscribers if not params are provided                         | `/api/v1/subscriber_trace?msisdn=88095983595`

## Swagger API Documentation

To explore and test the API, you can use the Swagger API documentation. To access the Swagger UI, navigate to the following endpoint in your browser:

- GET /swagger/index.html

## API docs generation

[Reference documentation](https://github.com/swaggo/gin-swagger)

```bash
cd {repo_root}
go generate ./cmd/...
```

This runs `go tool swag init --parseDependency --parseInternal --parseDepth 1 -g api/rest/handler.go` (see the `go:generate` directive in `cmd/main.go`).

## Authentication and response formats

The API listens on loopback by default. A non-loopback bind requires `UPF_API_TOKEN` (or `api_token` in the configuration). With a token configured, send `Authorization: Bearer <token>` on all management and Swagger requests. Only `GET /api/v1/health` is unauthenticated; it returns the JSON string `"OK"`. Set `api_allowed_origins` to explicit browser origins if needed; no cross-origin access is allowed by default. The metrics listener is separate and should stay private. Use TLS at a trusted reverse proxy or a private management tunnel across hosts.

```bash
curl -H "Authorization: Bearer $UPF_API_TOKEN" http://127.0.0.1:8080/api/v1/config
```

An empty session result currently serializes as JSON `null`. Session deletion takes exactly one query key (`imsi`, `msisdn` or `id`) and returns a JSON message/error object. Trace creation returns empty HTTP 201; a trace lookup with no matches returns empty HTTP 404. Association release returns empty HTTP 204. Configuration edits return HTTP 500 when the runtime edit is applied but the selected configuration file cannot be written.

To change XDP attach mode, first submit `interface_name: []` with the current mode to detach all links, then submit the desired interfaces and mode. Changing the mode while links are active returns HTTP 409.


### Request safety and HTTPS

GET and HEAD never change state ([RFC 9110 section 9.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1)).
Every POST, PUT, PATCH and DELETE requires `Content-Type: application/json`, including
operations with an empty body, such as association release. Other media types return
415. A tokenless loopback listener accepts only loopback Host names/addresses or its
configured address, preventing a remote DNS name from rebinding to this API.

Configure `api_tls_cert_file` and `api_tls_key_file` together to serve HTTPS directly.
The files contain a PEM certificate chain and private key. Startup fails if either
is missing or invalid. TLS 1.2 and later are supported; TLS 1.0 and 1.1 are disabled
([RFC 8996 section 3](https://www.rfc-editor.org/rfc/rfc8996.html#section-3), updating RFC 6750).
TLS does not replace the required bearer token outside loopback. If using plain HTTP
off loopback, provide equivalent transport security, such as a TLS proxy on an
isolated local network; startup logs a warning. Bearer tokens require confidentiality
in transit ([RFC 6750 section 5.3](https://www.rfc-editor.org/rfc/rfc6750.html#section-5.3)).
The shared administration token is not an OAuth authorization server or grant flow;
RFC 9700's grant-flow guidance does not add such flows to this API.

```yaml
api_address: 0.0.0.0:8080
api_tls_cert_file: /etc/eupf/tls/tls.crt
api_tls_key_file: /etc/eupf/tls/tls.key
```

Supply the token through `UPF_API_TOKEN`. The CLI accepts an `https://` URL in
`eupf_addr` or `--baseurl` and verifies the server certificate and hostname.
For a private CA, set `api_ca_bundle` in `config-cli.yaml`, `CLI_API_CA_BUNDLE`, or
`--api_ca_bundle` to a PEM CA file. There is no option to disable verification.
The Helm chart mounts `api.tls.existingSecret` at `/etc/eupf/tls`, selects HTTPS in
the optional CLI sidecar, and uses `api.tls.caBundleKey` when configured. The server
certificate must cover the addresses clients use, including 127.0.0.1 for that sidecar.

Configuration edits validate a candidate copy with the startup validator. Invalid
values return 400 naming the setting before runtime or persistence changes. PFCP
endpoint edits resolve every peer and bind the candidate socket before committing;
a failure leaves the old socket, identity, connectors and file in place. N3/N9
interface edits preserve separately advertised N3/N9, S1-U/S5S8 and PA addresses.

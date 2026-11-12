# Local and advertised user-plane addresses

[Configuration reference](Configuration.md) · [Data-plane settings](dataplane-settings.md)

A container or network namespace can have a private N3 address while the RAN
needs a different, reachable address. This is the use case in
[upstream #628](https://github.com/edgecomllc/eupf/issues/628).
The settings below accept IPv4 literals, not hostnames, FQDNs or IPv6 addresses.
`UpfConfig.Validate` enforces the `ipv4` tags in
[`cmd/config/config.go`](../cmd/config/config.go).

## Address selection

| Setting | Default / derivation | Use in this implementation |
| --- | --- | --- |
| `n3_address` | `127.0.0.1` | Local GTP-U destination accepted by XDP, source for downlink encapsulation, and local GTP path-manager address. |
| `n9_address` | Startup `n3_address` | Second local GTP-U destination accepted by XDP; source for N9 tunnel forwarding. |
| `n3_adv_address` | `n3_address` | N4 connection's access-side address for UP-allocated F-TEIDs, unless the session uses the 5G override below. |
| `n3_adv_address_5g` | `n3_address`, independently of `n3_adv_address` | Access-side F-TEID address for sessions classified as 5G. |
| `n9_adv_address` | `n9_address` | N4 connection's core-side address for UP-allocated F-TEIDs. |
| `s1u_address` | `127.0.0.1`; no N3 derivation | Sxa connection's access-side F-TEID address. |
| `s5s8_address` | `127.0.0.1`; no N9 derivation | Sxa connection's core-side F-TEID address. |
| `pa_address` | `127.0.0.1`; no N3/N9 derivation | Sxb connection's access- and core-side F-TEID address. |

Defaults and provenance are in `defineFlags`, `initCommonConfig`, `Unmarshal`
and `explicitAddress` in [`cmd/config/config.go`](../cmd/config/config.go).
The three Sxa/Sxb user-plane fields also permit an empty string at configuration
validation (`omitempty,ipv4`); configure actual IPv4 addresses when using them.
Sxa/Sxb connections start only when `sxa_address` / `sxb_address` is nonempty.
Those two settings are PFCP bind host:port values, distinct from the user-plane
addresses above. See [`cmd/main.go`](../cmd/main.go), `startConn` and its callers.

For newly allocated tunnel resources, PFCP Session Establishment Responses and
Session Modification Responses carry an F-TEID IE inside Created PDR; a
modification can also carry one inside Updated PDR. Source Interface Access
(value 0) selects the access-side address; other supported source interfaces
select the core-side address. This is allocation response information, not an
unconditional rewrite of CP-provided F-TEIDs. See `allocatedPDRChildren`,
`processCreatedPDRs` and `processUpdatedPDRs` in
[`cmd/core/pdr.go`](../cmd/core/pdr.go), and TS 29.244 V20.1.0 clause 5.5.3,
clause 8.2.3, Tables 7.5.3.2-1 and 7.5.5.5-1.

The implementation classifies a session as 5G at establishment when S-NSSAI or
a QFI in Create QER is present. A QFI in Create/Update QER during modification
also marks it as 5G. `sessionN3Address` then selects the global
`n3_adv_address_5g` runtime snapshot, including for Sxa/Sxb connections if a
session on them is classified this way. See
[`cmd/core/pfcp_session_handlers.go`](../cmd/core/pfcp_session_handlers.go),
`HandlePfcpSessionEstablishmentRequest`, `HandlePfcpSessionModificationRequest` and
`sessionN3Address`.

With `pfcp_profile: huawei`, outgoing Sxa Association Setup Requests additionally
encode S1-U/S5S8 addresses in enterprise 2011 IE 32787; Sxb requests encode PA
in that IE. The default profile's Association Setup Requests do not include
these vendor address fields. See `buildSxaSetupRequestIEs` /
`buildSxbSetupRequestIEs` in [`cmd/core/pfcp_build_ie.go`](../cmd/core/pfcp_build_ie.go)
and the connector methods in [`cmd/core/pfcp_profile.go`](../cmd/core/pfcp_profile.go).
These vendor IEs are implementation-specific, not standard F-TEID IEs.

## Example: advertise a reachable address

```yaml
n3_address: 192.0.2.10
n9_address: 192.0.2.11
n3_adv_address: 198.51.100.10
n3_adv_address_5g: 198.51.100.10
n9_adv_address: 198.51.100.11
```

Set both N3 advertised settings if both kinds of sessions should advertise the
same external address. Advertising does not assign an address to an interface,
create a route, install NAT or add another XDP receive address. Arrange external
routing or translation so packets reach the configured local N3/N9 address.
The receive-address match and encapsulation sources are in
[`cmd/ebpf/xdp/n3n6_entrypoint.c`](../cmd/ebpf/xdp/n3n6_entrypoint.c),
`upf_ip_entrypoint_func`, `handle_n6_packet_ipv4` and `handle_gtp_packet`.
Multiple endpoint selection remains a [deferred request](roadmap.md).

## REST edits and restart behaviour

`POST /api/v1/config/dataplane_addresses` replaces the complete section:

```json
{"n3_address":"192.0.2.20","n9_address":"192.0.2.21"}
```

Both fields are required and must be IPv4 literals. On success, the handler
updates the XDP global configuration, the GTP path-manager local N3 address,
the N4 advertised address snapshots and the 5G snapshot, then persists the
submitted keys. No restart is required for this edit. See
`editDataPlaneAddressesConfig` / `validatedEdit` in
[`cmd/api/rest/config.go`](../cmd/api/rest/config.go) and
`UpdateDataPlaneAddresses` in [`cmd/core/config_edit.go`](../cmd/core/config_edit.go).

Each advertised setting remembers whether a nonempty value was supplied in
the startup file, flag or environment. Unset or empty advertised values follow
the corresponding local address edit. Explicit values remain fixed, even if
they initially equalled the local address. Sxa S1-U/S5S8 and Sxb PA stay fixed.
The REST schema exposes only the local N3/N9 pair; changing an explicit
advertised or Sxa/Sxb user-plane address requires a startup-source change and
restart. See [`cmd/api/rest/schemas.go`](../cmd/api/rest/schemas.go) and
`RefreshDerivedAdvertisedAddresses` in [`cmd/config/config.go`](../cmd/config/config.go).

N9's startup fallback is separate: after startup, an edit supplies N9 explicitly;
it does not automatically track N3. Derived advertised values are not frozen
into the file by the edit. `UpdateFile` writes only submitted keys to the
selected configuration file, preserving the distinction on restart with the
same startup sources. Startup flag/environment overrides still take precedence
on restart. A file edit by itself does not reload runtime settings. A runtime
edit followed by a persistence error returns HTTP 500; inspect the response
and runtime configuration before retrying. See `updateConfigFile` in
[`cmd/api/rest/config.go`](../cmd/api/rest/config.go).

An address edit does not signal replacement tunnel endpoints to existing CP
peers or rewrite all existing session state. Coordinate changes with the CP
and network; future allocation responses use the new selection. The handler
calls no PFCP session-update procedure (`UpdateDataPlaneAddresses`, above).

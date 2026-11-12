# PFCP transport and peer liveness

PFCP uses TS 29.244 V20.1.0. Each connection serializes association and session
changes; REST and metrics readers take consistent snapshots. Heartbeat maintenance
and retransmissions share the receive loop, with no goroutine per association.

The following startup options use the listed YAML key. The environment name is
`UPF_` followed by the uppercase key, and the CLI flag replaces underscores with
hyphens. All seven policy options in the table require a configuration file update and restart; REST does not edit them. The existing timer API can
change `heartbeat_timeout` and `association_setup_timeout` while running.

| Key | Default | Meaning |
| --- | --- | --- |
| `pfcp_peer_allow_list` | `[]` | Source IP addresses or CIDR networks admitted before decoding any PFCP datagram. Empty admits every source, including unknown heartbeat peers. Restrict this list or isolate the PFCP network when peers are untrusted. |
| `pfcp_request_timeout` | `5` | T1 in seconds for originated requests other than heartbeat. Range 1–3600; zero selects 5. |
| `pfcp_request_retries` | `3` | N1 retransmissions after the initial request, 0–100. Zero sends once. |
| `pfcp_response_retention` | `60` | Duplicate request response cache lifetime in seconds, 20–86400. Zero selects 60. Must cover the configured local retry windows; align it with the peer's maximum retransmission window too. |
| `pfcp_max_transactions` | `4096` | Maximum outstanding originated requests and maximum cached request outcomes per association. At most 65536; zero selects 4096. |
| `pfcp_max_associations` | `1024` | Maximum simultaneous associations per connection. At most 65536; zero selects 1024. Existing Node IDs may replace their association at this limit. |
| `heartbeat_failure_grace` | `0` | Extra unreachable seconds after exhausting heartbeat retransmissions, at most 86400. During this interval sessions remain installed and probes continue. Zero deletes the failed peer and its sessions after the retry budget. A valid heartbeat clears the failure period. |

Existing `heartbeat_timeout` is the heartbeat T1 in seconds (zero disables
originated probes), `heartbeat_retries` is N1, and `heartbeat_interval` is the
interval between probes, with no overlapping probe for a peer. Timeout and
interval values are at most 3600 seconds and retries at most 100. An interval
of zero selects five seconds.

For example:

```yaml
pfcp_peer_allow_list: [192.0.2.0/24, '2001:db8::/32']
pfcp_request_timeout: 5
pfcp_request_retries: 3
pfcp_response_retention: 60
pfcp_max_transactions: 4096
pfcp_max_associations: 1024
heartbeat_timeout: 5
heartbeat_retries: 3
heartbeat_interval: 5
heartbeat_failure_grace: 30
```

TS 29.244 clause 6.4 requires identical retransmissions and endpoint/sequence
matching. Originated sequence numbers are allocated across the local endpoint
and are never reused while outstanding. Duplicate requests replay their encoded
response without repeating session operations. Cache retention is local policy;
clause 6.4 specifies no numeric lifetime. Each association's response cache and the connection's outbound queue have separate
16 MiB encoded-payload ceilings. Unassociated sources do not consume replay entries.
Expiry uses an ordered index rather than scanning all responses on every datagram.

A full association budget evicts its oldest entries after a minimum replay window
of 20 seconds, even if the configured retention has not elapsed. A peer's N1/T1 is
unknown; operators must size the budget for the peer's retransmission window and
burst rate. Entries younger than 20 seconds are protected: new requests beyond
capacity are left unexecuted and unanswered for peer retransmission, without a
Cause 75 rejection. Defaults sustain up to 4096 / 20 = 204.8 distinct requests per
second per association when replies fit the byte budget and bursts stay within
4096 entries. At maximum 65535-byte replies, the byte budget permits only 256
protected entries (12.8 requests/s); allow headroom for bursts and other procedures.
These are admission-budget rates, not measured throughput claims.

Bundling requires both UP and CP BUNDL feature bits negotiated during association
setup or update (TS 29.244 V20.1.0 clauses 6.5, 8.2.25 and 8.2.58). The UPF
advertises support and accepts at most 16 messages and 8192 bytes in a bundle.
Unassociated, unnegotiated and oversized bundles are discarded as a whole, before
any decoder or handler can produce responses. A supported datagram can cause at
most 16 responses, each bounded by the UDP payload limit.

TS 23.527 V20.0.0 clauses 4.2, 4.4.2.1 and 4.4.3.1 require ignoring Association
Setup recovery timestamps, detecting restarts from heartbeat timestamps, and
deleting affected sessions after restart or the configured unreachable period.
TS 23.007 V19.2.0 clause 19A distinguishes an increased timestamp (restart) from
a smaller reordered timestamp (discard). An indefinite keep-sessions-on-failure
mode would conflict with these requirements for a UPF without SMF-set support.
Association Setup with an existing Node ID replaces the association; only
sessions requested by the PFCP Session Retention Information IE survive
(TS 29.244 clause 6.2.6.2.2 and Table 7.4.4.1-2).

PFCP receives use a 65535-byte buffer so reassembled UDP datagrams larger than a
link MTU are not truncated. Unknown message types and unmatched responses are
discarded (clauses 7.6.4 and 7.6.5). Valid heartbeats from admitted, unknown peers
are answered without allocating an association (clause 6.2.2.2).

Monitor `upf_pfcp_retransmissions`, `upf_pfcp_request_timeouts` and
`upf_pfcp_association_prunes` alongside session counts. Set the retry budget and
grace period for the deployment's tolerated disruption, and reserve processing
capacity for PFCP while forwarding traffic. A delayed receive loop sends each
configured retry before declaring failure; it does not consume the entire
budget merely because several timer intervals elapsed during local overload.

Associations are indexed by the CP Node ID, independent of source addresses
(TS 29.244 V20.1.0 clause 5.8.1). Establishment uses the request's Node ID;
Modification and Deletion resolve the local SEID and its owning association.
Different Node IDs may share an address. The source allow-list still applies
before decoding, so every additional CP address must be admitted by that list.

Responses return to the request's source IP and UDP port (clause 4.2.2).
Originated requests always use destination port 8805. Node requests use the
Node ID address when it is an IP. For FQDN Node IDs this implementation uses
the admitted Setup source IP, without a DNS lookup in the receive loop; those
peers must provide a routable source address, or configure an IP Node ID when
using NAT (clause 5.8.1 NOTE 2). Setup source ports are never saved as request
destinations. Heartbeats cover that node endpoint; incoming heartbeat recovery
is attributed only to an unambiguous known source/entity. Arbitrary source
addresses are not accumulated as a growing address registry.

Session requests use the session's CP F-SEID address on port 8805 (clause
4.3.2), including an accepted Modification that changes it. Both IPv4 and IPv6
are retained; IPv4 is preferred on an IPv4 socket and IPv6 on an IPv6 socket.
A session's advertised addresses also identify its CP entity for recovery.

The CLI retains every configuration field returned by `GET /config` in `eupf show`
and backup archives. Archives use the server's YAML key names. Restore checks all
startup-only fields before any runtime edit: if any differ, it lists their keys
and returns an error requiring a configuration file update and restart. It never
reports a successful restore while discarding a changed transport policy.


The association setup timer uses `association_setup_timeout` at startup and after
REST edits (range 1–1048576 seconds). An existing unreadable or malformed config
file fails startup; an explicitly selected missing `--config` or `--pcc-config`
file also fails. Only an absent implicit default file uses defaults.

SIGTERM and SIGINT stop HTTP listeners and run deferred socket, map, XDP-link,
SDF-listener and capture cleanup. Normal shutdown exits zero. HTTP shutdown has a
three-second deadline and force-closes remaining connections; the process gives
all shutdown work at most 15 seconds and reports deadline expiry as failure.
Association release is still handled by the existing release hook pending the
separate release-lifecycle change.

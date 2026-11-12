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
| `pfcp_max_transactions` | `4096` | Maximum outstanding originated requests and maximum cached request outcomes per connection. At most 65536; zero selects 4096. |
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
clause 6.4 specifies no numeric lifetime. Cached responses have one connection-wide
entry limit (`pfcp_max_transactions`) and one 16 MiB total accounting limit.
Accounting includes the encoded response, stored peer/entity strings, and a
conservative 1024-byte metadata charge per entry for both indexes and the map.
The bound is shared by all associations; adding associations does not multiply
it. The originated-request queue has a separate 16 MiB encoded-payload ceiling.
These are retained-state limits, not a bound on process RSS, transient decoding
allocations or the Go allocator's overhead. Unassociated sources consume no
replay entries. Initial successful Setup is charged to the new Node ID.

Before executing new work, admission reserves room for a maximum-size response
and its metadata. On saturation, an association below its entry and byte fair
shares may evict the oldest eligible response of the association most above its
share. Other associations may replace only their own old responses. No response
is evicted within the 20-second minimum replay window. If none is eligible, new
work is left unexecuted and unanswered for retransmission, without Cause 75.
Both Heartbeat and Association Release bypass this gate. The fair shares adapt
to the number of associations; all of a Node ID's source addresses share them.
Expiry and association cleanup use linked indexes: forgetting an association
visits only its own responses and removes their accounting immediately.

With default limits, at most 4096 small outcomes fit in one protected window
across the entire connection: 4096 / 20 = 204.8 distinct requests per second,
shared between associations. Large responses can reach the byte bound earlier.
These are admission-budget calculations, not measured throughput. Size limits
and replay retention must cover the peer's N1/T1 window and expected bursts.

Bundling requires both UP and CP BUNDL bits from that association's own Setup
or Update exchange, including UP-initiated Sxa/Sxb (TS 29.244 V20.1.0 clause
6.5). Every valid session message in a negotiated bundle is processed as if it
arrived alone, subject to the same replay admission. The UDP datagram bounds
work; there is no additional message-count or 8192-byte cutoff. Admission
retains the peer association across a bundle, including deletion of its last
session; replay entries retain that identity for later retransmissions from an
additional CP address. Unassociated or
unnegotiated bundled frames are discarded. Node messages in a bundle are not
processed: the codec reports invalid bundle framing, which is logged with the
peer and frame position. No frame boundary is invented after invalid framing.

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
Shutdown and POST `/pfcp_associations/release` start the same UP-initiated
procedure (TS 29.244 V20.1.0 clauses 6.2.7.3.1 and 6.2.8). Each CP receives an
Association Update Request with the release indication and Graceful Release
Period. The period is `T1 * (N1 + 1)` using `pfcp_request_timeout` and
`pfcp_request_retries`, rounded up to two-second IE units and limited to 2–8
seconds. The queued Update retransmits normally. Its acknowledgement or failure
does not remove the association or sessions. CP Release, or expiry of that
period, starts rule cleanup. An originated-queue admission failure is logged;
indication admission is retried while at least two seconds of the same bounded
local timer remain. Heartbeat failure cannot shorten an initiated release.
New Setup is refused while the connection is releasing; established sessions
continue to accept CP changes until cleanup starts.

The UPF always accepts CP Association Release, including retries and unknown
Node IDs. Cleanup commits each session through the existing rule transaction
API. A failed session remains owned with its IDs reserved; no release waiter
reports completion while any rules remain. Cleanup retries after 100, 200, 400,
then at most 500 milliseconds, for three seconds from the first cleanup attempt.
Exhaustion logs the affected session IDs and sends a terminal error to the
supervisor, which exits non-zero after deferred cleanup. No failed session's
IDs are recycled. During cleanup, session admission to that association stops.
The release waiter observes locked counts and fatal state. The grace period,
three-second cleanup allowance and HTTP shutdown fit the process deadline.

Rule maps are not pinned: the only pinned map is the program dispatch array.
Startup loads fresh rule maps and replaces the dispatch programs. Restart
therefore does not restore rules from the failed process. The retained tests
and wire evidence exercise this with synthetic state; no persistent session
restoration is claimed.

Every originated procedure has one terminal completion: accepted response, peer
rejection, invalid response, no response after N1, or local cancellation. An
invalid matching response stops retransmission and notifies the procedure even
when it is discarded (clauses 7.6.1 and 7.6.3). Heartbeat clears its probe state;
retry exhaustion applies the configured unreachable policy. A failed Setup
waits a full setup interval before another configured connector attempt. Session
Report failures are recorded for their live session and logged with procedure,
peer and remote SEID; failure does not imply acknowledgement, and no new report
transaction is invented beyond N1. An accepted later report clears that failure.
Association Update completion never substitutes for the CP's Release Request.

A complete Request header with inconsistent Length receives Cause 68; session
responses use the known CP SEID or zero (clauses 7.6.3 and 7.2.2.4.2). Too-short
headers are discarded. An inconsistent-length Heartbeat Request is logged and
discarded because its Response has no Cause IE, consistent with the Heartbeat
exemptions in clauses 7.6.6 and 7.6.7. Valid frames before an untrustworthy bundle
length are processed; decoding never guesses a subsequent boundary.

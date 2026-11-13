# PFCP transport and peer liveness

PFCP uses TS 29.244 V20.1.0. Each connection serializes association and session
changes; REST and metrics readers take consistent snapshots. Heartbeat maintenance
and retransmissions share the receive loop, with no goroutine per association.

The following startup options use the listed YAML key. The environment name is
`UPF_` followed by the uppercase key, and the CLI flag replaces underscores with
hyphens. Startup policy options in the table require a configuration file update and restart; REST does not edit them. The existing timer API can
change `heartbeat_timeout` and `association_setup_timeout` while running.

| Key | Default | Meaning |
| --- | --- | --- |
| `pfcp_peer_allow_list` | `[]` | Source IP addresses or CIDR networks admitted before decoding any PFCP datagram. Empty admits every source, including unknown heartbeat peers. Restrict this list or isolate the PFCP network when peers are untrusted. |
| `pfcp_request_timeout` | `5` | T1 in seconds for originated requests other than heartbeat. Range 1–3600; zero selects 5. |
| `pfcp_request_retries` | `3` | N1 retransmissions after the initial request, 0–100. Zero sends once. |
| `pfcp_response_retention` | `60` | Duplicate request response cache lifetime in seconds, 20–86400. Zero selects 60. Must cover the configured local retry windows; align it with the peer's maximum retransmission window too. |
| `pfcp_max_originated_requests` | `4096` | Outstanding originated requests per connection, 1–65536; zero selects 4096. |
| `pfcp_max_replay_entries` | `131072` | Retained request outcomes across the process, 1–1048576; zero selects 131072. |
| `pfcp_replay_memory_mib` | `128` | Replay accounting budget across the process in MiB, 16–1024; zero selects 128. |
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
pfcp_max_originated_requests: 4096
pfcp_max_replay_entries: 131072
pfcp_replay_memory_mib: 128
pfcp_max_associations: 1024
heartbeat_timeout: 5
heartbeat_retries: 3
heartbeat_interval: 5
heartbeat_failure_grace: 30
```

TS 29.244 clause 6.4 requires identical retransmissions and endpoint/sequence
matching. Originated sequence numbers are unique across the local endpoint
while outstanding. A duplicate request replays the encoded outcome without
repeating session operations. The entire configured `pfcp_response_retention`
protects an outcome; there is no shorter eviction window. A duplicate whose
final-usage response is still waiting is dropped until that response is ready.
Its state change has already committed, so a later request sees the changed
session. Responses can leave in sequence-independent order.

Replay entries and memory have independent process-wide bounds, shared by N4, Sxa and Sxb through their common resource manager. Accounting
charges the encoded response, stored peer/entity strings and 640 bytes of
metadata per completed outcome. A pending final-usage response reserves the
maximum 65535-byte encoding plus metadata. This covers the measured retained
metadata; it is not a bound on process RSS, transient IE trees, decoding or Go
allocator overhead. The originated queue has its own entry bound and a separate
16 MiB encoded-payload ceiling. Unassociated sources allocate no replay entries;
a successful initial Setup is charged to the learned Node ID.

New cacheable work reserves global capacity before execution. Fair shares use
the associations currently holding entries: entry bound / holders and memory
bound / holders, with a new entrant included. A peer already at either share
waits for expiry; a peer below both shares uses available global space. No
unexpired outcome is evicted. A peer arriving at a full cache must therefore
wait for expiry even when the current holders exceed its eventual share. A
single admitted response can exceed its byte share, after which further new
work is deferred. Heartbeat and Association Release always bypass replay
capacity. `upf_pfcp_replay_capacity_drops_total` counts capacity deferrals.

Capacity planning uses `rate * retention` entries and
`entries * (encoded response bytes + peer/entity bytes + 640)` accounting bytes,
plus one maximum-response reservation. At 2000 small cacheable requests/second
and 60 seconds, 120000 outcomes fit the default 131072 entries and 128 MiB.
A Linux/amd64 Go 1.27.4 heap probe retaining 120000 80-byte replies measured
54.5 MB with one association and 55.4 MB with 1024 associations, against 89.4 MB charged by the cache.
Large replies consume the memory bound sooner. Reproduce the heap measurement
with `EUPF_REPLAY_HEAP=/tmp/replay.heap go test ./cmd/core -run
TestReplayOutcomeHeapProfile -count=1 -v`. The budgets do not multiply when Sxa/Sxb are enabled. The chart uses a 512 MiB memory limit and one CPU, with a 500m CPU request. Its memory floor is `2 * replay budget + max(64 MiB, observed startup/map charge plus growing-map reserve) + 3 * 16 MiB originated payloads + 32 MiB transient headroom`: 400 MiB at defaults. The 64 MiB baseline floor covers the measured default-map startup peak, including memory charged by the kernel. A default-capacity map-only probe filled all 2048 entries in each PDR hash/trie and measured about 32.7 MiB of additional kernel charge; the growing-map reservation is 38 MiB. The process reads the cgroup memory limit and current charge before and after loading maps, adds a conservative capacity reservation for growing PDR hash/trie entries, refuses a budget that cannot fit, and derives a Go soft limit by subtracting the baseline and 32 MiB headroom. It honors a smaller `GOMEMLIMIT` only if that can fit the configured replay and queues. Go does not account for BPF kernel memory in its soft limit. Larger map/session configurations need a larger cgroup limit; the observed baseline raises the floor automatically.

Expiry and association invalidation unlink entries from both indexes in O(1)
per removed outcome. Every address of one peer Node ID on the same local connection uses the same share. Associations on different local N4/Sxa/Sxb endpoints have distinct shares, even for the same peer Node ID; all shares consume the single process budget.

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
A CP-initiated Association Setup Request with an existing Node ID replaces the association; only
sessions requested by the PFCP Session Retention Information IE survive
(TS 29.244 clause 6.2.6.2.2 and Table 7.4.4.1-2). A UP-initiated Setup Response
for an established Node ID retains that association and its sessions (clause
6.2.6.3). Configured connectors remember the Node ID learned from the response
and stop Setup attempts while that identity remains associated.

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
A session's advertised addresses also identify its CP entity for recovery. Every
session originator carries the local UP SEID through destination selection and
completion; CP SEID values can collide between entities of one association
(clauses 5.6.2 and 5.22.2). The address index counts Setup, association and CP
F-SEID references, removing each only after its final session reference leaves.

The CLI retains every configuration field returned by `GET /config` in `eupf show`
and backup archives. Archives use the server's YAML key names. Restore checks all
startup-only fields before any runtime edit: if any differ, it lists their keys
and returns an error requiring a configuration file update and restart. It never
reports a successful restore while discarding a changed transport policy.


The association setup timer uses `association_setup_timeout` at startup and after
REST edits (range 1–1048576 seconds). An existing unreadable or malformed config
file fails startup; an explicitly selected missing `--config` or `--pcc-config`
file also fails. Only an absent implicit default file uses defaults.

SIGTERM and SIGINT latch process-wide Setup refusal on every PFCP endpoint,
including idle endpoints while a REST release waiter runs. New Setup receives
Cause 75, No resources available (table 7.4.4.2-1 and clause 8.2.1). Pending
UP-initiated Setups complete as canceled and no new ones are admitted. Final
usage responses waiting at socket Close are canceled; shutdown never waits on
those goroutines while holding the connection lock.

Shutdown and POST `/pfcp_associations/release` send an Association Update with
the release indication and Graceful Release Period (clauses 6.2.7.3.1 and
6.2.8). The period is `T1 * (N1 + 1)`, rounded up to two-second units and limited
to 2–8 seconds. Identical retransmissions advertise that same full period.
The local deadline grants the full period from an accepted Update Response,
or from the last transmission when no accepted response arrives. It never
expires earlier than that grant. Admission failures are retried within a
bounded delivery window. Heartbeat failure cannot shorten release. Established
sessions accept CP changes until cleanup starts.

A REST release selects only the associations present at initiation. Setup is
refused while that connection drains; once those associations leave, management
release permits new associations again. New associations do not extend its
waiter. A management wait timeout is logged and does not terminate the UPF.

CP Association Release is always accepted, including unknown Node IDs and
retransmissions. Its response precedes cleanup. Admission to that association
stops immediately, and receive-loop maintenance deletes sessions in batches of
64, releasing locks between batches. Successful progress has no cleanup time
limit. Each session that actually fails deletion starts its own three-second retry window, with
100, 200, 400 and then at most 500 ms backoff. Retired-map reclamation and failed
rollback use the same bounded recovery policy. A successful deletion clears that session's failure history; a transient error cannot give healthy remaining sessions a deadline. Affected IDs stay reserved.
Exhaustion logs affected sessions and exits non-zero through the supervisor;
it never silently leaves admission poisoned indefinitely.

During process shutdown, an already released association, or an expired release
period, requires no per-session map deletion: the UPF closes its bpf_link XDP
attachments and map descriptors. Rule maps are unpinned; the only pinned map is
an empty program dispatch array. Startup creates fresh rule maps. No persistent
session restoration is provided. The process deadline is the delivery window,
full graceful period and four seconds for HTTP shutdown/scheduling: 32 seconds
with default T1=5, N1=3. The chart uses 40 seconds. Raise the chart's
`terminationGracePeriodSeconds` above the derived process deadline when changing
transport retries/timeouts. HTTP shutdown itself has a three-second deadline.

Every originated procedure has one terminal completion: accepted, rejected,
invalid, timed out, or canceled. Changing heartbeat timeout cancels every old
probe through that completion path. A failed Setup backs off for a setup
interval. A Session Report accepted by the CP marks its information delivered
(clause 6.3.5.2). Cause 65 queues local deletion only while the addressed CP F-SEID (SEID and IP) remains current. A failed transfer to a superseded CP F-SEID is immediately re-originated with the same report information, the current CP F-SEID and a new sequence number (table 7.5.4.1-1; clauses 6.3.5.3 and 6.4). The address is rechecked before queued local deletion. Other failures and timeouts are logged and counted in
`upf_pfcp_report_failures_total`. Admitted usage from a failed transfer is added
to the live URR's next report, including a later termination report.

A retained URR carries its generation across counter-slot swaps; only Remove/Create URR ends that identity. If the session or that URR generation has already been removed or
replaced when failure arrives, those reported octets cannot be merged into a
new rule. They are logged and counted in
`upf_pfcp_undelivered_usage_octets_total`. A timeout cannot establish whether the
CP processed a report whose responses were lost; retrying its information in a
new report can therefore duplicate usage in that case. Association Update
completion never substitutes for the CP Release procedure.

Setup replacement and changed CP recovery timestamps invalidate affected session contexts immediately and reclaim their rules in maintenance batches of 64. Setup/Heartbeat responses precede deletion. Only sessions requested for retention remain active; PSREI confirms that operation. Requests for an invalidated local SEID receive Cause 65 while its detached context awaits cleanup. New establishments use the current association immediately; identifiers still held for reclamation can produce No resources available, or the restoration resource-unavailable cause for an explicit RESTI reservation. `upf_pfcp_cleanup_sessions` counts detached contexts still awaiting deletion.

`resource_reuse_delay` (default 60 seconds, range 1–86400; zero selects 60) reserves a startup restoration window. Every actual process startup holds automatic TEID and UE IPv4 allocation until that window ends; Setup and explicit RESTI reservations remain available. This implements TS 23.527 V20.0.0 clause 4.3.2 and TS 23.007 V19.2.0 clauses 16.1b/17.1b without relying on persistent container state or probabilistic random starts. For any pool size or churn, a previous instance's automatically allocated identifier cannot be automatically reused during the configured interval. After it, allocation resumes from the FIFO free chain; an unrestored old identifier may be the first allocation. The delay must cover the deployment's restoration time. It also applies to the first startup and new sessions requesting automatic resources receive Cause 75 until it expires. It does not create a further delay after that interval, reserve identifiers against a different UPF process, or add automatic IPv6 pool allocation; explicit IPv6 address/prefix reservation remains supported.

`upf_pfcp_final_usage_wait_seconds{message_type=...}` measures each response's wait from deferred-response construction until its final-usage completion signal. It excludes subsequent encoding and socket transmission.

The synthetic 125-second container run accepted 250000 requests at 2000/s across all three endpoints under 512 MiB / one CPU. It recorded no OOM kill, a 138170368-byte peak cgroup charge, a 151506944-byte sampled peak process RSS, and about 0.33 CPU for the UPF. Those are fixed-workload measurements with default map capacities and three live sessions; forwarding load and other session/rule populations require separate sizing.

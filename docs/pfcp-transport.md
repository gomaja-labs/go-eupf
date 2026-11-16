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
| `restoration_period` | `60` | Seconds after a UPF start reserved for session restoration, 0–86400. Automatic UE IPv4 allocation waits; unknown-tunnel GTP-U Error Indications are suppressed. Zero disables both holds. |

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
TestReplayOutcomeHeapProfile -count=1 -v`. The budgets do not multiply when Sxa/Sxb are enabled. The chart uses a 512 MiB memory limit and one CPU, with a 500m CPU request. The startup memory floor is `2 * replay budget + B + 32 KiB * max_sessions + 3 * (16 MiB + R) originated payloads and retained usage + 32 MiB transient headroom + H + K + W`, with `B = max(64 MiB, observed loaded cgroup charge + growing-map reserve)`. `R = max(16 MiB, 2048 * (urr_map_size + 128))` bytes reserves detached final usage per endpoint. Empty kernel metadata maps and the fixed ring contribute to `B`; their later growth is reserved separately in `K`. `max_sessions` is a process-wide admission limit shared by N4, Sxa and Sxb. Active contexts, empty contexts after rule removal, and invalidated contexts awaiting cleanup count toward it. Each slot remains reserved until both the transaction and deferred rule reclamation succeed; a failed deletion retains its slot, while a safely rolled-back establishment returns it. At the limit every new establishment receives Cause 75. A RESTI resource held by another live or retiring session returns Cause 73 with the Failed PDR ID; Cause 86 is reserved for addresses unavailable to every session. The per-session reserve rounds the measured live state to 16 KiB and reserves it twice for GC and replacement. A Linux/amd64 Go 1.27.4 synthetic Open5GS-shaped fixture (four PDRs, three FARs, two QERs and two URRs per session, each with a CP-provisioned 24-hour inactivity timer) retained 12,660 bytes/session at 8,192 sessions with real eBPF maps and their Go publication mirrors, including the URR measurement-window timestamps and excluding replay outcomes. This measurement uses two explicit garbage collections with replay outcomes cleared. These are retained Go-heap observations, not process RSS, compiler memory, or a packet-buffer budget. Different rule populations and forwarding load need separate sizing.

The chart selects 96 MiB replay, 4096 packet slots and a four-packet per-session ceiling. Its minimum floor is 475.3125 MiB before a larger measured baseline raises it. Let `P = buffer_packets`, `N = max_sessions`, `F = far_map_size` (derived as `2*N`), and `U = urr_map_size` (derived as `2*N`). All terms below are bytes:

- `H = 2*131072 + P*(2048 + 2*160) + 2*1024*N + 2*320*(2*F) + 2*4608*F`: fixed runtime, payloads/descriptors, session metadata, current/retiring FAR lifetimes, and pending notification identities, with replacement/GC headroom.
- `K = 3 MiB + 320*N + 1152*(2*F) + 4608*P`: growth of session anchors/wakeups, current/retiring FAR metadata, and cached rendered packets in the kernel. This is outside the Go soft limit.
- `W = 768*U`: additional measurement-window storage and replacement/GC headroom for URRs.

At chart defaults `H = 32 MiB`, `K = 25.8125 MiB`, and `W = 1.5 MiB`. Packet credit does not limit metadata admission; changing `buffer_per_session` leaves these metadata reserves unchanged. A Linux/amd64 Go 1.27.4 retained-heap profile with sampling rate 1 at 4096 items measured 148 bytes per packet descriptor/free index, about 894 bytes per one-FAR owner, 284 bytes per FAR in one many-FAR owner, and 4555 bytes per FAR holding all 65 notification identities. The prepared one-packet profile added 122,008 in-use bytes including probe overhead, its payload/descriptor and the deferred control, admission and rendering collections (the net MemStats retained-heap increase was 79,056 bytes); the fixed runtime term rounds this complete small shape to 128 KiB and doubles it for replacement/GC. Private initialization measured 2,269,184–2,297,856 kernel bytes at one packet, 2,248,704 at 4096 and 3,252,224 at 65536. `K` reserves a fixed 3 MiB for the programs/conduit; empty result-hash bucket growth (about 16 bytes/slot) fits the existing per-packet rounding from 4103 to 4608. An 8192-map comparison of the current URR model against the same model without its two timestamps measured 384 additional bytes per one-URR map; dense maps amortize that overhead. These are named-toolchain heap observations, not RSS or universal resource bounds.

Session anchors contain 56 value bytes, FAR-slot bindings 24 bytes, FAR lifetime/notification values 792 bytes, and wakeups four bytes. The current Linux 6.18 map-only probe created all ten `buffer_*` maps in the initial collection, then populated every hash to its configured capacity. Their summed creation deltas were 4,464,640 kernel bytes at 1,024 sessions and 12,730,368 at 65,535; population added 4,706,304 and 300,146,688 bytes. Anchor/wakeup growth was 253,952 and 15,802,368 bytes, below `320*N`; lifetime/binding growth was 4,452,352 and 284,344,320 bytes, below `1152*(2*F)`. Thus the existing rounded `K` terms still cover these measured shapes. These cgroup kernel deltas exclude unrelated maps and use synthetic keys and values; `MapInfo.Memlock` is metadata, not the measurement. The activity array reserves eight bytes per maximum session plus slot zero in the loaded baseline.

The separate rendered-result map has 32-byte keys and 2144-byte values. Its earlier 4096-entry fill increased kernel charge by 16,805,888 bytes (4103 per packet); `K` reserves 4608 per packet. After the API listener becomes ready, background initialization prepares the metadata controller and BUFF-capable entrypoint, native processing, ring admission, private rendering/TC programs, output sockets and veth. Their deferred fixed charge remains explicitly reserved in `K`. Interface edits and installation share a mutex; failed installation restores earlier links. Admission and rendering share the primary configuration map, so REST address changes reach every continuation.

A current synthetic chart fixture ran as UID 1000 with the chart capabilities, 512 MiB and one CPU, 1,024 monitored sessions, 96 MiB replay and all 4,096 packet slots full at 126 observations spanning 125.599 seconds. It accepted 250,000 FAR modifications across N4/Sxa/Sxb at nominal 2,000/s while buffered packets expired and refilled over four retention periods. The observed cgroup peak was 205,320,192 bytes; no OOM event occurred. This fixed workload does not establish a universal resource bound.

The earlier fixture used 128 MiB replay and excluded packet buffers and their new kernel maps. In that measured process, loaded charge was 54,755,328 bytes and the growing-map reserve was 24,117,248 bytes (23 MiB), yielding a 464,748,544-byte requirement (443.2 MiB) and a 424,443,904-byte Go soft limit (404.8 MiB). The process resolves its own cgroup through `/proc/self/cgroup` and `/proc/self/mountinfo`, uses the smallest visible ancestor hard limit, reads its own cgroup's charge (or the nearest charging ancestor when the controller is disabled below it), and logs the resolved path, charge source and limiting file. This works with private and host cgroup namespaces; no visible hard limit leaves refusal and automatic Go soft-limit selection disabled. A smaller `GOMEMLIMIT` is honored only if it fits replay, session, buffer, URR-window and originated reserves. Go's soft limit does not include BPF kernel memory.

For `M = pdr_map_size`, the PDR bucket array has `2*M + min(2*M, 128) + 1` slots. The two hash maps can own at most `2*M` live keys. The shared rule mutex permits one publication transaction at a time, and the existing limit of 64 PDRs per session bounds its nonempty final hash buckets to 64, including key moves. Another 64 slots allow one retired transaction batch to overlap it. Further retirement batches apply backpressure rather than reserving another copy of every configured key. Slot zero stays unused; IPv6 LPM nodes continue to use kernel RCU reclamation.

At chart capacity this is 4,225 slots instead of 8,193; standalone defaults use 262,269 instead of 524,281. The current value is 3,808 bytes, including the activity binding and key tag; 3,744 bytes described an earlier layout. Isolated cgroup kernel creation deltas for the bucket array changed from 31,203,328 to 16,097,280 bytes at chart capacity and from 1,996,464,128 to 998,723,584 at standalone capacity: observed savings of 14.41 and 951.52 MiB. Allocator and cgroup accounting round these observations; multiplying value size alone is not a kernel-memory measurement.

PDR, FAR, QER and URR slot allocation share a deadline one second after a transaction's first capacity shortage. The minimum kernel's non-expedited grace period can exceed 100 ms while making progress. Waiting uses one shared grace completion, including after callers time out; stalled readers cannot retain one barrier per rejected request. Exhaustion returns No resources available, Cause 75 (TS 29.244 V20.1.0 table 8.2.1-1), because safe publication capacity is temporarily unavailable. A recovery I/O failure remains a dataplane failure. The deadline bounds capacity waiting; scheduling, other transaction work and lock acquisition can add response delay.

The configured FAR/QER/URR array sizes already bound live plus retiring identifiers; they are not separate whole-map replacement reserves and are unchanged. Slot zero is unavailable. QER versions retain shared policer anchors until every referring version has passed grace. URR configuration remains in user space while final packet counters retain their identifiers through grace. An entirely live physical pool cannot be made available by waiting and may reject further admission or replacement. The `buffer_states` capacity of `2*F` has a different lifetime: canceled or draining cycles may still own retained packets and notification state beyond a rule grace period. It remains capped, with admission backpressure, rather than being reduced to a short transaction batch. Buffer anchors and activity slots are bounded by process-wide session admission, which includes retiring contexts and pending sampler pins.

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
limit. Callers requiring forwarding to have stopped must wait until the affected
sessions disappear from `GET /api/v1/pfcp_sessions`. The registered-port release
regression permits at most two seconds for its single-session reclamation before
testing that a subsequent packet is not delivered; that fixture bound is not a
maximum cleanup time for an arbitrarily large association. Each session that actually fails deletion starts its own three-second retry window, with
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

`restoration_period` (default 60 seconds, range 0–86400) is the time after a UPF start reserved for the SMF to restore its sessions. Set it with `UPF_RESTORATION_PERIOD` or `--restoration-period`. Only automatic UE IPv4 allocation (`feature_ueip`) waits for this period; such requests receive Cause 75 while explicit RESTI reservations remain available. Zero disables this hold and permits immediate reuse of an unrestored predecessor UE IPv4 address. During this same period, the data plane silently discards G-PDUs for unknown nonzero TEIDs instead of sending GTP-U Error Indication, and counts them in `upf_gtp_error_indications_suppressed_total` (TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1A.4 and 17.1b.1). The guard starts before XDP attachment and uses the kernel monotonic clock. It expires automatically, does not suppress Echo Responses or consume the diagnostic rate budget, and has no lookup on known-tunnel forwarding. Zero disables both restoration holds. The 60-second default is an initial deployment value: size it to exceed restart detection, association establishment and the deployment's complete proactive restoration time (TS 23.527 clause 4.3.4 NOTE 2; TS 23.007 clause 16.1A.4 NOTE 3).

Automatic TEIDs are available immediately, including on the first start. For a fixed `teid_pool` size n, b = ceil(log2(n + 1)), P = 2^(32-b) - 1 seconds, and the TEID is ((1 + (Recovery Time Stamp in Unix seconds mod P)) << b) + index, with index 1..n. Generation zero is excluded so an upgrade cannot allocate the previous release's TEIDs 1..n. The same timestamp is advertised in Setup and Heartbeat on every endpoint. Two instances with the same pool size can allocate the same automatic TEID only when their integer start seconds differ by an exact multiple of P: 65,535 seconds (18 h 12 min 15 s) for the default 65,535-entry pool, or 2,047 seconds (34 min 7 s) for the maximum 1,048,576-entry pool. This includes two starts in one second. A backward or forward clock step obeys the same modulo rule; a repeated timestamp or exact-period step can reuse a generation. This is not a persistent uniqueness guarantee, and changing pool size changes the bit partition. Explicit RESTI can reserve a predecessor TEID of any generation immediately; a TEID held by another live or retiring session returns Cause 73 with its Failed PDR ID. At session capacity every establishment returns Cause 75. Cause 86 applies only to resources no session could use, such as a restored local F-TEID address unavailable on its requested interface (TS 23.527 V20.0.0 clause 4.3.2 NOTE). A CP-provisioned UE IPv4 address has the same acceptance rules during restoration and new admission; the UPF pool bounds only automatic allocation. Only explicit reservations in the current automatic range consume free-chain indices. Within an instance, freed indices retain FIFO reuse; allocating or reserving a pool index never scans the pool. TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1b.1/17.1b.1.

`upf_pfcp_final_usage_wait_seconds{message_type=...}` measures each response's wait from deferred-response construction until its final-usage completion signal. It excludes subsequent encoding and socket transmission.

The synthetic 125-second container run accepted 250,000 requests at approximately 2,000/s across all three endpoints under 512 MiB / one CPU, with 60-second retention. It recorded no OOM kill, a 194,654,208-byte peak cgroup charge, a 163,385,344-byte sampled peak process RSS, and approximately 0.43 CPU cores charged to the cgroup. These are separate measurements, not quantities to add together. The fixture uses the chart's 1,024-session map capacities and 1,024 live sessions; other session/rule populations and forwarding load require separate sizing.


### Packet buffering runtime

One application reader consumes a bounded fixed-slot ring shared by N4, Sxa and Sxb. BAR and BUFF/NOCP admission allocate metadata independently of packet storage. XDP takes global and per-session credit only when a packet arrives. A separate durable wakeup and first-packet observation survives every storage limit and ring overflow. Session anchors share packet credit across FARs and QoS flows. BAR-associated FARs additionally share their suggested total and downlink-only bounds. Producer preparation, successful copies, ordered completion and stale-cookie rejection are tracked separately. Buffers are held in admission sequence per FAR.

A successful send is recorded before kernel acknowledgement; an acknowledgement retry does not repeat transmission. Rule mutation waits for an active renderer/send operation, and canceled lifetimes retain their reservation until producer grace, consumed/completed records, I/O completion and a successful terminal transaction result. Grace callbacks signal completion without waiting for ring consumption. Completed drain guards are removed through fresh FAR publication and another grace period.

The current renderer and AF_PACKET output use BPF test-run and `PACKET_QDISC_BYPASS` on Linux 6.18 and 5.15. Native IPv4/IPv6 inside IPv4 GTP-U is covered by focused comparisons, and the application sender has a receiver capture. Local-tunnel and kernel continuations resume the ordinary forwarding helpers. Outer Header Creation supports IPv4/UDP/GTP-U; inner IPv4 and IPv6 packets are supported. BUFF, NOCP and BAR are accepted; DDND, DLBD, UDBC and DBDM are advertised. Downlink Data Service Information includes the six-bit DSCP of the IPv4 or IPv6 packet that triggered the notification, including DSCP zero, independently of QFI availability (TS 29.244 V20.1.0 table 7.5.8.2-1). BUCP, DDDS and EDBNC are not implemented. The QER Paging Policy Indicator remains rejected. See [configuration](Configuration.md#packet-storage-settings) for limits.

Buffered output resumes the same forwarding helpers as ordinary XDP. A private
program build captures the final action without adding instructions to ordinary
FORW. Redirect and same-device TX use an AF_PACKET socket on the resolved device.
Kernel PASS uses a private veth and a TC ingress redirect to the original ingress,
preserving kernel routing, neighbour resolution, TTL, MTU and ICMP handling.
In generic XDP mode this ingress redirect runs XDP again on Linux 5.15 and 6.18.
The sender inspects the link's actual attachment mode and wraps the complete
rendered frame in a private Ethernet envelope (Local Experimental EtherType 1,
0x88b5), a magic value, the original ingress ifindex and a 64-bit process token
drawn from crypto/rand. A one-entry, frozen BPF map holds the token. The buffering
entrypoint authenticates the token, magic and ingress before any padding,
classification or traffic counting, removes the envelope and returns XDP_PASS.
Only an authenticated envelope on a configured generic-mode link is consumed. Other 88-B5 frames take the base action. Frames with the private magic but an invalid token, ingress, length or attachment mode increment the rejected-continuation counter and take the base action. Driver mode removes its existing cursor at TC. Both paths
preserve the rendered frame, ingress device, protocol and packet type.
Local tunnels re-enter the private XDP dispatcher; echo and router
control use its existing continuations. A continuation whose ingress interface has disappeared is discarded once and counted as `ingress_removed` in `upf_buffer_discarded_packets_total`; it is never retried as an output failure. DROP and ABORTED consume the retained
packet. Outer GTP-U remains IPv4; both IPv4 and IPv6 inner packets are supported.
A bounded per-packet kernel result cache prevents repeated test-run syscalls or
send retries from repeating QER/URR processing on later local legs. Successful
completion removes that cache entry with the packet's idempotent acknowledgement.
The runtime requires NET_RAW in addition to its existing BPF and network
administration capabilities. The kernel needs veth, clsact and cls_bpf support. Link ownership is registered before creation, so shutdown can remove an initialization in progress without waiting for program verification. Each private veth carries an alias identifying an abstract Unix owner socket in the same network namespace. Startup removes marked links only when that owner socket has disappeared; live owners and unmarked links are preserved.

Packet order is defined at hand-over: per FAR, every older retained packet is
handed to its continuation before a later packet can enter any output. The carrying
operation returns at hand-over. The output worker stays on one CPU to keep its
kernel-path sends on one receive backlog. Kernel queue admission is the boundary;
subsequent neighbour or qdisc delays can let a later XDP redirect overtake that
packet on the wire, as they can on the ordinary fast path. Cancellation applies
only before hand-over. See [data-plane ordering](dataplane.md#buffered-packet-hand-over).

After the API listener is ready, a background loader prepares and installs buffering
control, admission, rendering, TC/veth and output sockets. Readiness does not wait
for it. PFCP never loads or verifies a program; a BUFF request arriving during
initialization waits for the remaining work and logs its wait duration once.
Later requests use the prepared output immediately. Initialization failure is final
for the process: it is logged at error level and every later BUFF admission returns
Cause 77 (System failure), before publishing buffering state. BAR-only metadata
remains usable when its controller loaded successfully but forwarding failed.

The loader owns duplicate program and map descriptors. Shutdown cancels admission
waits and closes live resources without waiting for an in-flight verifier; a result
that finishes after cancellation is discarded without installation. The ordinary
entry retains the base forwarding path; buffering's parser, policing and storage
work uses a separately verified frame.

Buffering metrics are `upf_buffer_retained_packets` (gauge, including admitted
ring records until acknowledgement) and `upf_buffer_discarded_packets_total`
(counter with `reason` equal to `overflow`, `expiry` or `cancellation`). Overflow
covers storage admission failures, including frame/ring/credit bounds. Expiry
covers retained packets whose retention window ends. Cancellation covers
superseded admission cookies and retained packets discarded by DROP, DROBU,
rule removal, session/association cleanup, shutdown or a dropping continuation.
A successful hand-over remains a send if its acknowledgement is retried after
cancellation. Counters advance once; the gauge is sampled every 20 ms. At final
lifetime reclamation a debug log records its overflow, expiry and cancellation
totals. Labels never contain session, peer or subscriber identifiers.

### Local session release

Authenticated management DELETE `/api/v1/pfcp_sessions?id=<UP-SEID>` (or the existing subscriber selector) uses TS 29.244 V20.1.0 clause 5.18.2. A successful response contains `seid` and `epfar`; the latter identifies whether the association negotiated Enhanced PFCP Association Release. The UPF first commits the deletion transaction, stops forwarding and detaches the session from active lookup. It collects final counters after producer grace. Resource IDs and admission return only through successful reclamation. A failed deletion retains ownership and returns HTTP 503.

Non-zero final usage is reported with USAR and TEBUR; a session with no non-zero usage uses UISR. The last request carries PSDBU only when both functions negotiated EPFAR (TS 29.244 V20.1.0 table 7.5.8.1-1 and clause 6.3.5.2). An EPFAR CP treats that as deletion (clause 6.3.5.3). Final USAR/TEBUR or UISR reports are sent to every CP. Other CPs can learn that the local context no longer exists from Cause 65 on their next session request. The UPF does not wait for a Session Deletion Request. Crossing Modification or Deletion requests find no live session. The remaining delivery context is kept only through the terminal outcome of the last report: acceptance, rejection, invalid response, exhausted N1, or cancellation by association replacement/restart/release or shutdown. Failed or unacknowledged octets are logged and counted in `upf_pfcp_undelivered_usage_octets_total`.

Already admitted usage retains its original transaction until completion. Accepted earlier windows are excluded from the final report; explicitly rejected windows are merged only into the same URR lifetime. A timeout or invalid response cannot establish whether the CP processed the earlier window. During a crossing local release its unacknowledged octets are counted and logged, and are not issued again with a new UR-SEQN. Retransmissions of the original transaction retain identical bytes. Prior failure debt already restored into a live URR follows the existing ordinary-report policy described above.

Each endpoint retains at most 128 local-release contexts, additionally bounded by its originated-request count and an accounting ceiling `R = max(16 MiB, 2048 * (urr_map_size + 128))` bytes. A single session owning every configured URR fits this ceiling; smaller configurations keep the 16 MiB floor. Admission reserves 2 KiB plus 2 KiB per URR before deletion. Each session has at most one final report outstanding, with a 16,000-octet message budget. Report-context admission pressure leaves the live session intact for retry. The memory plan reserves these contexts independently of originated request payloads on N4, Sxa and Sxb. Current-CP context-not-found cleanup uses this same local-release transaction. Unrecoverable rule-journal failures still require process restart; a poisoned data plane cannot safely commit a new per-session deletion.

Enhanced PFCP Association Release is advertised as EPFAR (TS 29.244 V20.1.0 clauses 5.18.1 and 6.2.7.3.1). It is used only when the CP also advertises EPFAR. A CP's PARPS is acknowledged and stops new session admission. A local association release first sends PARPS. After its terminal response outcome, local policy proceeds with preparation even if the CP rejected it or exhausted N1; it never waits indefinitely for that request. Each session then uses the same local deletion and final-report procedure described above. URSS is sent only after all session reports reach terminal outcomes, including accounted delivery failures. The CP's Association Release Request completes the procedure; otherwise the existing T1/N1 window plus the exactly encoded release period bounds the final wait. Heartbeat failure cannot bypass preparation.

An early CP Association Release is accepted and starts asynchronous reclamation. Reports that can no longer be delivered are canceled and their outstanding octets counted. The API/session reclamation bound in the synthetic release fixture applies before testing absence of forwarding, including EPFAR. Shutdown uses one overall T1/N1-plus-release-period bound for each enhanced association. If safe deletion has not finished by that deadline, shutdown reports failure and retains unreclaimed ownership. Non-EPFAR shutdown keeps the existing asynchronous local deletion without inventing an enhanced exchange with that CP.

`inactivity_release_timeout` is a startup setting in seconds: 0 disables local inactivity release (the default), and 1–86400 enables it. Configure it in the configuration file, with `--inactivity-release-timeout`, or through `UPF_INACTIVITY_RELEASE_TIMEOUT`; the CLI schema and Helm values expose the same setting. This is local release policy under clause 5.18.2. It is independent of the CP's session-level User Plane Inactivity Timer, which requests a UPIR report under clause 5.11.2 and leaves the session forwarding.

Both timers observe one separately allocated session activity bit. A matching received user packet sets it before FAR action or QoS, including a packet subsequently dropped. PFCP, unmatched packets, GTP control messages and authenticated buffered continuations do not refresh it. The immutable PDR image holds only the activity slot. The packet path reads the aligned eight-byte slot and stores one only when it was clear; it performs no atomic increment. The poll clears only an observed set bit, then timestamps that positive observation. An empty observation uses the time before its read, so a packet arriving during a delayed empty read cannot be overtaken by expiry. A delayed packet store can therefore extend monitoring but cannot erase newer activity with an older generation. The deletion/rollback journal returns the slot only after its referring rule images pass reclamation; a new lifetime starts clear. The mmapable array reserves eight bytes for each maximum session plus slot zero, which disables monitoring. It shares the configured process-wide session capacity across PFCP endpoints.

Each session uses observation interval `I = min(5 seconds, max(100 ms, T / 40))`, where T is the smaller nonzero local or most recently provisioned CP timer. A deadline heap visits only due sessions on a 100 ms worker tick. Two observations can contribute rounding, so algorithmic expiry delay is at most `2I + 100 ms`: 5% of the timer with a 200 ms floor and ten-second ceiling, before the worker tick and scheduler/I/O/processing/capacity delays. Expiry never advances before the inactivity period. Each batch snapshots at most 64 sessions, reads their activity outside the PFCP state lock, then checks their current lifetimes and timers under the lock. Sampler pins retain both the activity slot and session admission through any overlapping deletion and rule grace. Only one observation of a session may be pending, so an empty read cannot overtake an unapplied positive observation. Requests provisioning a timer trigger an immediate observation of that session; FAR-only changes rely on the background sweep; due observations run in the background. Disabled monitoring bypasses the sampling lock. Observed activity rounds its time upwards to the sampling instant, so detection can be late by that granularity and processing delay; it does not expire a session early. An incorrect optional timer in Session Establishment is discarded while the remaining rules are processed; an incorrect conditional timer update rejects Modification without changing live state (clause 7.6.8). A successful timer update is checked immediately after dispatch, using the latest activity bit. Reducing a timer below the elapsed inactivity sends UPIR immediately; increasing it preserves the age; zero or a null-length timer disables reporting. A sent UPIR disarms reporting until the CP updates the timer. Sampling retains the last activity at the most recently configured cadence for a later update and for local policy. A zero CP timer with no local policy stops scheduled observations. An observation that began before timer reprovisioning cannot expire that newly provisioned timer; a fresh observation checks activity received before the update. If both timers expire together, local release takes precedence and sends the terminal report. A failed modification leaves the live timer and activity binding unchanged. An activity-read or clear failure is a dataplane failure reported to the supervisor, never evidence of inactivity. Per-PDR UPINT remains rejected and UPIDP is not advertised (clause 5.11.3).

A detached release context retains its CP entity address reference until its terminal outcome. A CP entity restart invalidates delivery even while final counter grace is pending; Setup replacement and association release do the same. Reclamation still collects the final counters, then records unsent octets without sending them to the retired context. Crossing session requests from an additional admitted CP address resolve the detached SEID and receive Cause 65 with zero response SEID. Late or repeated responses to canceled reports do not restore their context or count usage again.

At standalone defaults (65,535 sessions, 128 MiB replay and 4,096 packet slots), the current runtime measured a 1,040,744,448-byte loaded charge and a 1,543,480,320-byte growing-map reserve. Including the current session, queue, buffer and URR-window terms requires 7,855,603,904 bytes (7.32 GiB). An 8 GiB container became ready with a 5,627,178,816-byte Go soft limit; 512 MiB was refused before loading maps. This startup check does not exercise 65,535 live forwarding sessions.

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
states use twice that capacity for overlapping lifetimes. At the chart sizes,
FAR/QER/URR each use 2,177 physical slots; standalone defaults each use 131,199.

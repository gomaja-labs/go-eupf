# Data-plane behaviour and validation boundaries

The accelerated path handles IP PDU sessions over IPv4/UDP/GTP-U. It validates
IPv4 IHL and total length, UDP length, GTP version/PT/message length and optional
header spans before charging a PDU. GTP extension chains are bounded to sixteen
headers. Decapsulation removes the measured span, including IPv4 options.
TS 29.281 V19.2.0 clauses 5.1 and 5.2.1 define these envelopes.

An unknown extension requiring comprehension by the recipient generates a
Supported Extension Headers Notification, with no subscriber-volume charge.
Endpoint-only comprehension requirements do not prevent an intermediate N9
UPF from forwarding the extension. Unknown extensions that an intermediate
node must remove currently take the intact kernel slow path. Extension-chain
rewriting for this last case is not implemented.

IPv4 fragments take the intact kernel slow path. IPv6 classification on N6
and inside GTP-U walks up to eight Hop-by-Hop, Routing, Destination Options,
Fragment and Authentication headers to find the final Next Header (RFC 8200
section 4, as updated by RFC 9673; Errata 5256 uses the common extension-header
length definition). ESP is an encrypted terminal protocol with no visible ports.
Incomplete headers, invalid lengths and chains exceeding eight extensions drop
before any PDR is selected. They cannot bypass a higher-precedence rule by
appearing to have no ports. Transit Hop-by-Hop options are not processed, as
permitted by RFC 9673; extension contents remain unchanged.

Non-first IPv6 fragments retain the final protocol only when the Fragment
header identifies it directly. They never match an explicit port constraint,
even `0-65535` (RFC 6733 section 4.3.1). A fragment whose next extension cannot
be located drops. Offset-one fragments drop under that same section. Atomic
and first fragments can match ports when their complete transport header is
present. No fragment reassembly is performed in XDP.
The XDP program does not reassemble fragments or process Hop-by-Hop options.
Deployment must provide the required kernel slow path; XDP_PASS alone does
not establish successful reassembly or GTP processing. See RFC 791 section 3.2
and RFC 8200 section 4, updated by RFC 9673.

A valid GTP Echo Request with S=1 receives a fresh Echo Response containing its
sequence number and mandatory Recovery=0, independent of request IEs and
Ethernet padding (TS 29.281 V19.2.0 clauses 7.2.2 and 8.2). Unknown nonzero
TEIDs receive Error Indication with the triggering TEID and destination address
after the startup `restoration_period`; suppressed indications are counted in
`upf_gtp_error_indications_suppressed_total` (TS 23.527 V20.0.0 clause 4.3.2);
zero TEIDs are silently discarded (clause 7.3.1). Diagnostic replies target UDP
2152; Echo Response returns to the request source port (clauses 4.4.2.2, 4.4.2.4
and 4.4.2.5). Error Indications and Supported
Extension Headers Notifications share a global 100 responses/second budget to
bound reflection. Echo Responses are not policed by this budget.

Received End Markers for unknown contexts are consumed. An intermediate UPF
selects a known End Marker by ingress interface and, when present, QFI, then forwards it
through that PDR's FAR without applying QER gates/rates or charging URRs; a terminal UPF consumes it (clause 7.3.2). Ordinary End Markers on control-plane tunnel switches are generated after the
rule grace period; see [transmission limits](rule-capabilities.md#end-marker-transmission).
A container-less ordinary marker uses the first PDR matching the ingress
interface, even when the PDRs have QFI lists; a present unmatched QFI is dropped.
Exactly one frame leaves per received marker (TS 29.281 V19.2.0 clauses 5.2.2.7
and 7.3.2.1; TS 29.244 V20.1.0 clause 5.17.3).
Inter-system forwarding adds the PDR QER's QFI or removes the PDU Session
Container as the PDR requests (TS 29.244 V20.1.0 clause 5.17.3). N19 and N19mb
suppress markers. Propagation of received Error Indications to the control
plane remains required integration work.

URR counters and QER rates use the validated IP PDU length, including its IP
header and excluding GTP optional headers, outer IP/UDP headers, Ethernet and
padding. Volume is counted after QER gate and bitrate enforcement (TS 29.244
V20.1.0 clause 5.2.2.2.1). Kernel increments are atomic across CPUs. Updating a
URR configuration preserves live counters. Session transactions serialize control-plane journals without touching a shared
packet-admission counter. Dependencies are written before a PDR's complete
replacement bucket is published; obsolete keys are removed afterwards. TEID and
IPv4 hash entries contain one aligned array-slot index, updated in place with
BPF_F_LOCK. XDP loads it once and checks the array bucket's key and map kind.
A recycled hash element triggers one retry; a remaining mismatch is unmatched
and never generates an Error Indication (TS 29.281 V19.2.0 clause 7.3.1).
Bucket slots stay reserved until the batched grace completes, including rollback.
The shared array has four times the configured per-map PDR capacity plus reserved
slot zero; exhaustion waits for queued retirement before reporting capacity.
IPv6 remains an LPM trie with deferred frees: Linux v5.15
`kernel/bpf/lpm_trie.c:381` uses `kfree_rcu`; v6.18 `:451` uses
`bpf_mem_cache_free_rcu`. These lifetimes differ from hash element recycling
since Linux 6.1. Old
FAR/QER updates reserve and write fresh configuration slots, then rebind all
referencing PDRs, including unchanged PDRs and generated-reply bindings. Old
versions remain reserved until the batched kernel RCU grace period completes
(TS 29.244 V20.1.0 clauses 5.2.3 and 6.3.3.3). A packet therefore reads one
complete old or new configuration. QER versions share atomic policer timestamps
in the initial QER slot: the anchor remains reserved across configuration
updates and is released only after logical QER removal and its final grace.
No userspace snapshot copies live metering state. The current rate applies to
the continuing virtual-time credit (clause 5.4.4); an update does not reset credit.
URR configuration is control-plane-only, so Update URR never overwrites live
counter slots and cannot tear their configuration.
URR detachment waits for old invocations before reading final usage and clearing
its slot. A dummy map-in-map update invokes the kernel's BPF synchronization;
there are no packet-path instructions for this synchronization. Native and
generic XDP, test runs and tail calls remain inside the kernel RCU reader.
Local-tunnel recursion and Router Advertisement continuation use tail calls.
Failed rollback restoration and reclamation retry with bounded exponential
backoff for three seconds. Affected slots remain reserved. Exhaustion notifies
the supervisor and exits non-zero; restored rollback state reopens admission.

PFCP responses wait asynchronously only when they need final URR usage. Removed
URRs are reported in the Modification Response (TS 29.244 V20.1.0 clause
5.2.2.3.1); Deletion includes every final URR report without depending on ARDR.
No connection or journal lock crosses that wait. Work queued before a grace
period starts shares that period; detachment arriving during a period uses the
next batch. Unrelated requests continue and retransmissions of a waiting request
are not executed again. FAR/QER slots, retired counter slots, lookup keys, TEIDs
and UE leases remain unavailable for reuse until reclamation completes.

Every bound QER applies in received binding order, up to four per PDR
(TS 29.244 V20.1.0 clause 5.4.4). Each gate and bitrate is enforced; a later
rejection may already have consumed an earlier QER's reservation. The first
QER with a QFI IE supplies QFI/RQI marking, including QFI zero. The first
nonzero QER DSCP in binding order applies, otherwise the FAR marking applies. QFI/RQI is emitted in a PDU Session Container only
for a 5GS session. RQI without QFI is rejected.

The QER policer uses ceiling transmission time in nanoseconds, a shared atomic
reservation and a 5 ms burst window. A PDU larger than that window is admitted
once and pays its complete transmission interval. Rate zero means unlimited.
Contention is retried four times, then fails closed. This policy bounds rate;
it does not guarantee fairness or minimum throughput under contention.

FIB forwarding decrements the routed IPv4 TTL or IPv6 Hop Limit once, only on
a successful redirect. Downlink forwarding also decrements the inner lifetime
before encapsulation; locally generated packets retain their original lifetime. Exhausted packets and MTU/neighbor failures go to the kernel unchanged
at that forwarding stage, for the applicable ICMP or resolution processing
(RFC 1812 section 5.3.1; RFC 8200 sections 3 and 5). Kernel ICMP delivery requires
appropriate routes and tunnel configuration. IPv6 Traffic Class rewrites preserve
the complete Flow Label. IPv4 address rewrites checksum the complete IHL span.

Router Solicitations are checked for Hop Limit, code, checksum, length and option
validity (RFC 4861 section 6.1.1). The bounded responder handles ICMP payloads up
to 256 bytes; larger solicitations go to the kernel. Advertisements use the
solicitor's address, or ff02::1 for an unspecified source, with link-local source
and Hop Limit 255 (sections 4.2 and 6.2.6). Router Lifetime 64800 is permitted by
RFC 8319 section 4. The control plane binds each uplink PDR to the session's
highest-precedence IPv6 downlink PDR, using the lowest PDR ID to break ties.
Generated replies use that FAR and QER list, including link-local and multicast
destinations. Without a downlink binding the reply is dropped. Generated router
control traffic does not increment user-plane URRs.

Each local TEID or N6 UE IPv4/IPv6 prefix maps to one session and an ordered list
of independently replaceable PDRs (TS 29.244 V20.1.0 clauses 5.2.1, 5.2.1A and
8.2.11). Lower numeric Precedence wins; PDR ID breaks equal precedence. Source
Interface, UE address constraint, QFI and SDF tuple constraints are conjunctive.
Repeated SDF filters and repeated QFIs are alternatives within their own field.
Access PDRs reverse the CP description's addresses and ports (clause 5.2.1A.2A).
`assigned` resolves against the session's IPv4 address and/or IPv6 prefix.
An unavailable address family never widens the match. Flow Descriptions use
TS 29.212 V20.0.0 clause 5.4.2: `permit out`, decimal protocol (0-255) or
`ip`, source address/prefix or `any`, destination address/prefix or `assigned`,
and optional single ports or ranges. Names resolve to protocol numbers through
`/etc/protocols` (RFC 6733 section 4.3.1). Options, `deny`, direction `in`,
negation, lists, unknown protocol names and other departures are semantically
incorrect. Their optional SDF Filter is logged and ignored under TS 29.244
V20.1.0 clause 7.6.8; each increments `upf_ignored_sdf_filters_total` with
session/PDR context in the log. If all are ignored the PDR is unfiltered.
Explicit ports require actual TCP, UDP or SCTP ports in the packet; a port
predicate on another protocol matches no packet.
A known key with no matching PDR drops. Unowned N6 destinations, non-IP traffic,
and explicitly documented kernel slow paths retain XDP_PASS; an unknown GTP
TEID follows the Error Indication procedure above. IPv6 prefixes use an LPM
trie. Overlapping prefixes owned by different sessions are rejected. Distinct
overlapping prefixes within one session are currently rejected as unsupported,
since a longest-prefix lookup cannot preserve precedence across both lists.
Identical prefixes can hold the ordinary independent PDR list.

Fixed bounds are four PDRs per key, five SDF filters, eight QFIs, four QERs and
three URRs per PDR, and 64 rules of each type per session.
Ownership, key/prefix intersections and key capacity are checked against the
final draft before slot reservation or map writes. Map capacities are
configured separately and array slot zero is reserved. Capacity failures return
No resources available; unsupported standard rule fields return Service not
supported, with Failed Rule ID and Offending IE where applicable. No list is
silently truncated. Diagnostic PDR GETs return a session ID and ordered rules;
direct REST map PUT routes are absent. Session displays show logical per-session
rule IDs, keeping internal array slots separate.

The URR subset measures volume after QoS, requires a positive total-volume
threshold for VOLTH, and sends final reports on URR removal/session deletion. Duration,
event, packet, quota, periodic, linked, application and other unimplemented
measurement controls are rejected. Below-threshold octets remain unreported
until a report is triggered; the threshold is disarmed after a report until
updated. Removing the last PDR association reports non-null usage and retains a reset
URR. Reattaching a PDR resumes measurement from zero. Sequence numbers start
at zero independently for each URR. Reports
include total, uplink and downlink octets; packet timestamps are omitted because
they are not measured. No end-marker emission, buffering, application detection,
IPv6 outer tunnel or IPv6 UE address allocation capability is advertised.
Explicit IPv6 prefix ownership includes uplink-only PDIs. Both concurrently
chosen resources appear in Created PDR; allocations through Update PDR use
Updated PDR.

PFCP mutations validate into a private session and resource view, reserve every
new slot, write dependencies, publish final PDR buckets, detach obsolete
references, and retire unreachable slots. The journal records actual map
publications. Rollback restores previous bindings and detached counter values,
then retires newly allocated slots after old invocations return. New FAR/QER
configurations are initialized exactly once in fresh reserved slots. Undo never
overwrites a version that a packet may still hold; rollback clears all new
versions after the grace and before releasing any of their IDs. A cleanup retry
therefore cannot clear a reused ID. Failed allocations are quarantined until
that retirement, avoiding late callbacks freeing a reused slot. Live URR configuration updates preserve counters throughout.
The existing PFCP state lock serializes session mutations,
association cleanup and snapshots; diagnostic map readers also exclude the
journal. Local SEIDs are allocated by the shared resource manager across N4/Sxa/Sxb
and never wrap. A shared reservation lock serializes reservation journals
across these endpoints, after the connection state lock and before the map
journal lock. Local SEIDs are UPF-wide. TEIDs and UE IP leases use that same local
identity, including explicit reservations, shared CHOOSE IDs and last-reference
release. Pools are limited to 1,048,576 entries; UE allocation is IPv4 only.
Each request records only its own reservations and active references. Indexed
FIFO free pools, per-session ownership lists and IPv6 prefix tries avoid pool
scans. Lease generations prevent a late reclamation callback from freeing a
new reservation. Rule-plan preflight and detachment use a published-key index
and touch only the requesting session keys. The same journal owns immutable
slices of published PDR entries in Go, one per live key, restored together with
kernel bindings on rollback. Drafts copy those slices before editing. Buckets
with packet-mutated notification flags are read from the kernel when preparing
their undo image; other configurations need no large bucket read. These unpinned
maps start empty and have no independent writers; diagnostics still read the
kernel map. Unchanged PDR buckets are not
republished.

Session Establishment Recovery Time Stamps are associated with CP F-SEID IP,
compared with previous values, and stale requests are discarded (TS 23.007
V19.2.0 clause 19A). A newer timestamp removes that entity's existing sessions
through the same journal. Cleanup failure retains ownership for retry. Setup
timestamps remain ignored. Recovery history is bounded to 1024 entities per
association; a new entity beyond the bound is rejected. RESTI accepts available
explicit resources return restoration failure Cause 86 only when their local F-TEID address is unavailable on the requested interface or their UPF-allocated IPv4 UE address is outside the configured allocation range; an occupied resource returns Cause 73 with its Failed PDR ID, and session capacity always returns Cause 75
(TS 29.244 V20.1.0 Table 7.5.2.1-1 note 4). Other unimplemented restoration or
charging flags are rejected. Native N6 PDIs support Core ingress and destination UE-IP lookup. Native
source-address lookup, Access ingress without F-TEID, and forwarding without a
return tunnel are rejected. GTP forwarding requires an Outer Header Removal IE.
Core-side GTP ingress requires distinct N3 and N9 addresses; shared addresses
cannot distinguish this match field. Only IPv4/UDP/GTP-U outer creation is
supported. Spare bits are ignored; named unsupported controls are rejected.

EPC and 5GC always advertise FTUP and allocate F-TEIDs in the UP function
(clause 5.5.1). A new CP-allocated F-TEID receives Cause 71 unless RESTI permits
restoration. There is no FTUP configuration mode.

Network Instance names admitted by `allow_apn` and `deny_apn` are aliases of the same
kernel routing domain. A name denied by the configured admission policy is rejected with Cause 73,
Failed Rule ID and Offending IE 22. Empty allow and deny policies admit any name. No network-instance isolation is provided. See the
[IE capability and bound audit](rule-capabilities.md).

Map capacities are configured before Load. Live resizing returns an error
without changing handles, instructions or data. All map buffers use bpf2go
value types and typed map calls so the library checks their size; REST DTOs are
converted explicitly. Notification delivery uses a bounded queue and drops events
when the receiver is slow; it does not block packet-reader shutdown. Forwarding
consults the kernel FIB for every packet, so route, neighbour and MTU changes
take effect immediately.

Tests enter private network and mount namespaces and create their own permanent
neighbors. Run them inside the privileged development image with iproute2,
unshare and the required BPF privileges. The program-load tests exercise the running kernel;
the minimum also has a separate KVM boot and packet-test script. See
[minimum-kernel validation](minimum-kernel.md) for inputs and commands. An
individual host-kernel run does not establish minimum-kernel support.

Packets on a CP-function local TEID use the CP-side ingress context (TS 29.244
V20.1.0 clause 5.3.1). CP-originated downlink uses DL gates/rates/accounting and
is re-encapsulated with the destination tunnel's QFI. UP-to-CP FARs use ordinary
GTP-U forwarding. CP tunnels use the configured IPv4 N3 endpoint. CHOOSE offers
of both V4 and V6 allocate IPv4 on the current IPv4-only tunnel interfaces;
IPv6-only offers reject with Cause 76. User-plane IPv6 payloads are supported
independently of the outer tunnel family.


CP-function packets use the Source Interface and retained FAR Destination
Interface to choose UL versus DL, consistently for QoS, usage and SDF endpoint
orientation (TS 29.244 V20.1.0 clause 5.4.4). UE-to-CP and CP-to-DN are UL;
CP-to-UE and DN-to-CP are DL. N4-u shares the configured N3 IPv4 endpoint.
See `rule-capabilities.md` for the clause 5.3.1 scenario matrix and limits.

Outgoing GTP-U tunnels use UDP destination port 2152 and a stable dynamic source
port `49152 | (TEID & 16383)`, for native encapsulation and GTP relay. Generated
End Markers use that same old-tunnel source port. This provides per-tunnel
transport load distribution without retaining arbitrary ingress source ports
(TS 29.281 V19.2.0 clauses 4.4.2.0 and 4.4.2.6). Echo and diagnostic reply
port handling is unchanged.

## Buffered packet hand-over

A BUFF-to-FORW transition retains a BUFF-class release version while packets are
pending. Every retained packet of a FAR is handed to its continuation in arrival
order before a later packet of that FAR can enter any output. Hand-over completes
when the carrying operation returns: an AF_PACKET send, a kernel-path send, local
re-entry, or drop. One output worker is pinned to one CPU, keeping successive
kernel-path sends on the same receive backlog. Once retained work completes,
the rule journal publishes ordinary FORW and reclaims the release version after
producer grace. Plain FORW uses the base 16-byte FAR and performs no buffering
identity or guard lookup.

Hand-over order does not imply wire order between different continuations. A
packet passed to Linux can wait for neighbour resolution or an output qdisc;
XDP_REDIRECT bypasses those queues, allowing a later redirected packet to appear
first. This is also ordinary forwarding behavior. Packets taking one continuation
retain FIFO hand-over; attached-XDP tests check wire FIFO within one continuation
and exactly-once delivery across mixed continuations. DROP, DROBU, FAR or BAR
removal and deletion cancel only packets not yet handed over. Once the kernel has
accepted a packet, its later transmission or drop is outside the UPF's control.
The resumed first leg retains its prior policing and accounting, as required by
TS 29.244 V20.1.0 clause 5.2.4.2.

Session-level PFCPSMReq-Flags DROBU is accepted in Session Modification Requests:
it discards every packet still retained for the session before applying the
request's FAR changes. BUFF|NOCP afterwards starts a fresh first-packet report
period (TS 29.244 V20.1.0 clauses 5.2.4.3 and 8.2.31).

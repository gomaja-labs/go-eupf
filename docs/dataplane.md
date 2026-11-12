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

IPv4 fragments and inner IPv6 extension/fragment headers take the intact kernel
slow path. Direct IPv6 packets with extension headers also go to the kernel.
The XDP program does not reassemble fragments or process Hop-by-Hop options.
Deployment must provide the required kernel slow path; XDP_PASS alone does
not establish successful reassembly or GTP processing. See RFC 791 section 3.2
and RFC 8200 section 4, updated by RFC 9673.

A valid GTP Echo Request with S=1 receives a fresh Echo Response containing its
sequence number and mandatory Recovery=0, independent of request IEs and
Ethernet padding (TS 29.281 V19.2.0 clauses 7.2.2 and 8.2). Unknown nonzero
TEIDs receive Error Indication with the triggering TEID and destination address;
zero TEIDs are silently discarded (clause 7.3.1). Diagnostic replies target UDP
2152; Echo Response returns to the request source port (clauses 4.4.2.2, 4.4.2.4
and 4.4.2.5). Error Indications and Supported
Extension Headers Notifications share a global 100 responses/second budget to
bound reflection. Echo Responses are not policed by this budget.

Received End Markers for unknown contexts are consumed. An intermediate UPF
forwards a known End Marker through the default FAR, without applying QERs or
charging URRs; a terminal UPF consumes it (clause 7.3.2). Generating End Markers
on control-plane tunnel switches, selecting a QoS-specific forwarding context,
and propagating received Error Indications to the control plane remain required
integration work.

URR counters and QER rates use the validated IP PDU length, including its IP
header and excluding GTP optional headers, outer IP/UDP headers, Ethernet and
padding. Volume is counted after gate and bitrate enforcement (TS 29.244
V20.1.0 clause 5.2.2.2.1). Kernel increments are atomic across CPUs. Updating a
URR configuration preserves live counters. Session transactions close a shared
admission gate and wait for admitted XDP invocations to finish. They detach all
references before reading final URR counters, clear the slot, then release its
ID after commit. Tail calls release admission before the next invocation.
A closed gate drops known user-plane traffic during the transaction; it does
not buffer it. Control traffic and unowned N6 destinations retain their ordinary
paths. This is a whole-UPF pause, bounded to a one-second drain wait, rather
than a per-session concurrency guarantee. A failed rollback leaves admission
closed and rejects further transactions until restart.

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
The unresolved `assigned` address token and unsupported protocol numbers return
Service not supported, rather than widening a match.
A known key with no matching PDR drops. Unowned N6 destinations, non-IP traffic,
and explicitly documented kernel slow paths retain XDP_PASS; an unknown GTP
TEID follows the Error Indication procedure above. IPv6 prefixes use an LPM
trie. Overlapping prefixes owned by different sessions are rejected. Distinct
overlapping prefixes within one session are currently rejected as unsupported,
since a longest-prefix lookup cannot preserve precedence across both lists.
Identical prefixes can hold the ordinary independent PDR list.

Fixed bounds are four PDRs per key, two SDF filters, eight QFIs, four QERs and
three URRs per PDR, and 64 rules of each type per session. Map capacities are
configured separately and array slot zero is reserved. Capacity failures return
No resources available; unsupported standard rule fields return Service not
supported, with Failed Rule ID and Offending IE where applicable. No list is
silently truncated. Diagnostic PDR GETs return a session ID and ordered rules;
direct REST map PUTs return 405. Session displays show logical per-session
rule IDs, keeping internal array slots separate.

The URR subset measures volume after QoS, supports a positive total-volume
threshold, and sends final reports on URR removal/session deletion. Duration,
event, packet, quota, periodic, linked, application and other unimplemented
measurement controls are rejected. Below-threshold octets remain unreported
until a report is triggered; the threshold is disarmed after a report until
updated. Sequence numbers start at zero independently for each URR. Reports
include total, uplink and downlink octets; packet timestamps are omitted because
they are not measured. No end-marker emission, buffering, application detection,
IPv6 outer tunnel or IPv6 UE address allocation capability is advertised.
Explicit IPv6 prefix ownership includes uplink-only PDIs. Both concurrently
chosen resources appear in Created PDR; allocations through Update PDR use
Updated PDR.

PFCP mutations validate into a private session and resource view, reserve every
new slot, then journal exact previous map values while admission is closed.
Rollback restores QER policer runtime and URR counters as well as bindings and
allocator bitmaps. The existing PFCP state lock serializes session mutations,
association cleanup and snapshots; diagnostic map readers also exclude the
journal. Local SEIDs are allocated by the shared resource manager across N4/Sxa/Sxb
and never wrap. A shared reservation lock serializes private pool snapshots
across these endpoints, after the connection state lock and before the map
journal lock. Local SEIDs are UPF-wide. TEIDs and UE IP leases use that same local
identity, including explicit reservations, shared CHOOSE IDs and last-reference
release. Pools are limited to 1,048,576 entries; UE allocation is IPv4 only.
The private resource view currently copies the bounded pools on each request.

Session Establishment Recovery Time Stamps are associated with CP F-SEID IP,
compared with previous values, and stale requests are discarded (TS 23.007
V19.2.0 clause 19A). A newer timestamp removes that entity's existing sessions
through the same journal. Cleanup failure retains ownership for retry. Setup
timestamps remain ignored. Recovery history is bounded to 1024 entities per
association; a new entity beyond the bound is rejected. RESTI accepts available
explicit resources and occupied resources return restoration failure Cause 86
(TS 29.244 V20.1.0 Table 7.5.2.1-1 note 4). Other unimplemented restoration or
charging flags are rejected. Native N6 PDIs support Core ingress and destination UE-IP lookup. Native
source-address lookup, Access ingress without F-TEID, and forwarding without a
return tunnel are rejected. GTP forwarding requires an Outer Header Removal IE.

EPC/5GS deployments must enable FTUP; CP allocation
mode remains available in configuration and does not satisfy clause 5.5.1.

Map capacities are configured before Load. Live resizing returns an error
without changing handles, instructions or data. All map buffers use bpf2go
value types and typed map calls so the library checks their size; REST DTOs are
converted explicitly. Notification delivery uses a bounded queue and drops events
when the receiver is slow; it does not block packet-reader shutdown. Forwarding
consults the kernel FIB for every packet, so route, neighbour and MTU changes
take effect immediately.

Tests enter private network and mount namespaces and create their own permanent
neighbors. Run them inside the privileged development image, or with
`go test -exec sudo ./cmd/ebpf/` on a Linux host with iproute2, unshare and the
required BPF privileges. The program-load tests exercise the running kernel;
they do not establish support on an unavailable minimum kernel. The README
names Linux 5.15.0-25-generic as its minimum tested version.

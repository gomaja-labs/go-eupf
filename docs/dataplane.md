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
URR configuration preserves live counters. Callers must remove references and
quiesce traffic before deleting/reusing a URR; deletion is not an atomic
snapshot of an active counter.

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
RFC 8319 section 4. A production return-tunnel binding to the originating session
is still needed: the current downlink lookup uses the response destination and
cannot infer the session from a link-local or multicast destination.

PDR identity, precedence and conjunctive PDI matching remain incomplete. The
current map representation cannot maintain independently replaceable/deletable
ordered PDRs sharing a key (TS 29.244 V20.1.0 clauses 5.2.1 and 8.2.11). UE IP,
Source Interface and QFI constraints need coordinated control-plane and map
changes. Do not treat successful SDF tuple matching as full PDI compliance.

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

# Deferred requests

These requests describe work beyond this release. They are design inputs, not
commitments or delivery dates. The linked upstream issues supply the requested
behaviour; the source links identify the current implementation and likely
change locations. The deployment experiments below have not been established
by the repository's unit tests or PFCP smoke tests.

## Multiple N3 endpoints and subscriber-group selection

[Upstream #663](https://github.com/edgecomllc/eupf/issues/663) requests an N3
receive-address set and selection of an advertised N3 endpoint by UE IPv4
prefix, optionally DNN, for multi-port load sharing. It proposes separate
receive and advertisement controls. This release has one local N3 and one N9
address in `dataplane_config`, with global advertised-address selection rather
than a subscriber-group endpoint table. The single-address advertisement use
case from #628 is covered by [advertised addresses](advertised-addresses.md).

Implementation would require a validated endpoint model, deterministic prefix
and overlap rules, a fallback, selection when a UE address is not yet known,
and a defined policy for existing sessions when mappings change. Update
[`cmd/config/config.go`](../cmd/config/config.go),
[`cmd/ebpf/xdp/n3n6_entrypoint.c`](../cmd/ebpf/xdp/n3n6_entrypoint.c),
[`cmd/core/pfcp_session_handlers.go`](../cmd/core/pfcp_session_handlers.go) and
[`cmd/core/pdr.go`](../cmd/core/pdr.go), including response selection and
local-tunnel validation. Test both receive and advertised paths, concurrent
updates and return routing. TS 29.244 V20.1.0 clause 5.5.3 and clause 8.2.3
govern allocated F-TEIDs; TS 29.281 V19.2.0 clauses 3.1 and 4.2.1 cover tunnel endpoint
identification. A prefix policy must preserve those endpoint identities.

## XDP receive-side scaling with CPUMAP

[Upstream #616](https://github.com/edgecomllc/eupf/issues/616) requests software
RSS for NICs that cannot distribute GTP-U by TEID: one CPU set receives and
hashes packets, another processes them through CPUMAP. The current
[`XDP entrypoint`](../cmd/ebpf/xdp/n3n6_entrypoint.c) has no CPUMAP dispatch
stage or CPU-set configuration, so this is not a supported release setting.

A design needs bounded CPU-set validation, a stable tunnel hash, queue sizing,
CPU hotplug handling, overload/drop counters, and a second-stage program that
preserves packet metadata and transaction admission. Changes would span the
XDP entrypoint, [`cmd/ebpf/objects.go`](../cmd/ebpf/objects.go), startup and
configuration. Validate ordering, overload, counters and fairness under
multi-queue load on real NICs; compare with hardware RSS and record CPU use,
loss and latency. TS 29.281 V19.2.0 clauses 4.2.1 and 4.3.1 provide tunnel and
ordering context; they do not prescribe Linux CPU placement or CPUMAP.

## Embedded UE address translation

[Upstream #137](https://github.com/edgecomllc/eupf/issues/137) asks for UE IP
NAT; its issue body gives no further requirements. This release routes UE
traffic and uses external NAT where needed, as described in the
[deployment index](deployments/README.md); the
[Open5GS compose example](deployments/open5gs-compose/docker-compose.yaml)
contains an external masquerade rule. Advertising an address does not provide
UE NAT.

Before implementation, define address-only versus port translation, supported
protocols, mapping/filtering policy, timeouts, fragments, ICMP translation,
resource ceilings, session deletion and observability. A possible design uses
bounded forward/reverse flow maps in the XDP path and reconciles their lifetime
with [`session state`](../cmd/core/session.go), configuration and restart
handling. It needs checksum, reverse-path, collision and exhaustion captures,
not just map tests. TS 29.244 V20.1.0 clause 5.4.8 describes traffic steering
to service functions including NAT; it does not specify a complete embedded
NAT implementation. Translation-specific standards and their current status
must be selected once the NAT scope is defined.

## Application filtering and PFD management

[Upstream #136](https://github.com/edgecomllc/eupf/issues/136) asks for
application filtering using PFDs; its body is empty. The release's
[`rule capability checks`](../cmd/core/rule_capability.go) reject unsupported
Application ID matching. Predefined SDF filters are not a node-wide PFD store
or a complete application detector.

Implementation needs node-level PFD Management Request/Response handling in
[`cmd/core/pfcp_connection.go`](../cmd/core/pfcp_connection.go), a bounded store
shared across sessions and controlling CPs, Application ID matching in the
rule model and XDP path, and a declared supported subset of PFD Contents.
Define replacement/deletion, rollback, association interactions and application
start/stop reporting before advertising support. TS 29.244 V20.1.0 clause
6.2.5 makes PFD management optional and defines its node-wide scope and atomic
failure behaviour; Tables 7.4.3.1-1 through 7.4.3.1-3 and 7.4.3.2-1 define the
messages. Clause 8.2.6 defines Application ID and clause 8.2.39 defines PFD
Contents. Partial acceptance requires an explicit PAPFD design (clause 5.42),
not unconditional success for unimplemented content.

## eBPF CNI deployment validation

[Upstream #496](https://github.com/edgecomllc/eupf/issues/496) asks to deploy
with an eBPF CNI (Cilium or Calico), run the zero scenario in generic and native
XDP modes, and measure performance. This is deferred deployment validation;
the [existing deployment examples](deployments/README.md) do not establish
that matrix.

Create version-pinned CNI/core/RAN manifests under `docs/deployments`, establish
which program owns each hook, and test attachment, routing, policy and cleanup
without replacing the CNI's program. Exercise both attach modes using
[`BindDataPlaneInterfaces`](../cmd/core/config_edit.go) and publish topology,
kernel/NIC/CNI versions, packet captures and repeatable performance commands.
This is a Linux/CNI integration requirement, not a new PFCP procedure. GTP-U
packet validity still follows TS 29.281 V19.2.0 clause 5.1.

## OMEC gNBSim scale scenarios

[Upstream #474](https://github.com/edgecomllc/eupf/issues/474) asks for
Open5GS/eUPF/gNBSim deployment and data tests with one gNB plus 100 UEs, then
ten gNBs sharing an IP with distinct ports plus 100 UEs, with documented
results. Those named scenarios are not established by this release's smoke
tests; the issue checklist leaves the traffic tests and result documentation
unfinished.

Add a pinned lab under `docs/deployments` and a repeatable harness alongside
[`scripts/enb-load-test`](../scripts/enb-load-test). Separate registration,
session-establishment success, forwarding and sustained throughput results;
collect PFCP/GTP-U captures and resource measurements. Distinct ports on a
shared gNB IP must not collapse tunnel identity. TS 29.281 V19.2.0 clauses 3.1 and 4.2.1
and TS 29.244 V20.1.0 clause 5.6.2 provide tunnel/session identity checks.
These tests would not by themselves establish commercial capacity.

## One UE and three gNBs with UERANSIM

[Upstream #472](https://github.com/edgecomllc/eupf/issues/472) asks whether one
UE can connect to multiple gNBs, for a deployment if possible, and for research
into simulated RSSI changes. Its comment mentions `gnbSearchList` and distinct
gNB IDs; neither proves simultaneous connectivity or handover support.
The simulator capability and intended mobility procedure remain unspecified,
so the scenario is not a release guarantee.

First distinguish cell search, handover and simultaneous connectivity, verify
the chosen UERANSIM version's capabilities, then add a pinned lab under
`docs/deployments` and assertions in `pytest` or `robot`. Capture control-plane
tunnel changes and GTP-U continuity, loss and End Marker handling; relevant
UPF code is [`pfcp_session_handlers.go`](../cmd/core/pfcp_session_handlers.go)
and the [XDP entrypoint](../cmd/ebpf/xdp/n3n6_entrypoint.c).
TS 29.244 V20.1.0 clause 5.6.3 governs rule modification; TS 29.281 V19.2.0
clause 7.3.2 governs End Markers. These are UPF checks, not a specification of
radio mobility or simulated RSSI. Select current radio/core procedure documents
after defining the lab's mobility scenario.

## Managed Kubernetes routing without BGP

[Upstream #427](https://github.com/edgecomllc/eupf/issues/427) asks for automatic
UE routes after deployment, no BGP and no /32 routing masks on managed
Kubernetes. The [deployment examples](deployments/README.md) include BGP-based
setups; this release does not ship a general managed-cluster route controller.
The correct routing mechanism depends on the provider and CNI.

Choose a supported provider/CNI combination, decide between provider routes,
a tunnel or a gateway, and design prefix ownership, overlap rejection,
permissions, readiness, failover and route removal. Add manifests and lifecycle
checks under `.deploy/helm/eupf`, `docs/deployments` and `scripts`; test return
traffic, pod rescheduling and stale-route cleanup. Keep deployment routing
separate from PFCP session admission. TS 29.244 V20.1.0 clause 5.2.1 describes
packet detection and forwarding rules; it does not require BGP or define a
Kubernetes route controller. Prefix aggregation needs deployment evidence that
the entire prefix has the same reachable UPF next hop.

# Rule capability audit

This table covers every direct child IE in the Create/Update PDR, PDI, FAR,
Forwarding Parameters, QER, URR and BAR tables of **TS 29.244 V20.1.0**.
Each source cell names the actual table. An implemented group supports only its
listed children. A rejected grouped feature includes its nested children.
Unknown/unexpected IEs and excess singular occurrences are ignored under
clauses 7.6.9–7.6.10. Semantically invalid optional SDF Filters are logged and
ignored under clause 7.6.8. Flow Description uses the restricted grammar of
TS 29.212 V20.0.0 clause 5.4.2, as required by TS 29.244 clause 8.2.5.

Rejections normally use Cause 76 (Service not supported), Failed Rule ID and
Offending IE. Capacity exhaustion uses Cause 75 (No resources available) and
Failed Rule ID. Invalid new CP F-TEID allocation uses Cause 71. Missing/invalid
mandatory fields retain the procedural causes specified in clauses 7.5–7.6.
BUFF/NOCP, BAR provisioning and buffering controls stay rejected until buffering
is implemented. These tables do not claim compatibility with every SMF feature.

## PDR

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| PDR ID | Implemented | Session-local identity. | 7.5.2.2-1, 7.5.4.2-1 |
| Precedence | Implemented | Lower numeric value wins. | 7.5.2.2-1, 7.5.4.2-1 |
| PDI | Implemented | Complete replacement when supplied in Update PDR. | 7.5.2.2-1, 7.5.4.2-1 |
| Outer Header Removal | Implemented | IPv4/UDP/GTP-U or GTP-U/UDP/IP removal only. | 7.5.2.2-1, 7.5.4.2-1 |
| FAR ID | Implemented | Session-local forwarding binding. | 7.5.2.2-1, 7.5.4.2-1 |
| URR ID | Implemented | Up to three session-local usage bindings. | 7.5.2.2-1, 7.5.4.2-1 |
| QER ID | Implemented | Up to four session-local QoS bindings. | 7.5.2.2-1, 7.5.4.2-1 |
| Activate Predefined Rules | Rejected | No predefined packet-processing rules are installed. | 7.5.2.2-1, 7.5.4.2-1 |
| Activation Time | Rejected | Deferred rule activation is not advertised or scheduled. | 7.5.2.2-1, 7.5.4.2-1 |
| Deactivation Time | Rejected | Deferred rule deactivation is not advertised or scheduled. | 7.5.2.2-1, 7.5.4.2-1 |
| MAR ID | Rejected | ATSSS/multi-access scheduling is not implemented. | 7.5.2.2-1 |
| Packet Replication and Detection Carry-On Information | Rejected | Cross-session replication and continued PDR lookup are not implemented. | 7.5.2.2-1 |
| IP Multicast Addressing Info | Rejected | Multicast membership and multicast PDR selection are not implemented. | 7.5.2.2-1, 7.5.4.2-1 |
| UE IP address Pool Identity | Rejected | Named UE address pools are not configured; only the single IPv4 pool exists. | 7.5.2.2-1 |
| Multipath Applicable Indication | Rejected | MPTCP/MPQUIC handling is not implemented. | 7.5.2.2-1 |
| Transport Delay Reporting | Rejected | GTP-U path-delay measurement/marking is not implemented. | 7.5.2.2-1, 7.5.4.2-1 |
| RAT Type | Ignored | Statistics metadata; packet matching and routing do not use RAT-specific statistics. | 7.5.2.2-1, 7.5.4.2-1 |
| Deactivate Predefined Rules | Rejected | No predefined rules can be activated. | 7.5.4.2-1 |

## PDI

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| Source Interface | Implemented | Access, Core or CP-function; Core GTP needs a distinct N9 address. | 7.5.2.2-2 |
| Local F-TEID | Implemented | UP allocation with CHOOSE; an existing UP-allocated tunnel may be referenced. RESTI permits restoration. | 7.5.2.2-2 |
| Local Ingress Tunnel | Rejected | N4mb generic UDP tunnel handling is not implemented. | 7.5.2.2-2 |
| Network Instance | Implemented | Admission-policy alias of the sole routing domain; see below. | 7.5.2.2-2 |
| Redundant Transmission Detection Parameters | Rejected | Duplicate detection and redundant N3/N9 reception are not implemented. | 7.5.2.2-2 |
| UE IP address | Implemented | One IE, with IPv4 and/or an explicit IPv6 prefix; allocation is IPv4 only. | 7.5.2.2-2 |
| Mapped N6 IP Address | Rejected | Mapped N6 address allocation/NAT is not implemented. | 7.5.2.2-2 |
| N6 Routing Information | Rejected | HR-SBO N6 tunnel selection is not implemented. | 7.5.2.2-2 |
| Traffic Endpoint ID | Rejected | PDI optimization/traffic endpoint indirection is not advertised. | 7.5.2.2-2 |
| SDF Filter | Implemented | Up to five OR alternatives; IP tuple subset including assigned. | 7.5.2.2-2 |
| Application ID | Rejected | Application detection/classification is not implemented. | 7.5.2.2-2 |
| Ethernet PDU Session Information | Rejected | Ethernet PDU sessions are not advertised. | 7.5.2.2-2 |
| Ethernet Packet Filter | Rejected | Ethernet PDU filtering is not implemented. | 7.5.2.2-2 |
| QFI | Implemented | Up to eight OR alternatives, with presence required even for QFI zero. | 7.5.2.2-2 |
| Framed-Route | Rejected | Framed-route packet matching and route installation are not advertised. | 7.5.2.2-2 |
| Framed-Routing | Rejected | Framed-routing behavior is not advertised. | 7.5.2.2-2 |
| Framed-IPv6-Route | Rejected | Framed-route packet matching and route installation are not advertised. | 7.5.2.2-2 |
| Source Interface Type | Ignored | 3GPP interface label for measurements; Source Interface and tunnel/local address already determine the supported ingress behavior. | 7.5.2.2-2 |
| IP Multicast Addressing Info | Rejected | Multicast membership and multicast PDR selection are not implemented. | 7.5.2.2-2 |
| DNS Query Filter | Rejected | DNS/FQDN steering is not advertised. | 7.5.2.2-2 |
| MBS Session Identifier | Rejected | MBS forwarding is not implemented. | 7.5.2.2-2 |
| Area Session ID | Rejected | Location-dependent MBS forwarding is not implemented. | 7.5.2.2-2 |
| Protocol Description | Ignored | Table note 10 explicitly excludes this from matching. PDU-set/media marking requests are separately rejected in QERs. | 7.5.2.2-2 |
| DNS Response Filter | Rejected | DNS response steering/replacement is not implemented. | 7.5.2.2-2 |
| Expedited Transfer Indication | Rejected | Expedited-transfer classification is not implemented. | 7.5.2.2-2 |

## FAR

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| FAR ID | Implemented | Session-local identity. | 7.5.2.3-1, 7.5.4.3-1 |
| Apply Action | Implemented | FORW or DROP only. BUFF/NOCP and other actions are rejected. | 7.5.2.3-1, 7.5.4.3-1 |
| Forwarding Parameters | Implemented | Supported routing/tunnel subset below. | 7.5.2.3-1 |
| Duplicating Parameters | Rejected | Packet duplication is not implemented. | 7.5.2.3-1 |
| BAR ID | Rejected | Buffering is not implemented; BUFF and NOCP remain rejected. | 7.5.2.3-1, 7.5.4.3-1 |
| Redundant Transmission Forwarding Parameters | Rejected | Redundant tunnel transmission is not implemented. | 7.5.2.3-1, 7.5.4.3-1 |
| MBS Multicast Parameters | Rejected | MBS multicast transmission is not implemented. | 7.5.2.3-1 |
| Add MBS Unicast Parameters | Rejected | MBS unicast replication is not implemented. | 7.5.2.3-1, 7.5.4.3-1 |
| Update Forwarding parameters | Implemented | Partial update of the supported forwarding subset. | 7.5.4.3-1 |
| Update Duplicating Parameters | Rejected | Packet duplication is not implemented. | 7.5.4.3-1 |
| Remove MBS Unicast Parameters | Rejected | MBS unicast replication is not implemented. | 7.5.4.3-1 |

## Forwarding Parameters

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| Destination Interface | Implemented | Access, Core, SGi/N6 or CP-function; actual output follows the supplied GTP-U tunnel and kernel FIB. | 7.5.2.3-2, 7.5.4.3-2 |
| Network Instance | Implemented | Admission-policy alias of the sole routing domain. | 7.5.2.3-2, 7.5.4.3-2 |
| Redirect Information | Rejected | Application redirection is not implemented. | 7.5.2.3-2, 7.5.4.3-2 |
| Outer Header Creation | Implemented | IPv4/UDP/GTP-U only. | 7.5.2.3-2, 7.5.4.3-2 |
| Transport Level Marking | Implemented | DSCP marking with the supported mask. | 7.5.2.3-2, 7.5.4.3-2 |
| Extended Transport Level Marking | Rejected | PDU-set importance-based DSCP marking is not advertised. | 7.5.2.3-2, 7.5.4.3-2 |
| Transport Level Marking Indications | Rejected | Incoming-packet-dependent marking is not implemented. | 7.5.2.3-2, 7.5.4.3-2 |
| Forwarding Policy | Rejected | No named forwarding policies are configured; Cause 70 is returned. | 7.5.2.3-2, 7.5.4.3-2 |
| Metadata | Rejected | Service-function-chain metadata insertion is not implemented. | 7.5.2.3-2, 7.5.4.3-2 |
| Header Enrichment | Rejected | Header enrichment is not advertised. | 7.5.2.3-2, 7.5.4.3-2 |
| Linked Traffic Endpoint ID | Rejected | Traffic endpoint indirection is not advertised. | 7.5.2.3-2, 7.5.4.3-2 |
| Proxying | Rejected | Requested ARP/ND proxying is not implemented. | 7.5.2.3-2 |
| Destination Interface Type | Ignored | 3GPP interface label; Destination Interface and the supplied tunnel/FIB determine output. No MAR or redundant forwarding is supported. | 7.5.2.3-2, 7.5.4.3-2 |
| Data Network Access Identifier | Ignored | N16a local-PSA identifier, not an N4 packet-handling instruction; no alternate routing domains or PSA-selection behavior are exposed. | 7.5.2.3-2, 7.5.4.3-2 |
| IP Address and Port Number Replacement | Rejected | Address/port replacement is not advertised. | 7.5.2.3-2, 7.5.4.3-2 |
| N6 Routing Information | Rejected | HR-SBO N6 tunnel selection is not implemented. | 7.5.2.3-2 |
| Header Handling Control Rule | Rejected | Payload header handling is not advertised. | 7.5.2.3-2, 7.5.4.3-2 |
| On-path N6 Connection Information | Rejected | Media-information proxy connections are not advertised. | 7.5.2.3-2 |
| PFCPSMReq-Flags | Rejected | Requested forwarding-switch actions such as End Marker generation are not implemented. | 7.5.4.3-2 |

## QER

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| QER ID | Implemented | Session-local identity. | 7.5.2.5-1, 7.5.4.5-1 |
| QER Correlation ID | Rejected | Cross-session APN rate correlation is not implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| Gate Status | Implemented | UL and DL gate enforcement. | 7.5.2.5-1, 7.5.4.5-1 |
| Maximum Bitrate | Implemented | UL and DL bitrate enforcement with a fixed 5 ms burst policy. | 7.5.2.5-1, 7.5.4.5-1 |
| Guaranteed Bitrate | Rejected | No minimum-rate reservation or scheduler is implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| Packet Rate | Rejected | Packets-per-time enforcement is not implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| Packet Rate Status | Rejected | Packet-rate status restoration requires an unsupported packet-rate meter. | 7.5.2.5-1 |
| DL Flow Level Marking | Rejected | Flow-level marking beyond the supported QFI/RQI and FAR DSCP is not implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| QoS flow identifier | Implemented | QFI in a 5GS PDU Session Container. | 7.5.2.5-1, 7.5.4.5-1 |
| Reflective QoS | Implemented | RQI marking; a QFI binding is required. | 7.5.2.5-1, 7.5.4.5-1 |
| Paging Policy Indicator | Rejected | Paging-policy marking is not implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| Averaging Window | Rejected | Only the documented fixed burst policy is implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| QER Control Indications | Rejected | Rate-status control/reporting is not implemented. | 7.5.2.5-1, 7.5.4.5-1 |
| QER Indications | Rejected | PDU-set/data-burst/SCONE marking is not advertised. | 7.5.2.5-1, 7.5.4.5-1 |
| PDU Set Importance for N6-unmarked PDUs | Rejected | PDU-set marking is not advertised. | 7.5.2.5-1, 7.5.4.5-1 |
| SCONE Throughput Advice | Rejected | SCONE processing is not advertised. | 7.5.2.5-1, 7.5.4.5-1 |

## URR

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| URR ID | Implemented | Session-local identity. | 7.5.2.4-1, 7.5.4.4-1 |
| Measurement Method | Implemented | Post-QoS octet volume only. | 7.5.2.4-1, 7.5.4.4-1 |
| Reporting Triggers | Implemented | Total-volume threshold and mandatory final reports; other triggers rejected. | 7.5.2.4-1, 7.5.4.4-1 |
| Measurement Period | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Volume Threshold | Implemented | Positive total threshold only; separate UL/DL thresholds rejected. | 7.5.2.4-1, 7.5.4.4-1 |
| Volume Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Event Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Event Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Time Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Time Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Quota Holding Time | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Dropped DL Traffic Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Quota Validity Time | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Monitoring Time | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Volume Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Time Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Volume Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Time Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Event Threshold | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Subsequent Event Quota | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Inactivity Detection Time | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Linked URR ID | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Measurement Information | Implemented | Zero flags retain default post-QoS octet measurement; active flags rejected. | 7.5.2.4-1, 7.5.4.4-1 |
| Time Quota Mechanism | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Aggregated URRs | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| FAR ID for Quota Action | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Ethernet Inactivity Timer | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Additional Monitoring Time | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Number of Reports | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Exempted Application ID for Quota Action | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| Exempted SDF Filter for Quota Action | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |
| User Plane Inactivity Timer | Rejected | Only post-QoS octets, a total-volume threshold and final reports are measured; this IE requests additional metering, scheduling, quota or reporting behavior. | 7.5.2.4-1, 7.5.4.4-1 |

## BAR

| IE | Treatment | Reason / supported subset | TS 29.244 V20.1.0 table |
|---|---|---|---|
| BAR ID | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1 |
| Downlink Data Notification Delay | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1 |
| Suggested Buffering Packets Count | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1 |
| MT-EDT Control Information | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1 |
| MT-SDT Control Information | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1 |
| DL Buffering Duration | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1 |
| DL Buffering Suggested Packet Count | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.2.6-1, 7.5.4.11-1, 7.5.9.2-1 |
| Extended DL Buffering Notification Policy | Rejected | Buffering, data notification and buffer-size/duration controls are not implemented or advertised. | 7.5.4.11-1, 7.5.9.2-1 |

## Bounds and peer shapes

One key admits **four PDRs**, each with **five SDF filters**, **eight QFIs**,
**four QERs** and **three URRs**. A session admits 64 rules of each rule type.
These are implementation limits, not 3GPP maxima. In 5GC, uplink PDRs share the
N3 F-TEID, so four PDRs means at most four QoS flows on that key, and fewer when
a QoS flow uses several independently ordered PDRs. This UPF does not promise
all 63 possible QFI values in one session. An over-limit request is rejected
with Cause 75 and the offending PDR's Failed Rule ID; no list is truncated.

The read-only peer-source review used:

- [Open5GS 39a8c771](https://github.com/open5gs/open5gs/tree/39a8c771f6d51a91112c28d1a57615dcb239118d):
  `lib/pfcp/build.c` constructs interface-type labels and repeated SDFs;
  `lib/proto/types.h` bounds bearers per session to four and SDF flows per PDR
  to fifteen; `lib/pfcp/ogs-pfcp.h` permits sixteen total PDRs/URRs and four QERs.
  Four PDRs per key accommodates its four bearer/QoS-flow shape when each flow
  uses one uplink PDR. Five filters restore the original eUPF limit but do not
  cover its fifteen-filter maximum. The four-QER budget covers its per-session
  QER bound. Three URRs are a deliberate resource limit, not support for its
  full sixteen-URR session budget.
- [free5GC SMF fd0052a1](https://github.com/free5gc/smf/tree/fd0052a19cb8e0950b5ba17d2a94506803f7fe7b):
  `internal/pfcp/message/build_establishment.go` constructs Source Interface,
  F-TEID choice, Network Instance, UE IP, SDF, FAR, QER and optional URR/BAR
  children. Its SMF-allocated F-TEID request is tested and rejects with Cause 71. Its optional
  GBR, buffering, periodic/quota measurement and separate UL/DL thresholds
  remain explicit rejections. Eight PDI QFI alternatives and 64 session rules
  provide bounded sets rather than claiming the peer's unrestricted list sizes.

`TestForwardingEstablishmentsFromCommonSMFShapes` follows Open5GS's default
UL/DL plus cp2up/up2cp rules (`context.c:2395-2444,2785-2832`,
`npcf-handler.c:729-775`) and free5GC's CP allocation (`datapath.go:679`). The
Open5GS default BUFF|NOCP/BAR request remains rejected with Cause 76. Its
forwarding variant accepts the four PDRs, including the CP-function rules.
free5GC's CP-allocated tunnel remains rejected with Cause 71. These are
synthetic requests constructed from pinned source, not live interoperability. The tests
for implemented, informative and unsupported fields are separate.

## Network Instance and assigned

There is one routing domain, using the kernel FIB of the UPF's network
namespace. Accepted Network Instance names are aliases of that domain; there is
**no tenant, DNN, slice or overlapping-address isolation** between aliases.
`allow_apn` and `deny_apn` regular expressions are admission rules. A name not
matching a configured allow expression, or matching the deny expression, is
rejected. With an empty allow expression and no matching deny expression,
previously unseen names are accepted as aliases too. An omitted name uses the
same routing domain. Forwarding Parameters use the same policy as PDI.

`assigned` means the terminal's address set, per
[RFC 6733 section 4.3.1](https://www.rfc-editor.org/rfc/rfc6733.html#section-4.3.1).
It resolves from the completed session to its IPv4 address and/or IPv6 prefix.
There is one supported IPv4 address and one supported IPv6 prefix in this set;
ambiguous multiple addresses are rejected rather than widening the filter.
Access filters reverse a downlink description's endpoints and ports. A missing
assigned address remains a rejection. Malformed optional Flow Descriptions are
absent under TS 29.244 V20.1.0 clause 7.6.8. The grammar is:

`permit out <decimal-protocol|ip|protocol-name> from <address[/mask]|any> [port[-port]] to <address[/mask]|assigned> [port[-port]]`

TS 29.212 V20.0.0 clause 5.4.2 restricts RFC 6733 section 4.3.1 encoding:
no `deny`, direction `in`, address negation, port lists or options. Source
`assigned` and destination `any` also depart from that clause. Every such
Flow Description is semantically incorrect and its SDF Filter is ignored,
logged and counted. If every filter is ignored the PDR has no SDF predicate.
Protocol names resolve to their numbers through `/etc/protocols`. An explicit
port predicate on a protocol without visible ports matches no packet; it
does not reject the request.

FTUP is always advertised. TS 29.244 V20.1.0 clause 5.5.1 requires UP F-TEID
allocation in EPC/5GC. New CP-allocated tunnels are rejected with Cause 71;
RESTI allows an available existing tunnel during restoration. Referencing an
already UP-allocated F-TEID in the same session does not allocate a new CP tunnel.

Source and Destination Interface CP-function values are supported for GTP-U
N4-u/Sx-u forwarding (TS 29.244 V20.1.0 clause 5.3.1). Local tunnel addresses
remain IPv4-only: an F-TEID CHOOSE offering both families receives V4 only;
a V6-only choice returns Cause 76. Numeric SDF protocol values cover 0-255,
with a separate `ip` wildcard. TCP, UDP and SCTP port ranges are supported;
prohibited grammar is ignored under clause 7.6.8. Ignored optional filters are logged with SEID/PDR ID and
counted by `upf_ignored_sdf_filters_total`.

# eUPF 3GPP compatibility

The current implementation uses 3GPP TS 29.244 V20.1.0 for PFCP and
TS 29.281 V19.2.0 for GTP-U. Support is limited to the documented procedures
and rule fields; this is not a claim of complete conformance to either release.

The maintained capability descriptions are:

- [Rule capabilities](rule-capabilities.md): supported and rejected PFCP IEs,
  feature advertisement, rule transactions, and their specification clauses.
- [PFCP transport](pfcp-transport.md): association, reliable delivery, recovery,
  usage report outcomes, and resource limits.
- [Data plane](dataplane.md): GTP-U packet processing, forwarding, QoS, usage,
  and control-message behavior.

Ordinary N3/N9/EPC End Markers are generated on a per-FAR SNDEM request when
the downstream F-TEID changes. Transmission follows rule publication and the
data-plane grace period, using the old tunnel's destination, port, and TEID.
The source is the local N3/N9 address currently programmed for G-PDUs, including
REST changes; advertised F-TEID, S1-U/S5S8 and PA addresses do not select it
(TS 29.281 V19.2.0 clause 4.4.3.6).
EMPU is advertised. Labeled N3/N9 data-forwarding tunnels use the old PDR
container-deletion instruction or a mapped QER QFI for SNDEM. Received markers
select the E-RAB by QFI when it is present and apply the same insertion/deletion
as G-PDUs. A container-less ordinary End Marker follows the first PDR matching
the ingress interface, regardless of QFI lists; a present unmatched QFI is dropped.
One frame leaves per received marker (TS 29.281 V19.2.0 clauses 5.2.2.7 and
7.3.2.1; TS 29.244 V20.1.0 clause 5.17.3).
N19 and N19mb do not emit or relay End Markers
(TS 29.244 V20.1.0 clause 5.3.2; TS 29.281 V19.2.0 clause 7.3.2).

BUFF, NOCP and bounded BAR control are supported as described in the capability
table. Generic-XDP kernel continuations carry an authenticated private envelope
so released packets are counted and classified once.

Local session release stops forwarding through the deletion transaction and
reports final USAR/TEBUR or UISR, with PSDBU in the last request only when both
functions negotiated EPFAR
(TS 29.244 V20.1.0 clause 5.18.2 and table 7.5.8.1-1). EPFAR is advertised and negotiated preparation
from either peer reports and deletes sessions before URSS. The local
`inactivity_release_timeout` setting shares received-packet activity with the
CP's session-level User Plane Inactivity Timer. The latter requests UPIR and
leaves forwarding intact (clauses 5.11.2 and 5.18.1). Per-PDR UPINT remains
unsupported and UPIDP is not advertised.

Unknown-tunnel Error Indications are suppressed during `restoration_period`
after startup, using the same period as automatic UE IPv4 restoration
(TS 23.527 V20.0.0 clause 4.3.2; TS 23.007 V19.2.0 clauses 16.1A.4 and
17.1b.1). See the [configuration reference](Configuration.md) for its bounds.

PDU Session Container insertion on relayed G-PDUs and End Markers requires the
FAR's 3GPP Interface Type to be N3 or N9 for data forwarding (TS 29.244 V20.1.0
clause 5.17.3). The UPF cannot otherwise identify an EPS-to-5GS forwarding tunnel.
Ordinary N9 and N4-u relays preserve received extension headers; their QER QFI
alone does not request insertion of a downlink container.

FTUP is always advertised: new local tunnels require UP F-TEID allocation
with CHOOSE; an existing UP allocation may be referenced, and RESTI permits
restoration (TS 29.244 V20.1.0 clauses 5.5.1 and 5.5.3). This excludes current
free5GC SMFs that allocate the F-TEID in the CP; see
[free5GC #509](https://github.com/free5gc/free5gc/issues/509).

PFCP bundling is advertised with BUNDL. DDND, DLBD, DBDM and UDBC advertise
the implemented buffering parameters; BUCP, DDDS and EDBNC are not implemented.
UEIP is advertised only when automatic IPv4 allocation is enabled. Explicit
IPv6 UE addresses and prefixes are supported, but IPv6 allocation and IPv6
outer GTP-U transport are not. N9/ULCL uses the documented Source Interface and
FAR destination rules; these capabilities do not imply support for every
branching or multicast procedure.

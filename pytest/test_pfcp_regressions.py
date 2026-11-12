"""Synthetic upstream regressions; run only inside the privileged dev container.

Build bin/eupf first, then:
  EUPF_REGRESSION_BINARY=/src/bin/eupf pytest -v pytest/test_pfcp_regressions.py
EUPF_REGRESSION_EVIDENCE selects the output directory for logs and capture.
Each test gets a fresh process and a bounded request count. No external peers
or subscriber data are used. Expected baseline failures are not marked xfail.
"""

import concurrent.futures
import socket
import time
import urllib.error
import urllib.request

import pytest
from scapy.contrib import pfcp


from conftest import far, pdr, get_json


def test_heartbeat_missing_recovery_does_not_crash(peer):
    # TS 29.244 V20.1.0 clause 7.6.6 exempts Heartbeat from Cause responses.
    packet = pfcp.PFCP(version=1, S=0, seq=100) / pfcp.PFCPHeartbeatRequest(IE_list=[])
    peer.sock.sendto(bytes(packet), ("127.0.0.1", 8805))
    time.sleep(0.1)
    assert peer.process.poll() is None, "Heartbeat without Recovery Time Stamp crashed eupf"
    response = peer.request(pfcp.PFCPHeartbeatRequest(IE_list=[
        pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
    ]))
    assert response.haslayer(pfcp.PFCPHeartbeatResponse)


def test_missing_source_interface_is_rejected(peer):
    # TS 29.244 V20.1.0 table 7.5.2.2-2 and clause 7.6.6.
    response = peer.establish([far(), pdr(source=False)])
    assert response[pfcp.IE_Cause].cause == 66
    assert response[pfcp.IE_OffendingIE].type == 20


def test_sdf_length_does_not_crash(peer):
    # TS 29.244 V20.1.0 clauses 7.6.8 and 8.2.5.
    malformed = pfcp.IE_NotImplemented(ietype=23, data=b"\x01\x00\xff\xfeA")
    response = peer.establish([far(), pdr(sdf=malformed)])
    assert peer.process.poll() is None
    assert response.haslayer(pfcp.PFCPSessionEstablishmentResponse)


def test_truncated_outer_header_is_rejected(peer):
    # TS 29.244 V20.1.0 clauses 7.6.8 and 8.2.56.
    truncated = pfcp.IE_NotImplemented(ietype=84, data=b"\x01\x00\x00\x00\x00\x01")
    response = peer.establish([far(outer=truncated), pdr()])
    assert response[pfcp.IE_Cause].cause == 73
    assert response[pfcp.IE_FailedRuleId].type == 1
    assert response[pfcp.IE_FailedRuleId].far_id == 1


def test_valid_create_far_modification_does_not_crash(peer):
    # TS 29.244 V20.1.0 table 7.5.4.1-1; OHC format in clause 8.2.56.
    seid = peer.session()
    outer = pfcp.IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=1234, ipv4="192.0.2.20")
    downlink = pdr(identifier=2, sdf=pfcp.IE_SDF_Filter(
        FD=1, flow_description=b"permit out udp from any to any"))
    downlink[pfcp.IE_FAR_Id].id = 2
    response = peer.request(pfcp.PFCPSessionModificationRequest(
        IE_list=[far(2, outer), downlink]), seid)
    assert response[pfcp.IE_Cause].cause == 1


def test_unknown_far_removal_preserves_other_session(peer):
    # TS 29.244 V20.1.0 table 7.5.4.7-1: FAR ID identifies the FAR to delete.
    peer.session()
    second_pdr = pdr(identifier=2)
    second_pdr[pfcp.IE_FAR_Id].id = 2
    second_pdr[pfcp.IE_UE_IP_Address].ipv4 = "192.0.2.11"
    second = peer.establish([far(2), second_pdr])
    assert second[pfcp.IE_Cause].cause == 1
    seid = second[pfcp.IE_FSEID].seid
    before = {identifier: get_json(f"/api/v1/far_map/{identifier}")
              for identifier in (0, 1)}
    response = peer.request(pfcp.PFCPSessionModificationRequest(IE_list=[
        pfcp.IE_RemoveFAR(IE_list=[pfcp.IE_FAR_Id(id=7777)]),
    ]), seid)
    assert response[pfcp.IE_Cause].cause != 1
    after = {identifier: get_json(f"/api/v1/far_map/{identifier}")
             for identifier in (0, 1)}
    assert after == before


def test_invalid_sdf_rejects_session_without_leaving_state(peer):
    # TS 29.244 V20.1.0 clause 5.2.9: reject rules that cannot be activated.
    before = get_json("/api/v1/pfcp_sessions") or []
    causes = []
    for _ in range(3):
        response = peer.establish([
            far(), pdr(sdf=pfcp.IE_SDF_Filter(FD=1, flow_description=b"invalid")),
        ])
        causes.append(response[pfcp.IE_Cause].cause)
        assert response[pfcp.IE_FailedRuleId].type == 0
        assert response[pfcp.IE_FailedRuleId].pdr_id == 1
    after = get_json("/api/v1/pfcp_sessions") or []
    print(f"invalid SDF: causes={causes}, sessions before={len(before)}, after={len(after)}")
    assert all(cause == 73 for cause in causes)
    assert after == before


def test_unidentifiable_pdr_is_not_silently_accepted(peer):
    # TS 29.244 V20.1.0 clause 5.2.1: a PDR must identify its session.
    seid = peer.session()
    response = peer.request(pfcp.PFCPSessionModificationRequest(IE_list=[
        pdr(identifier=5, address=False,
            sdf=pfcp.IE_SDF_Filter(FD=1, flow_description=b"permit out udp from any to any 5201")),
    ]), seid)
    assert response[pfcp.IE_Cause].cause != 1


@pytest.mark.parametrize("endpoint", ["/api/v1/pfcp_associations/full", "metrics"])
def test_session_creation_is_safe_during_http_reads(peer, endpoint):
    # Both #632 and #634 require readers to share the session lock discipline.
    def read_repeatedly():
        for _ in range(60):
            url = ("http://127.0.0.1:19090/metrics" if endpoint == "metrics"
                   else "http://127.0.0.1:18080" + endpoint)
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    response.read()
            except urllib.error.HTTPError as error:
                # Keep exercising the map even when the existing Timer field
                # makes the full-association JSON encoder return HTTP 500.
                assert endpoint != "metrics" and error.code == 500
                error.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        readers = [executor.submit(read_repeatedly) for _ in range(2)]
        for _ in range(40):
            seid=peer.session()
            response=peer.request(pfcp.PFCPSessionDeletionRequest(),seid)
            assert response[pfcp.IE_Cause].cause==1
        for reader in readers:
            reader.result()
    assert peer.process.poll() is None


@pytest.mark.parametrize("peer", ["huawei"], indirect=True)
def test_empty_huawei_subscriber_value_does_not_crash(peer):
    empty_subscriber = pfcp.IE_EnterpriseSpecific(ietype=32769, enterprise_id=2011, data=b"")
    response = peer.establish([pfcp.IE_CreateFAR(IE_list=[pfcp.IE_FAR_Id(id=1),pfcp.IE_ApplyAction(DROP=1)]), pdr(), empty_subscriber])
    assert response[pfcp.IE_Cause].cause == 1
    assert peer.process.poll() is None


def test_unknown_predefined_rule_is_rejected(peer):
    unknown = pdr()
    unknown.IE_list.append(pfcp.IE_ActivatePredefinedRules(name=b"unconfigured"))
    before = get_json("/api/v1/pfcp_sessions") or []
    response = peer.establish([far(), unknown])
    assert response[pfcp.IE_Cause].cause == 73
    assert response[pfcp.IE_FailedRuleId].type == 0
    assert response[pfcp.IE_FailedRuleId].pdr_id == 1
    assert (get_json("/api/v1/pfcp_sessions") or []) == before


@pytest.mark.parametrize("case,cause,offending,rule_kind,rule_id", [
    ("conditional",67,31,3,9),
    ("gate",69,25,2,9),
    ("policy",70,41,1,1),
    ("allocation",71,21,0,1),
    ("capacity",75,None,0,1),
    ("unsupported",76,62,3,9),
])
def test_rule_rejection_details_and_atomicity(peer,case,cause,offending,rule_kind,rule_id):
    # TS 29.244 V20.1.0 Table 8.2.1-1, clauses 8.2.22 and 8.2.80.
    rules=[far(),pdr()]
    if case=="conditional":
        rules.append(pfcp.IE_CreateURR(IE_list=[pfcp.IE_URR_Id(id=9),pfcp.IE_MeasurementMethod(VOLUM=1),pfcp.IE_ReportingTriggers(volume_threshold=1)]))
    elif case=="gate":
        rules.append(pfcp.IE_CreateQER(IE_list=[pfcp.IE_QER_Id(id=9),pfcp.IE_GateStatus(ul=2,dl=0)]))
    elif case=="policy":
        rules[0][pfcp.IE_ForwardingParameters].IE_list.append(pfcp.IE_ForwardingPolicy(policy_identifier=b"undefined"))
    elif case=="allocation":
        rules[1][pfcp.IE_PDI].IE_list.append(pfcp.IE_FTEID(V4=1,TEID=100,ipv4="127.0.0.1"))
    elif case=="capacity":
        rules[1][pfcp.IE_PDI].IE_list += [pfcp.IE_SDF_Filter(FD=1,flow_description=b"permit out udp from any to any") for _ in range(3)]
    elif case=="unsupported":
        rules.append(pfcp.IE_CreateURR(IE_list=[pfcp.IE_URR_Id(id=9),pfcp.IE_MeasurementMethod(DURAT=1),pfcp.IE_ReportingTriggers()]))
    before=get_json("/api/v1/pfcp_sessions") or []
    response=peer.establish(rules)
    assert response[pfcp.IE_Cause].cause==cause
    assert response[pfcp.IE_FailedRuleId].type==rule_kind
    field={0:"pdr_id",1:"far_id",2:"qer_id",3:"urr_id"}[rule_kind]
    assert getattr(response[pfcp.IE_FailedRuleId],field)==rule_id
    if offending is not None:
        assert response[pfcp.IE_OffendingIE].type==offending
    assert (get_json("/api/v1/pfcp_sessions") or [])==before


def test_final_usage_in_modification_and_deletion(peer):
    # TS 29.244 V20.1.0 clauses 5.2.2.3.1, 7.5.5 and 7.5.7.
    detection=pdr()
    detection.IE_list += [pfcp.IE_URR_Id(id=11),pfcp.IE_URR_Id(id=22)]
    usage=lambda identifier:pfcp.IE_CreateURR(IE_list=[pfcp.IE_URR_Id(id=identifier),pfcp.IE_MeasurementMethod(VOLUM=1),pfcp.IE_ReportingTriggers()])
    response=peer.establish([far(),usage(11),usage(22),detection])
    assert response[pfcp.IE_Cause].cause==1
    seid=response[pfcp.IE_FSEID].seid
    modification=peer.request(pfcp.PFCPSessionModificationRequest(IE_list=[pfcp.IE_RemoveURR(IE_list=[pfcp.IE_URR_Id(id=11)])]),seid)
    assert modification[pfcp.IE_Cause].cause==1
    deletion=peer.request(pfcp.PFCPSessionDeletionRequest(),seid)
    assert deletion[pfcp.IE_Cause].cause==1
    for response,expected in [(modification,11),(deletion,22)]:
        assert response[pfcp.IE_URR_Id].id==expected
        assert response[pfcp.IE_UR_SEQN].number==0
        assert response[pfcp.IE_VolumeMeasurement].total==0


def test_kernel_write_failure_restores_previous_rules(peer,evidence):
    # A real kernel EPERM occurs after a successful FAR update. The saved FAR
    # and session state must be restored; Cause 77 identifies the system failure.
    import os
    from pathlib import Path
    import subprocess
    binary=Path(os.environ["EUPF_REGRESSION_BINARY"])
    helper=binary.parent/"mapfault"
    assert helper.is_file(), "build cmd/core/testtools/mapfault before this suite"
    detection=pdr()
    detection.IE_list.append(pfcp.IE_QER_Id(id=9))
    response=peer.establish([far(),pfcp.IE_CreateQER(IE_list=[pfcp.IE_QER_Id(id=9),pfcp.IE_GateStatus(ul=0,dl=0)]),detection])
    assert response[pfcp.IE_Cause].cause==1
    seid=response[pfcp.IE_FSEID].seid
    before=get_json("/api/v1/pfcp_sessions")
    far_before=get_json("/api/v1/far_map/1")
    fault=subprocess.run([str(helper),str(peer.process.pid),str(binary),"qer_map"],check=True,capture_output=True,text=True)
    (evidence/"kernel-map-fault.json").write_text(fault.stdout)
    response=peer.request(pfcp.PFCPSessionModificationRequest(IE_list=[
        pfcp.IE_UpdateFAR(IE_list=[pfcp.IE_FAR_Id(id=1),pfcp.IE_ApplyAction(DROP=1)]),
        pfcp.IE_UpdateQER(IE_list=[pfcp.IE_QER_Id(id=9),pfcp.IE_GateStatus(ul=1,dl=1)]),
    ]),seid)
    assert response[pfcp.IE_Cause].cause==77
    assert response[pfcp.IE_FailedRuleId].type==2
    assert response[pfcp.IE_FailedRuleId].qer_id==9
    assert get_json("/api/v1/pfcp_sessions")==before
    assert get_json("/api/v1/far_map/1")==far_before

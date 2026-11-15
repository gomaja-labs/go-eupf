"""Synthetic local deletion, enhanced release and inactivity wire regressions."""
import json
import socket
import struct
import time
import urllib.error
import urllib.request

import pytest
from scapy.contrib import pfcp

from conftest import DESTINATION, Peer, TunnelTraffic, get_json, uplink_far, uplink_pdr
from test_pfcp_transport import management_request


def children(payload):
    """Decode bounded IE framing independently of optional Scapy field support."""
    offset = 0
    while offset < len(payload):
        assert offset + 4 <= len(payload)
        kind, size = struct.unpack_from("!HH", payload, offset)
        offset += 4
        assert offset + size <= len(payload)
        yield kind, payload[offset:offset + size]
        offset += size


def field(packet, kind):
    return next((body for value, body in children(bytes(packet.payload)) if value == kind), None)


def report_response(sock, request, seid, cause=1):
    sock.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=request.seq) /
        pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=cause)])), DESTINATION)


def terminal_report(packet, octets):
    # TS 29.244 V20.1.0 tables 7.5.8.1-1/7.5.8.3-1 and clause 8.2.119.
    assert packet.message_type == 56
    assert field(packet, 39) == (b"\x02" if octets else b"\x40")
    assert field(packet, 161)[0] & 1
    reports = [body for kind, body in children(bytes(packet.payload)) if kind == 80]
    assert len(reports) == (1 if octets else 0)
    if octets:
        nested = dict(children(reports[0]))
        assert nested[63][2] & 2  # TEBUR, clause 8.2.41.
        assert nested[66][0] & 7 == 7
        assert struct.unpack_from("!QQQ", nested[66], 1) == (octets, octets, 0)


def usage_rule():
    return pfcp.IE_CreateURR(IE_list=[pfcp.IE_URR_Id(id=9),
        pfcp.IE_MeasurementMethod(VOLUM=1), pfcp.IE_ReportingTriggers(volume_threshold=1),
        pfcp.IE_VolumeThreshold(TOVOL=1, total=1 << 60)])


def entity_socket(address="127.0.0.6"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((address, 8805))
    sock.settimeout(3)
    return sock


def authenticated_api(path, method="GET", token=None):
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:18080/api/v1/" + path,
            method=method, headers=headers), timeout=3) as response:
        return response.status, json.load(response)


@pytest.mark.parametrize("usage,cause", [(False, 1), (True, 77)])
def test_authenticated_rest_release_is_locally_final(server, usage, cause):
    # This fixture's credential is synthetic and has no use outside this process.
    token = "synthetic-release-test"
    remote = Peer(server(("--api-token", token, "--pfcp-request-timeout", "1")))
    entity = entity_socket()
    remote.entity_address = "127.0.0.6"
    traffic = None
    try:
        remote.associate()
        response = remote.establish([uplink_far(), *([usage_rule()] if usage else []),
            uplink_pdr(urrs=(9,) if usage else ())])
        assert response[pfcp.IE_Cause].cause == 1
        seid = response[pfcp.IE_FSEID].seid
        with pytest.raises(urllib.error.HTTPError) as denied:
            authenticated_api(f"pfcp_sessions?id={seid}", "DELETE")
        assert denied.value.code == 401
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        octets = traffic.send("final-local-usage") if usage else 0
        status, result = authenticated_api(f"pfcp_sessions?id={seid}", "DELETE", token)
        assert status == 200 and result == {"seid": seid, "epfar": False}
        wire = entity.recvfrom(65535)[0]
        request = pfcp.PFCP(wire)
        terminal_report(request, octets)
        assert not authenticated_api("pfcp_sessions", token=token)[1]
        # Both crossing requests refer to the deleted local context.
        for payload in [pfcp.PFCPSessionModificationRequest(), pfcp.PFCPSessionDeletionRequest()]:
            response = remote.request(payload, seid)
            assert response[pfcp.IE_Cause].cause == 65 and response.seid == 0
        assert entity.recvfrom(65535)[0] == wire
        report_response(entity, request, seid, cause)
        entity.settimeout(1.2)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
        traffic.send("deleted-forwarding", delivered=False)
    finally:
        if traffic is not None:
            traffic.close()
        entity.close()
        remote.close()


@pytest.mark.parametrize("up_initiated", [False, True])
def test_enhanced_release_from_both_initiators(server, up_initiated):
    # TS 29.244 V20.1.0 clauses 5.18.1 and 6.2.7.3.1.
    remote = Peer(server(("--pfcp-request-timeout", "1")))
    node = entity_socket(remote.address)
    entity = entity_socket()
    remote.entity_address = "127.0.0.6"
    traffic = None
    try:
        setup = remote.request(pfcp.PFCPAssociationSetupRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4=remote.node_address),
            pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
            pfcp.IE_NotImplemented(ietype=89, data=b"\x04")]))
        assert setup[pfcp.IE_Cause].cause == 1 and field(setup, 43)[1] & 0x80
        remote.associated = True
        response = remote.establish([uplink_far(), usage_rule(), uplink_pdr(urrs=(9,))])
        assert response[pfcp.IE_Cause].cause == 1
        seid = response[pfcp.IE_FSEID].seid
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        octets = traffic.send("enhanced-final-usage")
        if up_initiated:
            assert management_request("pfcp_associations/release") == 204
            prepare = pfcp.PFCP(node.recvfrom(65535)[0])
            assert prepare.message_type == 7 and field(prepare, 162)[0] & 1
            assert field(prepare, 111) is None
            node.sendto(bytes(pfcp.PFCP(version=1, S=0, seq=prepare.seq) /
                pfcp.PFCPAssociationUpdateResponse(IE_list=[
                    pfcp.IE_NodeId(id_type=0, ipv4=remote.node_address), pfcp.IE_Cause(cause=1)])), DESTINATION)
        else:
            prepare = remote.request(pfcp.PFCPAssociationUpdateRequest(IE_list=[
                pfcp.IE_NodeId(id_type=0, ipv4=remote.node_address),
                pfcp.IE_NotImplemented(ietype=162, data=b"\x01")]))
            assert prepare[pfcp.IE_Cause].cause == 1
        report = pfcp.PFCP(entity.recvfrom(65535)[0])
        terminal_report(report, octets)
        node.settimeout(.2)
        with pytest.raises(socket.timeout):
            node.recvfrom(65535)  # URSS must wait for the report's outcome.
        report_response(entity, report, seid)
        node.settimeout(3)
        completion = pfcp.PFCP(node.recvfrom(65535)[0])
        assert completion.message_type == 7 and field(completion, 111)[0] & 2
        assert field(completion, 162) is None
        node.sendto(bytes(pfcp.PFCP(version=1, S=0, seq=completion.seq) /
            pfcp.PFCPAssociationUpdateResponse(IE_list=[
                pfcp.IE_NodeId(id_type=0, ipv4=remote.node_address), pfcp.IE_Cause(cause=1)])), DESTINATION)
        remote.release()
        deadline = time.monotonic() + 2
        while get_json("/api/v1/pfcp_sessions"):
            assert time.monotonic() < deadline, "enhanced reclamation exceeded fixture's 2-second bound"
            time.sleep(.01)
        traffic.send("after-enhanced-release", delivered=False)
        assert get_json("/api/v1/pfcp_associations") == []
    finally:
        if traffic is not None:
            traffic.close()
        entity.close()
        node.close()
        remote.close()


def test_local_inactivity_uses_received_activity(server):
    remote = Peer(server(("--inactivity-release-timeout", "1")))
    entity = entity_socket()
    remote.entity_address = "127.0.0.6"
    traffic = None
    try:
        remote.associate()
        response = remote.establish([uplink_far(), uplink_pdr()])
        assert response[pfcp.IE_Cause].cause == 1
        seid = response[pfcp.IE_FSEID].seid
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        for _ in range(7):
            traffic.send("keep-active")
            time.sleep(.2)
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
        request = pfcp.PFCP(entity.recvfrom(65535)[0])
        terminal_report(request, 0)
        assert not get_json("/api/v1/pfcp_sessions")
        report_response(entity, request, seid)
        traffic.send("after-inactivity", delivered=False)
    finally:
        if traffic is not None:
            traffic.close()
        entity.close()
        remote.close()


def test_upir_timer_update_preserves_age_and_leaves_forwarding(server):
    # TS 29.244 V20.1.0 clause 5.11.2; wire timer is an unsigned count of
    # seconds (8.2.83), constructed directly rather than through Scapy timers.
    remote = Peer(server())
    entity = entity_socket()
    remote.entity_address = "127.0.0.6"
    traffic = None
    try:
        remote.associate()
        timer = lambda seconds: pfcp.IE_NotImplemented(ietype=117, data=struct.pack("!I", seconds))
        response = remote.establish([uplink_far(), uplink_pdr(), timer(1)])
        assert response[pfcp.IE_Cause].cause == 1
        seid = response[pfcp.IE_FSEID].seid
        first = pfcp.PFCP(entity.recvfrom(65535)[0])
        assert field(first, 39) == b"\x08" and field(first, 161) is None
        report_response(entity, first, seid)
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        traffic.send("forwarding-after-UPIR")
        entity.settimeout(1.2)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
        # Last packet is now more than a second old. A longer update does not
        # report; reducing it must report immediately without restarting age.
        assert remote.request(pfcp.PFCPSessionModificationRequest(IE_list=[timer(10)]), seid)[pfcp.IE_Cause].cause == 1
        entity.settimeout(.2)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
        started = time.monotonic()
        assert remote.request(pfcp.PFCPSessionModificationRequest(IE_list=[timer(1)]), seid)[pfcp.IE_Cause].cause == 1
        entity.settimeout(.5)
        updated = pfcp.PFCP(entity.recvfrom(65535)[0])
        assert time.monotonic() - started < .5 and field(updated, 39) == b"\x08"
        report_response(entity, updated, seid)
        assert remote.request(pfcp.PFCPSessionModificationRequest(IE_list=[timer(0)]), seid)[pfcp.IE_Cause].cause == 1
        entity.settimeout(1.2)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
        traffic.send("forwarding-after-timer-disable")
    finally:
        if traffic is not None:
            traffic.close()
        entity.close()
        remote.close()

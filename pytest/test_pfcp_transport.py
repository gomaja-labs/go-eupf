"""Synthetic PFCP transport regressions, run in the privileged development container.

Build bin/eupf (or bin/eupf-race) and set EUPF_REGRESSION_BINARY to its path.
EUPF_REGRESSION_EVIDENCE selects a directory for process logs. Packet capture
and tshark analysis are performed separately from these tests.
"""

import concurrent.futures
import json
import socket
import os
import signal
import struct
import subprocess
from pathlib import Path
import threading
import time
import urllib.request

import pytest
from scapy.contrib import pfcp


from conftest import DESTINATION, Peer, TunnelTraffic, get_json, uplink_far, uplink_pdr


def heartbeat():
    return pfcp.PFCPHeartbeatRequest(IE_list=[
        pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
    ])


def test_unknown_peer_heartbeat(server):
    # TS 29.244 V20.1.0 clause 6.2.2.2, including peers with no association.
    remote = Peer(server())
    try:
        response = remote.request(heartbeat())
        assert response.message_type == 2
        assert get_json("/api/v1/pfcp_associations") == []
    finally:
        remote.close()


def test_heartbeat_missing_timestamp_and_late_response(peer):
    # Clauses 7.6.6 and 7.6.5: no crash and no receive-loop stall.
    peer.sock.sendto(peer.packet(pfcp.PFCPHeartbeatRequest(IE_list=[])), DESTINATION)
    peer.sock.sendto(bytes(pfcp.PFCP(version=1, S=0, seq=8000) /
                           pfcp.PFCPHeartbeatResponse(IE_list=[
                               pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
                           ])), DESTINATION)
    response = peer.request(heartbeat())
    assert response.message_type == 2


def test_large_heartbeat_datagram(peer):
    request = heartbeat()
    request.IE_list.append(pfcp.IE_NotImplemented(ietype=4000, data=bytes(8192)))
    assert peer.request(request).message_type == 2


def test_version_not_supported_and_unknown_message(server):
    # Clauses 7.6.2 and 7.6.4; types 11 and 200 respectively.
    remote = Peer(server())
    try:
        request = bytes(pfcp.PFCP(version=2, S=0, seq=83) / heartbeat())
        response = pfcp.PFCP(remote.exchange(request))
        assert response.message_type == 11 and response.version == 1
        remote.sock.sendto(bytes(pfcp.PFCP(version=1, S=0, message_type=200, seq=84)), DESTINATION)
        remote.sock.settimeout(0.15)
        with pytest.raises(socket.timeout):
            remote.sock.recvfrom(65535)
        remote.sock.settimeout(3)
        assert remote.request(heartbeat()).message_type == 2
    finally:
        remote.close()


def test_unknown_peer_session_cause(server):
    remote = Peer(server())
    try:
        response = pfcp.PFCP(remote.exchange(remote.establishment_request()))
        assert response.message_type == 51
        assert response[pfcp.IE_Cause].cause == 72
    finally:
        remote.close()


def test_retransmitted_establishment_replays_response(peer):
    # TS 29.244 V20.1.0 clause 6.4: same request, same response, one execution.
    request = peer.establishment_request()
    first = peer.exchange(request)
    second = peer.exchange(request)
    identical = first == second
    assert identical, "duplicate establishment changed encoded response"
    assert len(get_json("/api/v1/pfcp_sessions")) == 1


def test_retransmitted_deletion_replays_response(peer):
    seid = peer.session()
    request = peer.packet(pfcp.PFCPSessionDeletionRequest(), seid)
    first = peer.exchange(request)
    assert pfcp.PFCP(first)[pfcp.IE_Cause].cause == 1
    second = peer.exchange(request)
    identical = first == second
    assert identical, "duplicate deletion changed encoded response"
    assert not get_json("/api/v1/pfcp_sessions")


def test_originated_report_retries_and_matches_response(server):
    remote = Peer(server(("--pfcp-request-timeout", "1", "--pfcp-request-retries", "3")))
    entity = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    entity.bind(("127.0.0.6", 8805))
    entity.settimeout(3)
    remote.entity_address = "127.0.0.6"
    try:
        remote.associate()
        seid = remote.session()
        request = urllib.request.Request(
            f"http://127.0.0.1:18080/api/v1/pfcp_sessions?id={seid}",
            method="DELETE",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        first, _ = entity.recvfrom(65535)
        original = pfcp.PFCP(first)
        assert original.message_type == 56
        second, _ = entity.recvfrom(65535)
        identical = first == second
        assert identical, "originated report retry changed bytes"
        entity.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=original.seq) /
                                  pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=1)])), DESTINATION)
        entity.settimeout(1.4)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
    finally:
        entity.close()
        remote.close()


@pytest.mark.parametrize("failure", ["context_not_found", "rejected", "timeout"])
def test_failed_report_follows_changed_cp_fseid(server, failure):
    # TS 29.244 V20.1.0 table 7.5.4.1-1, clauses 6.3.5.3 and 6.4.
    remote = Peer(server(("--pfcp-request-timeout", "1", "--pfcp-request-retries", "0")))
    old_entity = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    new_entity = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    old_entity.bind(("127.0.0.6", 8805))
    new_entity.bind(("127.0.0.7", 8805))
    old_entity.settimeout(3)
    new_entity.settimeout(3)
    remote.entity_address = "127.0.0.6"
    try:
        remote.associate()
        seid = remote.session()
        request = urllib.request.Request(
            f"http://127.0.0.1:18080/api/v1/pfcp_sessions?id={seid}", method="DELETE",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        first = pfcp.PFCP(old_entity.recvfrom(65535)[0])
        assert first.message_type == 56
        new_cp_seid = first.seid + 100
        changed = remote.request(pfcp.PFCPSessionModificationRequest(IE_list=[
            pfcp.IE_FSEID(v4=1, seid=new_cp_seid, ipv4="127.0.0.7")]), seid)
        assert changed[pfcp.IE_Cause].cause == 1
        if failure != "timeout":
            cause = 65 if failure == "context_not_found" else 77
            old_entity.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=first.seq) /
                pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=cause)])), DESTINATION)
        second = pfcp.PFCP(new_entity.recvfrom(65535)[0])
        assert second.message_type == 56 and second.seid == new_cp_seid
        assert second.seq != first.seq
        assert bytes(second.payload) == bytes(first.payload)
        new_entity.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=second.seq) /
            pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=1)])), DESTINATION)
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
        assert remote.request(pfcp.PFCPSessionModificationRequest(), seid)[pfcp.IE_Cause].cause == 1
    finally:
        old_entity.close()
        new_entity.close()
        remote.close()


def test_startup_choose_and_explicit_restoration(server):
    # TS 23.527 V20.0.0 clause 4.3.2: reserve the startup window for RESTI.
    remote = Peer(server(("--restoration-period", "60")))
    try:
        remote.associate()
        automatic = remote.establish([uplink_far(), uplink_pdr()])
        assert automatic[pfcp.IE_Cause].cause == 1
        assert automatic[pfcp.IE_FTEID].TEID > 32
        # TS 29.244 V20.1.0 clause 8.2.136: RESTI is IE 186, octet 5 bit 1.
        restoration = remote.establish([uplink_far(), uplink_pdr(teid=17),
            pfcp.IE_NotImplemented(ietype=186, data=b"\x01")])
        assert restoration[pfcp.IE_Cause].cause == 1
        occupied = remote.establish([uplink_far(), uplink_pdr(teid=17),
            pfcp.IE_NotImplemented(ietype=186, data=b"\x01")])
        assert occupied[pfcp.IE_Cause].cause == 86
    finally:
        remote.close()




@pytest.mark.parametrize("period,cause", [(0, 1), (60, 75)])
def test_restoration_period_only_holds_automatic_ue_ipv4(server, period, cause):
    remote = Peer(server(("--restoration-period", str(period), "--ueip", "--ueippool", "192.0.2.0/30")))
    try:
        remote.associate()
        # CHV4 is held in Scapy's spare field; secdev/scapy#5282.
        choose = pfcp.IE_CreatePDR(IE_list=[pfcp.IE_PDR_Id(id=1), pfcp.IE_Precedence(precedence=100),
            pfcp.IE_PDI(IE_list=[pfcp.IE_SourceInterface(interface=1),
                pfcp.IE_UE_IP_Address(spare=2, SD=1)]), pfcp.IE_FAR_Id(id=1)])
        response = remote.establish([uplink_far(drop=True), choose])
        assert response[pfcp.IE_Cause].cause == cause
        if cause == 1:
            assert response[pfcp.IE_UE_IP_Address].ipv4 == "192.0.2.1"
        tunnel = remote.establish([uplink_far(), uplink_pdr()])
        assert tunnel[pfcp.IE_Cause].cause == 1
        assert tunnel[pfcp.IE_FTEID].TEID > 32
    finally:
        remote.close()

def test_restart_allocates_new_teid_generation_and_restores_predecessor(server, evidence):
    # TS 23.527 V20.0.0 clause 4.3.2: CHOOSE is available throughout restoration.
    process = server(("--restoration-period", "60"))
    remote = Peer(process)
    try:
        remote.associate()
        setup_stamp = remote.request(heartbeat())[pfcp.IE_RecoveryTimeStamp].timestamp
        first = remote.establish([uplink_far(), uplink_pdr()])
        assert first[pfcp.IE_Cause].cause == 1
        predecessor = first[pfcp.IE_FTEID].TEID
        assert predecessor == ((1 + (((setup_stamp - 2208988800) & 0xffffffff) % ((1 << 26) - 1))) << 6) + 1
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=34) == 0
        # The PFCP timestamp has second resolution. Wait for a different second.
        while int(time.time()) == ((setup_stamp - 2208988800) & 0xffffffff):
            time.sleep(.01)
        restarted = Peer(server(("--restoration-period", "60")))
        try:
            restarted.associate()
            next_stamp = restarted.request(heartbeat())[pfcp.IE_RecoveryTimeStamp].timestamp
            chosen = restarted.establish([uplink_far(), uplink_pdr()])
            assert chosen[pfcp.IE_Cause].cause == 1
            current = chosen[pfcp.IE_FTEID].TEID
            assert next_stamp != setup_stamp and current != predecessor
            assert current == ((1 + (((next_stamp - 2208988800) & 0xffffffff) % ((1 << 26) - 1))) << 6) + 1
            restored = restarted.establish([uplink_far(), uplink_pdr(teid=predecessor),
                pfcp.IE_NotImplemented(ietype=186, data=b"\x01")])
            assert restored[pfcp.IE_Cause].cause == 1
            collision = restarted.establish([uplink_far(), uplink_pdr(teid=predecessor),
                pfcp.IE_NotImplemented(ietype=186, data=b"\x01")])
            assert collision[pfcp.IE_Cause].cause == 86
            (evidence / "restart-generations.json").write_text(json.dumps({
                "pool": 32, "before_timestamp": setup_stamp, "after_timestamp": next_stamp,
                "before_teid": predecessor, "after_teid": current,
                "restoration_cause": restored[pfcp.IE_Cause].cause,
                "collision_cause": collision[pfcp.IE_Cause].cause,
            }, indent=2) + "\n")
        finally:
            restarted.close()
    finally:
        remote.close()


def test_failed_usage_survives_last_pdr_dissociation(server):
    # TS 29.244 V20.1.0 clause 5.2.2.3.1 retains the URR across dissociation.
    remote = Peer(server())
    entity = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    entity.bind(("127.0.0.6", 8805))
    entity.settimeout(6)
    remote.entity_address = "127.0.0.6"
    traffic = None
    try:
        remote.associate()
        usage = pfcp.IE_CreateURR(IE_list=[pfcp.IE_URR_Id(id=9),
            pfcp.IE_MeasurementMethod(VOLUM=1),
            pfcp.IE_ReportingTriggers(volume_threshold=1),
            pfcp.IE_VolumeThreshold(TOVOL=1, total=1)])
        response = remote.establish([uplink_far(), usage, uplink_pdr(urrs=(9,))])
        assert response[pfcp.IE_Cause].cause == 1
        seid = response[pfcp.IE_FSEID].seid
        before_slot = get_json("/api/v1/pfcp_sessions")[0]["URRs"]["9"]["GlobalId"]
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        octets = traffic.send("usage-before-counter-swap")
        first = pfcp.PFCP(entity.recvfrom(65535)[0])
        assert first.message_type == 56
        assert first[pfcp.IE_VolumeMeasurement].total == octets
        # Clause 5.6.3: a null URR ID removes that PDR's URR references.
        modification = remote.request(pfcp.PFCPSessionModificationRequest(IE_list=[
            pfcp.IE_UpdatePDR(IE_list=[pfcp.IE_PDR_Id(id=1),
                pfcp.IE_NotImplemented(ietype=81, data=b"")])]), seid)
        assert modification[pfcp.IE_Cause].cause == 1
        after_slot = get_json("/api/v1/pfcp_sessions")[0]["URRs"]["9"]["GlobalId"]
        assert after_slot != before_slot
        assert modification[pfcp.IE_VolumeMeasurement].total == 0
        entity.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=first.seq) /
            pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=77)])), DESTINATION)
        second = pfcp.PFCP(entity.recvfrom(65535)[0])
        assert second.message_type == 56 and second.seq != first.seq
        assert second[pfcp.IE_URR_Id].id == 9
        assert second[pfcp.IE_VolumeMeasurement].total == octets
        entity.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=second.seq) /
            pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=1)])), DESTINATION)
    finally:
        if traffic is not None:
            traffic.close()
        entity.close()
        remote.close()


def test_pfcp_traffic_during_rest_and_metrics_reads(peer):
    # Exercise the deployed receive path and JSON/Prometheus readers together.
    stopped = threading.Event()

    def read(path, port=18080):
        for _ in range(150):
            if stopped.is_set():
                return
            with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
                assert response.status == 200
                response.read()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        readers = [executor.submit(read, path) for path in (
            "/api/v1/pfcp_associations", "/api/v1/pfcp_associations/full", "/api/v1/pfcp_sessions")]
        readers.append(executor.submit(read, "/metrics", 19090))
        try:
            for _ in range(24):
                seid = peer.session()
                response = peer.request(pfcp.PFCPSessionDeletionRequest(), seid)
                assert response[pfcp.IE_Cause].cause == 1
        finally:
            stopped.set()
            for reader in readers:
                reader.result()
    assert peer.process.poll() is None


def management_request(path, method="POST"):
    request = urllib.request.Request(f"http://127.0.0.1:18080/api/v1/{path}", method=method,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=2) as response:
        return response.status


def test_node_requests_and_up_release_use_registered_port(server):
    remote = Peer(server(("--hbtimeout", "1", "--hbinterval", "1", "--pfcp-request-timeout", "1")))
    node = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    node.bind((remote.address, 8805))
    node.settimeout(3)
    traffic = None
    try:
        remote.associate()
        response = remote.establish([uplink_far(), uplink_pdr()])
        assert response[pfcp.IE_Cause].cause == 1
        traffic = TunnelTraffic(response[pfcp.IE_FTEID].TEID)
        traffic.send("before-release-indication")
        heartbeat_request = pfcp.PFCP(node.recvfrom(65535)[0])
        assert heartbeat_request.message_type == 1
        assert remote.sock.getsockname()[1] != 8805
        # Respond with Heartbeat Response, whose payload has the same timestamp IE.
        response = pfcp.PFCP(version=1, S=0, seq=heartbeat_request.seq) / pfcp.PFCPHeartbeatResponse(
            IE_list=[pfcp.IE_RecoveryTimeStamp(timestamp=3900000000)])
        node.sendto(bytes(response), DESTINATION)
        assert management_request("pfcp_associations/release") == 204
        first = node.recvfrom(65535)[0]
        update = pfcp.PFCP(first)
        assert update.message_type == 7
        assert node.recvfrom(65535)[0] == first
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
        node.sendto(bytes(pfcp.PFCP(version=1, S=0, seq=update.seq) / pfcp.PFCPAssociationUpdateResponse(
            IE_list=[pfcp.IE_NodeId(id_type=0, ipv4=remote.address), pfcp.IE_Cause(cause=1)])), DESTINATION)
        assert len(get_json("/api/v1/pfcp_associations")) == 1
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
        traffic.send("waiting-for-cp-release")
        remote.release()
        traffic.send("after-cp-release", delivered=False)
        assert not get_json("/api/v1/pfcp_sessions")
        assert get_json("/api/v1/pfcp_associations") == []
        node.settimeout(1.2)
        with pytest.raises(socket.timeout):
            node.recvfrom(65535)
    finally:
        if traffic is not None:
            traffic.close()
        remote.close()
        node.close()


def inconsistent_length(wire, delta):
    wire = bytearray(wire)
    wire[2:4] = struct.pack("!H", len(wire) - 4 + delta)
    return bytes(wire)


def test_invalid_message_length_responses_and_heartbeat_exemption(server):
    remote = Peer(server())
    try:
        for delta in (-1, 1):
            setup = pfcp.PFCPAssociationSetupRequest(IE_list=[pfcp.IE_NodeId(id_type=0, ipv4=remote.address),
                pfcp.IE_RecoveryTimeStamp(timestamp=3900000000)])
            reply = pfcp.PFCP(remote.exchange(inconsistent_length(remote.packet(setup), delta)))
            assert reply.message_type == 6 and reply[pfcp.IE_Cause].cause == 68
            assert get_json("/api/v1/pfcp_associations") == []
        remote.associate()
        seid = remote.session()
        cp_seid = remote.sequence
        for delta in (-1, 1):
            wire = remote.packet(pfcp.PFCPSessionModificationRequest(), seid)
            reply = pfcp.PFCP(remote.exchange(inconsistent_length(wire, delta)))
            assert reply.message_type == 53 and reply[pfcp.IE_Cause].cause == 68
            assert reply.seid == cp_seid
        for delta in (-1, 1):
            remote.sock.sendto(inconsistent_length(remote.packet(heartbeat()), delta), DESTINATION)
            remote.sock.settimeout(.2)
            with pytest.raises(socket.timeout):
                remote.sock.recvfrom(65535)
        remote.sock.settimeout(3)
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
    finally:
        remote.close()


def test_invalid_report_response_stops_retransmission(server):
    remote = Peer(server(("--pfcp-request-timeout", "1", "--pfcp-request-retries", "3")))
    entity = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    entity.bind(("127.0.0.6", 8805))
    entity.settimeout(3)
    remote.entity_address = "127.0.0.6"
    try:
        remote.associate()
        seid = remote.session()
        assert management_request(f"pfcp_sessions?id={seid}", "DELETE") == 200
        first = entity.recvfrom(65535)[0]
        request = pfcp.PFCP(first)
        assert request.message_type == 56
        assert entity.recvfrom(65535)[0] == first
        response = bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=request.seq) /
                         pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=1)]))
        entity.sendto(inconsistent_length(response, 1), DESTINATION)
        entity.settimeout(1.3)
        with pytest.raises(socket.timeout):
            entity.recvfrom(65535)
    finally:
        remote.close()
        entity.close()


def test_session_requests_from_additional_cp_addresses(server):
    remote = Peer(server())
    second = Peer(remote.process, "127.0.0.7")
    third = Peer(remote.process, "127.0.0.8")
    second.node_address = remote.node_address
    try:
        remote.associate()
        seid = second.session()
        response = third.request(pfcp.PFCPSessionModificationRequest(), seid)
        assert response[pfcp.IE_Cause].cause == 1
        assert third.request(pfcp.PFCPSessionDeletionRequest(), seid)[pfcp.IE_Cause].cause == 1
        assert not get_json("/api/v1/pfcp_sessions")
    finally:
        third.close()
        second.close()
        remote.close()


def test_release_cleanup_failure_exits_and_restart_has_empty_maps(server, evidence):
    process = server()
    remote = Peer(process)
    traffic = None
    binary = Path(os.environ["EUPF_REGRESSION_BINARY"]).resolve()
    try:
        remote.associate()
        response = remote.establish([uplink_far(), uplink_pdr()])
        assert response[pfcp.IE_Cause].cause == 1
        teid = response[pfcp.IE_FTEID].TEID
        traffic = TunnelTraffic(teid)
        traffic.send("before-cleanup-failure")
        # PDR indices detach synchronously. A frozen FAR map makes the
        # later slot clear fail, exercising bounded asynchronous reclamation.
        fault = subprocess.run([str(binary.parent / "mapfault"), str(process.pid), str(binary), "far_map"],
                               check=True, capture_output=True, text=True)
        (evidence / "release-map-fault.json").write_text(fault.stdout)
        remote.release()
        deadline = time.monotonic() + 2
        while get_json("/api/v1/pfcp_sessions") and time.monotonic() < deadline:
            time.sleep(.01)
        assert not get_json("/api/v1/pfcp_sessions")
        assert process.wait(timeout=8) == 1
        remote.close()
        restarted = Peer(server())
        try:
            assert not get_json("/api/v1/pfcp_sessions")
            traffic.send("restart-has-no-old-rule", delivered=False)
            restarted.associate()
            response = restarted.establish([uplink_far(), uplink_pdr()])
            assert response[pfcp.IE_Cause].cause == 1
            assert response[pfcp.IE_FTEID].TEID != teid
            traffic.send("previous-generation-stays-unmatched", delivered=False)
            traffic.teid = response[pfcp.IE_FTEID].TEID
            traffic.send("fresh-rule-after-restart")
        finally:
            restarted.close()
    finally:
        if traffic is not None:
            traffic.close()
        remote.close()


def test_signal_shutdown_waits_for_cp_release(server):
    remote = Peer(server(("--pfcp-request-timeout", "1", "--pfcp-request-retries", "1")))
    node = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    node.bind((remote.address, 8805))
    node.settimeout(3)
    try:
        remote.associate()
        remote.session()
        remote.process.send_signal(signal.SIGTERM)
        request = pfcp.PFCP(node.recvfrom(65535)[0])
        assert request.message_type == 7 and remote.process.poll() is None
        assert len(get_json("/api/v1/pfcp_sessions")) == 1
        remote.release()
        assert remote.process.wait(timeout=5) == 0
    finally:
        remote.close()
        node.close()

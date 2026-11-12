"""Synthetic PFCP transport regressions, run in the privileged development container.

Build bin/eupf (or bin/eupf-race) and set EUPF_REGRESSION_BINARY to its path.
EUPF_REGRESSION_EVIDENCE selects a directory for process logs. Packet capture
and tshark analysis are performed separately from these tests.
"""

import concurrent.futures
import socket
import threading
import time
import urllib.request

import pytest
from scapy.contrib import pfcp


from conftest import DESTINATION, Peer, get_json


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
    try:
        remote.associate()
        seid = remote.session()
        request = urllib.request.Request(f"http://127.0.0.1:18080/api/v1/pfcp_sessions?id={seid}", method="DELETE")
        with urllib.request.urlopen(request, timeout=2) as response:
            assert response.status == 200
        first, _ = remote.sock.recvfrom(65535)
        original = pfcp.PFCP(first)
        assert original.message_type == 56
        second, _ = remote.sock.recvfrom(65535)
        identical = first == second
        assert identical, "originated report retry changed bytes"
        remote.sock.sendto(bytes(pfcp.PFCP(version=1, S=1, seid=seid, seq=original.seq) /
                                  pfcp.PFCPSessionReportResponse(IE_list=[pfcp.IE_Cause(cause=1)])), DESTINATION)
        remote.sock.settimeout(1.4)
        with pytest.raises(socket.timeout):
            remote.sock.recvfrom(65535)
    finally:
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

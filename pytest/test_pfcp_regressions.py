"""Synthetic upstream regressions; run only inside the privileged dev container.

Build bin/eupf first, then:
  EUPF_REGRESSION_BINARY=/src/bin/eupf pytest -v pytest/test_pfcp_regressions.py
EUPF_REGRESSION_EVIDENCE selects the output directory for logs and capture.
Each test gets a fresh process and a bounded request count. No external peers
or subscriber data are used. Expected baseline failures are not marked xfail.
"""

import concurrent.futures
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request

import pytest
from scapy.contrib import pfcp


@pytest.fixture(scope="session")
def evidence():
    directory = Path(os.environ.get("EUPF_REGRESSION_EVIDENCE", "/tmp/pfcp-regressions"))
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "tcpdump.log").open("w") as output:
        capture = subprocess.Popen(
            ["tcpdump", "-U", "-i", "lo", "-w", str(directory / "synthetic.pcap"),
             "udp", "port", "8805"], stdout=output, stderr=output,
        )
        time.sleep(0.2)
        assert capture.poll() is None, "tcpdump failed to start"
        yield directory
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=5)


class Peer:
    def __init__(self, process):
        self.process = process
        self.sequence = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.2", 0))
        self.sock.settimeout(1)

    def request(self, payload, seid=None):
        self.sequence += 1
        packet = pfcp.PFCP(version=1, S=int(seid is not None),
                           seid=seid or 0, seq=self.sequence) / payload
        self.sock.sendto(bytes(packet), ("127.0.0.1", 8805))
        try:
            data, _ = self.sock.recvfrom(65535)
        except socket.timeout:
            assert self.process.poll() is None, "eupf terminated on synthetic PFCP input"
            pytest.fail("no PFCP response within one second")
        response = pfcp.PFCP(data)
        assert response.seq == self.sequence
        assert response.message_type == packet.message_type + 1
        return response

    def associate(self):
        response = self.request(pfcp.PFCPAssociationSetupRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4="127.0.0.2"),
            pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
        ]))
        assert response[pfcp.IE_Cause].cause == 1

    def establish(self, extra=None):
        self.sequence += 1
        response = self.request(pfcp.PFCPSessionEstablishmentRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4="127.0.0.2"),
            pfcp.IE_FSEID(v4=1, seid=self.sequence, ipv4="127.0.0.2"),
        ] + (extra or [])), seid=0)
        return response

    def session(self):
        response = self.establish([far(), pdr()])
        assert response[pfcp.IE_Cause].cause == 1
        return response[pfcp.IE_FSEID].seid


def far(identifier=1, outer=None):
    forward = [pfcp.IE_DestinationInterface(interface=1)]
    if outer is not None:
        forward.append(outer)
    return pfcp.IE_CreateFAR(IE_list=[
        pfcp.IE_FAR_Id(id=identifier), pfcp.IE_ApplyAction(FORW=1),
        pfcp.IE_ForwardingParameters(IE_list=forward),
    ])


def pdr(identifier=1, source=True, address=True, sdf=None):
    detection = []
    if source:
        detection.append(pfcp.IE_SourceInterface(interface=1))
    if address:
        detection.append(pfcp.IE_UE_IP_Address(V4=1, ipv4="192.0.2.10"))
    if sdf is not None:
        detection.append(sdf)
    return pfcp.IE_CreatePDR(IE_list=[
        pfcp.IE_PDR_Id(id=identifier), pfcp.IE_Precedence(precedence=100),
        pfcp.IE_PDI(IE_list=detection), pfcp.IE_FAR_Id(id=1),
    ])


def get_json(path):
    with urllib.request.urlopen("http://127.0.0.1:18080" + path, timeout=2) as response:
        return json.load(response)


@pytest.fixture
def peer(request, evidence):
    binary = os.environ.get("EUPF_REGRESSION_BINARY")
    if not binary:
        pytest.skip("set EUPF_REGRESSION_BINARY to run socket regressions")
    with (evidence / (request.node.name.replace("/", "_") + ".log")).open("w") as output:
        process = subprocess.Popen([
            binary, "--iface", "lo", "--attach", "generic", "--maxsessions", "16",
            "--paddr", "127.0.0.1:8805", "--nodeid", "127.0.0.1",
            "--n3addr", "127.0.0.1", "--aaddr", "127.0.0.1:18080",
            "--maddr", "127.0.0.1:19090", "--hbinterval", "3600", "--loglvl", "debug",
        ], stdout=output, stderr=output,
           env={**os.environ, "GORACE": "halt_on_error=1"})
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert process.poll() is None, "eupf failed during startup; inspect log"
                try:
                    get_json("/api/v1/health")
                    break
                except (OSError, ValueError):
                    time.sleep(0.05)
            else:
                pytest.fail("eupf did not become ready")
            remote = Peer(process)
            try:
                remote.associate()
                yield remote
            finally:
                remote.sock.close()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)


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
    assert response[pfcp.IE_Cause].cause != 1


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
    second = peer.establish([far(2)])
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
    after = get_json("/api/v1/pfcp_sessions") or []
    print(f"invalid SDF: causes={causes}, sessions before={len(before)}, after={len(after)}")
    assert all(cause != 1 for cause in causes)
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
            response = peer.establish()
            assert response[pfcp.IE_Cause].cause == 1
        for reader in readers:
            reader.result()
    assert peer.process.poll() is None

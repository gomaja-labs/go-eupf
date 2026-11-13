"""Shared bounded PFCP server, capture and synthetic-peer fixtures."""
import ipaddress
import itertools
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time
import urllib.request

import pytest
from scapy.contrib import pfcp

DESTINATION = ("127.0.0.1", 8805)


def get_json(path, port=18080):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
        return json.load(response)


@pytest.fixture(scope="session")
def evidence():
    directory = Path(os.environ.get("EUPF_REGRESSION_EVIDENCE", "/tmp/pfcp-regressions"))
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / "tcpdump.log").open("w") as output:
        capture = subprocess.Popen(
            ["tcpdump", "-U", "--immediate-mode", "-i", "lo", "-w", str(directory / "synthetic.pcap"),
             "udp port 8805 or udp port 2152 or udp port 4321"], stdout=output, stderr=output,
        )
        try:
            deadline = time.monotonic() + 5
            while "listening on lo" not in (directory / "tcpdump.log").read_text():
                assert capture.poll() is None, "tcpdump failed to start"
                assert time.monotonic() < deadline, "tcpdump did not become ready"
                time.sleep(0.02)
            yield directory
        finally:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)


@pytest.fixture
def server(request, evidence):
    binary = os.environ.get("EUPF_REGRESSION_BINARY")
    if not binary:
        pytest.skip("set EUPF_REGRESSION_BINARY inside the development container")
    directory = evidence
    processes = []

    def start(extra=()):
        suffix = "" if not processes else f"-{len(processes) + 1}"
        output = (directory / (request.node.name.replace("/", "_") + suffix + ".log")).open("w")
        started_ns = time.time_ns()
        process = subprocess.Popen([
            binary, "--iface", "lo", "--attach", "generic", "--maxsessions", "16",
            "--paddr", "127.0.0.1:8805", "--nodeid", "127.0.0.1",
            "--n3addr", "127.0.0.1", "--aaddr", "127.0.0.1:18080",
            "--maddr", "127.0.0.1:19090", "--teidpool", "32", "--resource-reuse-delay", "1", "--hbtimeout", "5", "--hbinterval", "60", "--loglvl", "debug",
            *extra,
        ], stdout=output, stderr=output,
            env={**os.environ, "GORACE": "halt_on_error=1"})
        processes.append((process, output))
        with (directory / "processes.jsonl").open("a") as events:
            events.write(json.dumps({"test": request.node.name, "start_ns": started_ns,
                                     "pid": process.pid, "log": Path(output.name).name}) + "\n")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            assert process.poll() is None, "server failed during startup; inspect process log"
            try:
                get_json("/api/v1/health")
                time.sleep(1)  # Let the explicit one-second restoration window expire.
                return process
            except (OSError, ValueError):
                time.sleep(0.05)
        pytest.fail("server did not become ready")

    yield start
    for process, output in processes:
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=34)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        output.close()


class Peer:
    def __init__(self, process, address="127.0.0.2"):
        self.process = process
        self.address = address
        self.entity_address = address
        self.node_address = address
        self.associated = False
        self.sequence = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((address, 0))
        self.sock.settimeout(3)

    def close(self):
        if self.associated and self.process.poll() is None:
            self.release()
        self.sock.close()

    def release(self):
        response = self.request(pfcp.PFCPAssociationReleaseRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4=self.node_address),
        ]))
        assert response[pfcp.IE_Cause].cause == 1
        self.associated = False

    def packet(self, payload, seid=None):
        self.sequence += 1
        return bytes(pfcp.PFCP(version=1, S=int(seid is not None),
                               seid=seid or 0, seq=self.sequence) / payload)

    def exchange(self, wire):
        self.sock.sendto(wire, DESTINATION)
        data, _ = self.sock.recvfrom(65535)
        assert self.process.poll() is None, "server terminated on synthetic input"
        response = pfcp.PFCP(data)
        assert response.seq == pfcp.PFCP(wire).seq
        return data

    def request(self, payload, seid=None):
        return pfcp.PFCP(self.exchange(self.packet(payload, seid)))

    def associate(self):
        response = self.request(pfcp.PFCPAssociationSetupRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4=self.node_address),
            pfcp.IE_RecoveryTimeStamp(timestamp=3900000000),
        ]))
        assert response[pfcp.IE_Cause].cause == 1
        self.associated = True

    def establishment_request(self, extra=None):
        return self.packet(pfcp.PFCPSessionEstablishmentRequest(IE_list=[
            pfcp.IE_NodeId(id_type=0, ipv4=self.node_address),
            pfcp.IE_FSEID(v4=1, seid=self.sequence+1, ipv4=self.entity_address),

        ] + ([far(), pdr()] if extra is None else extra)), seid=0)

    def establish(self, extra=None):
        return pfcp.PFCP(self.exchange(self.establishment_request([] if extra is None else extra)))

    def session(self):
        response = pfcp.PFCP(self.exchange(self.establishment_request()))
        assert response[pfcp.IE_Cause].cause == 1
        return response[pfcp.IE_FSEID].seid


def far(identifier=1, outer=None):
    if outer is None:
        outer=pfcp.IE_OuterHeaderCreation(GTPUUDPIPV4=1,TEID=100,ipv4="198.51.100.20")
    forward = [pfcp.IE_DestinationInterface(interface=0)]
    if outer is not None:
        forward.append(outer)
    return pfcp.IE_CreateFAR(IE_list=[
        pfcp.IE_FAR_Id(id=identifier), pfcp.IE_ApplyAction(FORW=1),
        pfcp.IE_ForwardingParameters(IE_list=forward),
    ])


_ue_addresses = itertools.count(int(ipaddress.IPv4Address("198.18.0.10")))


def pdr(identifier=1, source=True, address=True, sdf=None, ue_address=None):
    detection = []
    if source:
        detection.append(pfcp.IE_SourceInterface(interface=1))
    if address:
        # No-usage Deletion responds before old address leases are reclaimed.
        # Each independent synthetic PDR uses a fresh address; shared-key tests
        # can pass the same ue_address explicitly.
        chosen = ue_address or str(ipaddress.IPv4Address(next(_ue_addresses)))
        detection.append(pfcp.IE_UE_IP_Address(V4=1, SD=1, ipv4=chosen))
    if sdf is not None:
        detection.append(sdf)
    return pfcp.IE_CreatePDR(IE_list=[
        pfcp.IE_PDR_Id(id=identifier), pfcp.IE_Precedence(precedence=100),
        pfcp.IE_PDI(IE_list=detection), pfcp.IE_FAR_Id(id=1),
    ])


@pytest.fixture
def peer(request, server):
    remote = Peer(server(("--pfcp_profile", getattr(request, "param", "default"))))
    try:
        remote.associate()
        yield remote
    finally:
        remote.close()


def uplink_far(identifier=1, drop=False):
    fields = [pfcp.IE_FAR_Id(id=identifier), pfcp.IE_ApplyAction(DROP=1) if drop else pfcp.IE_ApplyAction(FORW=1)]
    if not drop:
        fields.append(pfcp.IE_ForwardingParameters(IE_list=[pfcp.IE_DestinationInterface(interface=1)]))
    return pfcp.IE_CreateFAR(IE_list=fields)


def uplink_pdr(identifier=1, precedence=100, teid=None, protocol="udp", far_id=1, qers=(), urrs=()):
    tunnel = pfcp.IE_FTEID(V4=1, CH=1) if teid is None else pfcp.IE_FTEID(V4=1, TEID=teid, ipv4="127.0.0.1")
    detection = [pfcp.IE_SourceInterface(interface=0), tunnel,
                 pfcp.IE_SDF_Filter(FD=1, flow_description=(f"permit out {protocol} from 127.0.0.3 4321 to 127.0.0.2 54321").encode())]
    return pfcp.IE_CreatePDR(IE_list=[pfcp.IE_PDR_Id(id=identifier), pfcp.IE_Precedence(precedence=precedence),
        pfcp.IE_PDI(IE_list=detection), pfcp.IE_OuterHeaderRemoval(header=0), pfcp.IE_FAR_Id(id=far_id),
        *[pfcp.IE_QER_Id(id=value) for value in qers], *[pfcp.IE_URR_Id(id=value) for value in urrs]])


class TunnelTraffic:
    def __init__(self, teid):
        self.teid = teid
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sender.bind(("127.0.0.2", 0))
        self.receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiver.bind(("127.0.0.3", 4321))

    def close(self):
        self.sender.close()
        self.receiver.close()

    def send(self, label, delivered=True):
        from scapy.layers.inet import IP, UDP
        from scapy.packet import Raw
        from scapy.contrib.gtp import GTP_U_Header
        inner = IP(src="127.0.0.2", dst="127.0.0.3") / UDP(sport=54321, dport=4321) / Raw(label.encode())
        wire = bytes(GTP_U_Header(gtp_type=255, teid=self.teid) / inner)
        self.receiver.settimeout(2 if delivered else 0.2)
        self.sender.sendto(wire, ("127.0.0.1", 2152))
        if delivered:
            assert self.receiver.recv(2048) == label.encode()
        else:
            with pytest.raises(socket.timeout):
                self.receiver.recv(2048)
        return len(bytes(inner))

"""Fixture generator for PCAP to SQLite Network Traffic Analyzer test suite.

Generates realistic and deterministic PCAP capture files for automated testing:
- sample_lab.pcap: ~150 packets of diverse laboratory traffic (TCP, UDP, ICMP, IPv6, ARP)
- known_packets.pcap: Exactly 5 deterministic packets for exact value verification
- non_ip.pcap: Non-IP packets (ARP, raw Ethernet) with null/missing IP and port fields
- empty.pcap: 0-byte empty file
- corrupted.pcap: Damaged file with invalid magic header bytes
- benchmark_large.pcap: 5,000 packets for performance benchmark (T08)
"""

from __future__ import annotations

import os
import sys
import logging

# Suppress Scapy initialization warnings and set verbosity to 0
logging.getLogger("scapy").setLevel(logging.ERROR)
try:
    from scapy.config import conf
    conf.verb = 0
except ImportError:
    pass

from scapy.all import (
    Ether,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    Raw,
    wrpcap,
)

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "fixtures")


def ensure_fixtures_dir() -> str:
    """Ensure the tests/fixtures directory exists."""
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    return FIXTURES_DIR


def generate_known_packets_pcap(fixtures_dir: str) -> str:
    """Generate tests/fixtures/known_packets.pcap with 5 deterministic packets:

    Packet 1: TCP 192.168.1.10:44321 -> 93.184.216.34:80 (HTTP GET)
    Packet 2: TCP 93.184.216.34:80 -> 192.168.1.10:44321 (HTTP 200 OK)
    Packet 3: UDP 192.168.1.10:55123 -> 8.8.8.8:53 (DNS Query)
    Packet 4: UDP 8.8.8.8:53 -> 192.168.1.10:55123 (DNS Response)
    Packet 5: ICMP Echo Request 192.168.1.10 -> 1.1.1.1
    """
    path = os.path.join(fixtures_dir, "known_packets.pcap")
    packets = []

    mac_client = "00:11:22:33:44:01"
    mac_server = "00:11:22:33:44:02"
    mac_router = "00:11:22:33:44:fe"

    # Packet 1: HTTP GET
    p1 = (
        Ether(src=mac_client, dst=mac_router)
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=44321, dport=80, flags="PA", seq=1000, ack=2000)
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    p1.time = 1700000000.0
    packets.append(p1)

    # Packet 2: HTTP 200 OK
    p2 = (
        Ether(src=mac_router, dst=mac_client)
        / IP(src="93.184.216.34", dst="192.168.1.10")
        / TCP(sport=80, dport=44321, flags="PA", seq=2000, ack=1037)
        / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!")
    )
    p2.time = 1700000000.05
    packets.append(p2)

    # Packet 3: DNS Query
    p3 = (
        Ether(src=mac_client, dst=mac_router)
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=55123, dport=53)
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com"))
    )
    p3.time = 1700000001.0
    packets.append(p3)

    # Packet 4: DNS Response
    p4 = (
        Ether(src=mac_router, dst=mac_client)
        / IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=55123)
        / DNS(
            id=0x1234,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", rdata="93.184.216.34"),
        )
    )
    p4.time = 1700000001.02
    packets.append(p4)

    # Packet 5: ICMP Echo Request
    p5 = (
        Ether(src=mac_client, dst=mac_router)
        / IP(src="192.168.1.10", dst="1.1.1.1")
        / ICMP(type=8, code=0, id=0xcafe, seq=1)
        / Raw(b"PingPayloadData")
    )
    p5.time = 1700000002.0
    packets.append(p5)

    wrpcap(path, packets)
    return path


def generate_non_ip_pcap(fixtures_dir: str) -> str:
    """Generate tests/fixtures/non_ip.pcap with frames lacking IP or transport ports."""
    path = os.path.join(fixtures_dir, "non_ip.pcap")
    packets = []

    mac_a = "00:11:22:33:44:01"
    mac_b = "00:11:22:33:44:02"
    mac_bcast = "ff:ff:ff:ff:ff:ff"

    # Packet 1: ARP Request
    p1 = Ether(src=mac_a, dst=mac_bcast) / ARP(
        op=1,
        hwsrc=mac_a,
        psrc="192.168.1.10",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )
    p1.time = 1700000010.0
    packets.append(p1)

    # Packet 2: ARP Reply
    p2 = Ether(src=mac_b, dst=mac_a) / ARP(
        op=2,
        hwsrc=mac_b,
        psrc="192.168.1.1",
        hwdst=mac_a,
        pdst="192.168.1.10",
    )
    p2.time = 1700000010.005
    packets.append(p2)

    # Packet 3: Raw LLC / LLDP frame (Ethertype 0x88CC)
    p3 = Ether(src=mac_a, dst="01:80:c2:00:00:00", type=0x88CC) / Raw(b"LLDP_TEST_FRAME_DATA")
    p3.time = 1700000011.0
    packets.append(p3)

    # Packet 4: Raw Loopback Configuration Test Protocol (Ethertype 0x9000)
    p4 = Ether(src=mac_b, dst=mac_bcast, type=0x9000) / Raw(b"CTP_LOOPBACK_PACKET_PAYLOAD")
    p4.time = 1700000012.0
    packets.append(p4)

    wrpcap(path, packets)
    return path


def generate_empty_pcap(fixtures_dir: str) -> str:
    """Generate tests/fixtures/empty.pcap as a 0-byte empty file."""
    path = os.path.join(fixtures_dir, "empty.pcap")
    with open(path, "wb") as f:
        pass  # 0 bytes
    return path


def generate_corrupted_pcap(fixtures_dir: str) -> str:
    """Generate tests/fixtures/corrupted.pcap with invalid magic header bytes."""
    path = os.path.join(fixtures_dir, "corrupted.pcap")
    with open(path, "wb") as f:
        f.write(b"\xaa\xbb\xcc\xdd\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b")
    return path


def generate_sample_lab_pcap(fixtures_dir: str) -> str:
    """Generate tests/fixtures/sample_lab.pcap containing ~150 realistic lab packets:
    - TCP: HTTP handshake + GET + response + FIN/ACK, HTTPS/TLS session, SSH banner exchange
    - UDP: DNS queries/responses, NTP time synchronizations
    - ICMP: Ping requests and echo replies
    - IPv6: IPv6 TCP session, IPv6 UDP, ICMPv6 echo request/reply
    - Non-IP: ARP requests, ARP replies, raw Ethernet frames
    """
    path = os.path.join(fixtures_dir, "sample_lab.pcap")
    packets = []
    base_ts = 1700000100.0

    mac_client = "00:11:22:33:44:01"
    mac_server = "00:11:22:33:44:02"
    mac_gw = "00:11:22:33:44:fe"
    mac_bcast = "ff:ff:ff:ff:ff:ff"

    ip_client = "192.168.1.50"
    ip_web = "192.168.1.100"
    ip_dns = "8.8.8.8"
    ip_ntp = "216.239.35.0"
    ip_ssh = "192.168.1.200"
    ip_ext = "93.184.216.34"

    t = base_ts

    # 1. ARP Resolution (4 packets)
    p = Ether(src=mac_client, dst=mac_bcast) / ARP(op=1, hwsrc=mac_client, psrc=ip_client, pdst=ip_web)
    p.time = t; packets.append(p); t += 0.005
    p = Ether(src=mac_server, dst=mac_client) / ARP(op=2, hwsrc=mac_server, psrc=ip_web, hwdst=mac_client, pdst=ip_client)
    p.time = t; packets.append(p); t += 0.010

    # 2. DNS Queries and Responses (10 packets)
    domains = ["lab.local", "api.service.net", "update.internal", "db.cluster", "monitor.sys"]
    for i, dom in enumerate(domains):
        sport = 50000 + i
        # Query
        p_q = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_dns) / UDP(sport=sport, dport=53) / DNS(
            id=100 + i, rd=1, qd=DNSQR(qname=dom)
        )
        p_q.time = t; packets.append(p_q); t += 0.008
        # Response
        p_r = Ether(src=mac_gw, dst=mac_client) / IP(src=ip_dns, dst=ip_client) / UDP(sport=53, dport=sport) / DNS(
            id=100 + i, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=dom), an=DNSRR(rrname=dom, rdata="192.168.1.100")
        )
        p_r.time = t; packets.append(p_r); t += 0.012

    # 3. HTTP Full Session (12 packets)
    c_port = 45000
    # 3-way handshake
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="S", seq=100)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_web, dst=ip_client) / TCP(sport=80, dport=c_port, flags="SA", seq=500, ack=101)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="A", seq=101, ack=501)
    p.time = t; packets.append(p); t += 0.005
    # HTTP GET Request
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="PA", seq=101, ack=501) / Raw(b"GET /index.html HTTP/1.1\r\nHost: 192.168.1.100\r\nUser-Agent: LabClient/1.0\r\n\r\n")
    p.time = t; packets.append(p); t += 0.003
    # Server ACK
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_web, dst=ip_client) / TCP(sport=80, dport=c_port, flags="A", seq=501, ack=175)
    p.time = t; packets.append(p); t += 0.005
    # Server Response Data (Part 1 & 2)
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_web, dst=ip_client) / TCP(sport=80, dport=c_port, flags="PA", seq=501, ack=175) / Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>Lab Server OK</h1></body></html>")
    p.time = t; packets.append(p); t += 0.003
    # Client ACK
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="A", seq=175, ack=620)
    p.time = t; packets.append(p); t += 0.010
    # Teardown FIN/ACK
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="FA", seq=175, ack=620)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_web, dst=ip_client) / TCP(sport=80, dport=c_port, flags="A", seq=620, ack=176)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_web, dst=ip_client) / TCP(sport=80, dport=c_port, flags="FA", seq=620, ack=176)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_web) / TCP(sport=c_port, dport=80, flags="A", seq=176, ack=621)
    p.time = t; packets.append(p); t += 0.015

    # 4. HTTPS / TLS 1.3 Traffic (20 packets)
    https_port = 45100
    p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_ext) / TCP(sport=https_port, dport=443, flags="S", seq=1000)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_gw, dst=mac_client) / IP(src=ip_ext, dst=ip_client) / TCP(sport=443, dport=https_port, flags="SA", seq=5000, ack=1001)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_ext) / TCP(sport=https_port, dport=443, flags="A", seq=1001, ack=5001)
    p.time = t; packets.append(p); t += 0.005
    # Client Hello (TLS Handshake record)
    p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_ext) / TCP(sport=https_port, dport=443, flags="PA", seq=1001, ack=5001) / Raw(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + b"\x42" * 160)
    p.time = t; packets.append(p); t += 0.004
    # Server Hello & TLS Data records
    for step in range(8):
        p = Ether(src=mac_gw, dst=mac_client) / IP(src=ip_ext, dst=ip_client) / TCP(sport=443, dport=https_port, flags="PA", seq=5001 + step * 200, ack=1170) / Raw(b"\x17\x03\x03\x00\xc8" + b"\x55" * 195)
        p.time = t; packets.append(p); t += 0.003
        p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_ext) / TCP(sport=https_port, dport=443, flags="A", seq=1170, ack=5001 + (step + 1) * 200)
        p.time = t; packets.append(p); t += 0.003

    # 5. SSH Sessions (16 packets)
    ssh_port = 45200
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_ssh) / TCP(sport=ssh_port, dport=22, flags="S", seq=2000)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_ssh, dst=ip_client) / TCP(sport=22, dport=ssh_port, flags="SA", seq=7000, ack=2001)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_ssh) / TCP(sport=ssh_port, dport=22, flags="A", seq=2001, ack=7001)
    p.time = t; packets.append(p); t += 0.005
    # SSH Identification strings
    p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_ssh, dst=ip_client) / TCP(sport=22, dport=ssh_port, flags="PA", seq=7001, ack=2001) / Raw(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    p.time = t; packets.append(p); t += 0.003
    p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_ssh) / TCP(sport=ssh_port, dport=22, flags="PA", seq=2001, ack=7043) / Raw(b"SSH-2.0-OpenSSH_8.9p1\r\n")
    p.time = t; packets.append(p); t += 0.005
    # SSH Key Exchange packets
    for step in range(5):
        p = Ether(src=mac_server, dst=mac_client) / IP(src=ip_ssh, dst=ip_client) / TCP(sport=22, dport=ssh_port, flags="PA", seq=7043 + step * 100, ack=2024) / Raw(b"\x00\x00\x00\x5c" + b"\x99" * 92)
        p.time = t; packets.append(p); t += 0.004
        p = Ether(src=mac_client, dst=mac_server) / IP(src=ip_client, dst=ip_ssh) / TCP(sport=ssh_port, dport=22, flags="A", seq=2024, ack=7043 + (step + 1) * 100)
        p.time = t; packets.append(p); t += 0.004

    # 6. NTP Traffic (6 packets)
    for i in range(3):
        # Client NTP request (Mode 3)
        p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst=ip_ntp) / UDP(sport=123, dport=123) / Raw(b"\x23\x00\x00\x00" + b"\x00" * 44)
        p.time = t; packets.append(p); t += 0.015
        # Server NTP response (Mode 4)
        p = Ether(src=mac_gw, dst=mac_client) / IP(src=ip_ntp, dst=ip_client) / UDP(sport=123, dport=123) / Raw(b"\x24\x01\x00\xec" + b"\x00" * 44)
        p.time = t; packets.append(p); t += 0.020

    # 7. ICMP Echo Request / Reply (20 packets)
    for seq in range(1, 11):
        # Ping request
        p = Ether(src=mac_client, dst=mac_gw) / IP(src=ip_client, dst="8.8.8.8") / ICMP(type=8, code=0, id=1234, seq=seq) / Raw(b"PingPayload" + bytes([seq]))
        p.time = t; packets.append(p); t += 0.010
        # Ping reply
        p = Ether(src=mac_gw, dst=mac_client) / IP(src="8.8.8.8", dst=ip_client) / ICMP(type=0, code=0, id=1234, seq=seq) / Raw(b"PingPayload" + bytes([seq]))
        p.time = t; packets.append(p); t += 0.010

    # 8. IPv6 Traffic (TCP, UDP, ICMPv6) (20 packets)
    ipv6_client = "2001:db8:acad:1::50"
    ipv6_server = "2001:db8:acad:1::100"
    # IPv6 TCP Handshake & Data
    v6_port = 56000
    p = Ether(src=mac_client, dst=mac_server) / IPv6(src=ipv6_client, dst=ipv6_server) / TCP(sport=v6_port, dport=80, flags="S", seq=3000)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_server, dst=mac_client) / IPv6(src=ipv6_server, dst=ipv6_client) / TCP(sport=80, dport=v6_port, flags="SA", seq=8000, ack=3001)
    p.time = t; packets.append(p); t += 0.002
    p = Ether(src=mac_client, dst=mac_server) / IPv6(src=ipv6_client, dst=ipv6_server) / TCP(sport=v6_port, dport=80, flags="A", seq=3001, ack=8001)
    p.time = t; packets.append(p); t += 0.005
    p = Ether(src=mac_client, dst=mac_server) / IPv6(src=ipv6_client, dst=ipv6_server) / TCP(sport=v6_port, dport=80, flags="PA", seq=3001, ack=8001) / Raw(b"GET /ipv6 HTTP/1.1\r\nHost: ipv6.lab\r\n\r\n")
    p.time = t; packets.append(p); t += 0.005
    p = Ether(src=mac_server, dst=mac_client) / IPv6(src=ipv6_server, dst=ipv6_client) / TCP(sport=80, dport=v6_port, flags="PA", seq=8001, ack=3038) / Raw(b"HTTP/1.1 200 OK\r\n\r\nIPv6 Response")
    p.time = t; packets.append(p); t += 0.005
    # IPv6 UDP DNS
    p = Ether(src=mac_client, dst=mac_server) / IPv6(src=ipv6_client, dst=ipv6_server) / UDP(sport=56001, dport=53) / DNS(id=500, rd=1, qd=DNSQR(qname="ipv6.lab"))
    p.time = t; packets.append(p); t += 0.005
    p = Ether(src=mac_server, dst=mac_client) / IPv6(src=ipv6_server, dst=ipv6_client) / UDP(sport=53, dport=56001) / DNS(id=500, qr=1, aa=1, rd=1, qd=DNSQR(qname="ipv6.lab", qtype="AAAA"), an=DNSRR(rrname="ipv6.lab", type="AAAA", rdata="2001:db8:acad:1::100"))
    p.time = t; packets.append(p); t += 0.005
    # ICMPv6 Echo Request & Reply
    for s in range(1, 6):
        p = Ether(src=mac_client, dst=mac_server) / IPv6(src=ipv6_client, dst=ipv6_server) / ICMPv6EchoRequest(id=77, seq=s, data=b"ICMPv6LabData")
        p.time = t; packets.append(p); t += 0.008
        p = Ether(src=mac_server, dst=mac_client) / IPv6(src=ipv6_server, dst=ipv6_client) / ICMPv6EchoReply(id=77, seq=s, data=b"ICMPv6LabData")
        p.time = t; packets.append(p); t += 0.008

    # 9. Non-IP Frames (LLDP and raw Ethernet) (6 packets)
    for i in range(3):
        p = Ether(src=mac_client, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(f"LLDP_LAB_ANNOUNCE_{i}".encode())
        p.time = t; packets.append(p); t += 0.020
        p = Ether(src=mac_server, dst=mac_bcast, type=0x8906) / Raw(f"FCOE_INITIALIZATION_{i}".encode())
        p.time = t; packets.append(p); t += 0.020

    wrpcap(path, packets)
    return path


def generate_benchmark_large_pcap(fixtures_dir: str, num_packets: int = 5000) -> str:
    """Generate tests/fixtures/benchmark_large.pcap containing realistic packets
    designed for high-throughput database insertion benchmarks (T08).
    """
    path = os.path.join(fixtures_dir, "benchmark_large.pcap")
    packets = []
    base_ts = 1700010000.0

    mac_a = "00:11:22:33:44:01"
    mac_b = "00:11:22:33:44:02"

    # Pre-generate a varied pool of 100 prototype packets
    prototype_pool = []
    for i in range(100):
        c_ip = f"192.168.1.{10 + (i % 40)}"
        s_ip = f"10.0.0.{1 + (i % 20)}"
        proto_type = i % 5

        if proto_type in (0, 1):  # TCP traffic
            sport = 30000 + (i * 7) % 30000
            dport = 80 if (i % 2 == 0) else 443
            pkt = (
                Ether(src=mac_a, dst=mac_b)
                / IP(src=c_ip, dst=s_ip)
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(b"BENCHMARK_TCP_DATA_STREAM_" + bytes([i % 256]) * 32)
            )
        elif proto_type in (2, 3):  # UDP traffic (DNS, Syslog, SNMP)
            sport = 40000 + (i * 11) % 20000
            dport = 53 if (i % 2 == 0) else 514
            pkt = (
                Ether(src=mac_a, dst=mac_b)
                / IP(src=c_ip, dst=s_ip)
                / UDP(sport=sport, dport=dport)
                / Raw(b"BENCHMARK_UDP_DATAGRAM_PAYLOAD_" + bytes([i % 256]) * 16)
            )
        else:  # ICMP traffic
            pkt = (
                Ether(src=mac_a, dst=mac_b)
                / IP(src=c_ip, dst=s_ip)
                / ICMP(type=8, code=0, id=100 + i, seq=i)
                / Raw(b"PING_BENCHMARK_PAYLOAD_" + bytes([i % 256]) * 8)
            )
        prototype_pool.append(pkt)

    # Replicate prototype pool with evolving timestamps up to num_packets
    for i in range(num_packets):
        proto_idx = i % len(prototype_pool)
        p = prototype_pool[proto_idx].copy()
        p.time = base_ts + (i * 0.005)
        packets.append(p)

    wrpcap(path, packets)
    return path


def generate_all_fixtures() -> dict[str, str]:
    """Generate all test fixtures and return dictionary of paths."""
    fixtures_dir = ensure_fixtures_dir()
    print(f"Generating fixtures in {fixtures_dir}...")

    results = {}
    results["known_packets"] = generate_known_packets_pcap(fixtures_dir)
    print(f"Created: {results['known_packets']}")

    results["non_ip"] = generate_non_ip_pcap(fixtures_dir)
    print(f"Created: {results['non_ip']}")

    results["empty"] = generate_empty_pcap(fixtures_dir)
    print(f"Created: {results['empty']}")

    results["corrupted"] = generate_corrupted_pcap(fixtures_dir)
    print(f"Created: {results['corrupted']}")

    results["sample_lab"] = generate_sample_lab_pcap(fixtures_dir)
    print(f"Created: {results['sample_lab']}")

    results["benchmark_large"] = generate_benchmark_large_pcap(fixtures_dir, num_packets=5000)
    print(f"Created: {results['benchmark_large']}")

    print("All fixtures generated successfully.")
    return results


if __name__ == "__main__":
    generate_all_fixtures()

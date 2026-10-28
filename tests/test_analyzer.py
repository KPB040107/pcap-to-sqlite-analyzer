"""Automated test suite for PCAP to SQLite Network Traffic Analyzer.

Tests all acceptance criteria defined in the project specification:
- T01: Valid PCAP import (Database packet count equals parser count)
- T02: Known TCP and UDP packets (Protocol, endpoints, ports, lengths match expected values)
- T03: Packets without IP or ports (Import succeeds with null fields where appropriate)
- T04: Malformed or unsupported file (Clear error raised/recorded, no misleading completed status)
- T05: Repeat import of same file (Duplicate handling follows policy: skip or overwrite)
- T06: Host, protocol, port, and time filters (Queries return exact matching rows)
- T07: CSV export (Exported rows match the visible filtered query)
"""

from __future__ import annotations

import csv
import io
import os
import sqlite3
import pytest

from pcap_analyzer.database import (
    init_db,
    get_connection,
    get_capture_by_id,
    get_all_captures,
    get_capture_summary,
    get_top_endpoints,
    query_packets,
)
from pcap_analyzer.parser import parse_pcap
from pcap_analyzer.importer import (
    import_pcap,
    validate_pcap_file,
    compute_sha256,
)
from pcap_analyzer.exporter import (
    export_packets_to_csv,
    CSV_HEADERS,
)

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


@pytest.fixture(scope="session", autouse=True)
def ensure_fixtures():
    """Ensure all required fixture files exist before running tests."""
    from generate_fixtures import generate_all_fixtures
    required = [
        "known_packets.pcap",
        "sample_lab.pcap",
        "non_ip.pcap",
        "empty.pcap",
        "corrupted.pcap",
        "benchmark_large.pcap",
    ]
    missing = [f for f in required if not os.path.exists(os.path.join(FIXTURES_DIR, f))]
    if missing:
        generate_all_fixtures()


@pytest.fixture
def temp_db(tmp_path):
    """Provide a fresh SQLite database path for test isolation."""
    db_file = tmp_path / "test_traffic.sqlite"
    return str(db_file)


# ---------------------------------------------------------------------------
# T01: Valid PCAP import
# ---------------------------------------------------------------------------
def test_t01_valid_pcap_import(temp_db):
    """T01: Valid PCAP import.
    Acceptance criterion: Database packet count equals parser count.
    """
    pcap_path = os.path.join(FIXTURES_DIR, "sample_lab.pcap")
    assert os.path.exists(pcap_path), "sample_lab.pcap must exist"

    # Count packets using parser directly
    parser_total = sum(len(batch) for batch, _ in parse_pcap(pcap_path))
    assert parser_total > 0, "Parser must decode packets from valid lab capture"

    # Execute import
    summary = import_pcap(file_path=pcap_path, db_path=temp_db)

    assert summary["status"] == "completed"
    assert summary["duplicate"] is False
    assert summary["packet_count"] == parser_total
    assert summary["error_count"] == 0

    capture_id = summary["capture_id"]

    # Verify directly against database
    with get_connection(temp_db) as conn:
        cur = conn.execute("SELECT COUNT(*) AS cnt FROM packets WHERE capture_id = ?", (capture_id,))
        db_count = cur.fetchone()["cnt"]
        assert db_count == parser_total, f"DB packet count ({db_count}) != parser count ({parser_total})"

        # Verify capture record
        cap_cur = conn.execute("SELECT * FROM captures WHERE capture_id = ?", (capture_id,))
        cap_row = cap_cur.fetchone()
        assert cap_row["status"] == "completed"
        assert cap_row["packet_count"] == parser_total
        assert cap_row["error_count"] == 0


# ---------------------------------------------------------------------------
# T02: Known TCP and UDP packets
# ---------------------------------------------------------------------------
def test_t02_known_packets(temp_db):
    """T02: Known TCP and UDP packets.
    Acceptance criterion: Protocol, addresses, ports and lengths match expected values.
    """
    pcap_path = os.path.join(FIXTURES_DIR, "known_packets.pcap")
    summary = import_pcap(file_path=pcap_path, db_path=temp_db)

    assert summary["status"] == "completed"
    assert summary["packet_count"] == 5

    rows, total = query_packets(temp_db, summary["capture_id"], page=1, page_size=10)
    assert total == 5
    assert len(rows) == 5

    # Packet 1: TCP HTTP GET
    p1 = rows[0]
    assert p1["packet_number"] == 1
    assert p1["protocol"] == "TCP"
    assert p1["src_ip"] == "192.168.1.10"
    assert p1["dst_ip"] == "93.184.216.34"
    assert p1["src_port"] == 44321
    assert p1["dst_port"] == 80
    assert p1["length_bytes"] == 91

    # Packet 2: TCP HTTP 200 OK
    p2 = rows[1]
    assert p2["packet_number"] == 2
    assert p2["protocol"] == "TCP"
    assert p2["src_ip"] == "93.184.216.34"
    assert p2["dst_ip"] == "192.168.1.10"
    assert p2["src_port"] == 80
    assert p2["dst_port"] == 44321
    assert p2["length_bytes"] == 106

    # Packet 3: UDP DNS Query
    p3 = rows[2]
    assert p3["packet_number"] == 3
    assert p3["protocol"] == "UDP"
    assert p3["src_ip"] == "192.168.1.10"
    assert p3["dst_ip"] == "8.8.8.8"
    assert p3["src_port"] == 55123
    assert p3["dst_port"] == 53
    assert p3["length_bytes"] == 71

    # Packet 4: UDP DNS Response
    p4 = rows[3]
    assert p4["packet_number"] == 4
    assert p4["protocol"] == "UDP"
    assert p4["src_ip"] == "8.8.8.8"
    assert p4["dst_ip"] == "192.168.1.10"
    assert p4["src_port"] == 53
    assert p4["dst_port"] == 55123
    assert p4["length_bytes"] == 98

    # Packet 5: ICMP Echo Request
    p5 = rows[4]
    assert p5["packet_number"] == 5
    assert p5["protocol"] == "ICMP"
    assert p5["src_ip"] == "192.168.1.10"
    assert p5["dst_ip"] == "1.1.1.1"
    assert p5["src_port"] is None
    assert p5["dst_port"] is None
    assert p5["length_bytes"] == 57


# ---------------------------------------------------------------------------
# T03: Packet without IP or ports
# ---------------------------------------------------------------------------
def test_t03_packet_without_ip_or_ports(temp_db):
    """T03: Packet without IP or ports.
    Acceptance criterion: Import succeeds with null fields where appropriate in non_ip.pcap.
    """
    pcap_path = os.path.join(FIXTURES_DIR, "non_ip.pcap")
    summary = import_pcap(file_path=pcap_path, db_path=temp_db)

    assert summary["status"] == "completed"
    assert summary["packet_count"] == 4
    assert summary["error_count"] == 0

    rows, total = query_packets(temp_db, summary["capture_id"], page=1, page_size=10)
    assert total == 4

    # Packets 1 & 2: ARP frames - have ARP IPs, but ports MUST be NULL
    p1 = rows[0]
    p2 = rows[1]
    assert p1["protocol"] == "ARP"
    assert p1["src_port"] is None
    assert p1["dst_port"] is None
    assert p2["protocol"] == "ARP"
    assert p2["src_port"] is None
    assert p2["dst_port"] is None

    # Packets 3 & 4: Raw Ethernet frames - IP addresses and ports MUST be NULL
    p3 = rows[2]
    p4 = rows[3]
    assert p3["src_ip"] is None
    assert p3["dst_ip"] is None
    assert p3["src_port"] is None
    assert p3["dst_port"] is None
    assert p3["length_bytes"] > 0

    assert p4["src_ip"] is None
    assert p4["dst_ip"] is None
    assert p4["src_port"] is None
    assert p4["dst_port"] is None
    assert p4["length_bytes"] > 0


# ---------------------------------------------------------------------------
# T04: Malformed or unsupported file
# ---------------------------------------------------------------------------
def test_t04_empty_file_rejected(temp_db):
    """T04: Empty file validation.
    Acceptance criterion: Clear error raised, no misleading completed capture record.
    """
    init_db(temp_db)
    empty_path = os.path.join(FIXTURES_DIR, "empty.pcap")
    with pytest.raises(ValueError) as excinfo:
        import_pcap(file_path=empty_path, db_path=temp_db)

    assert "empty" in str(excinfo.value).lower()

    # Ensure no capture record was written or marked completed
    with get_connection(temp_db) as conn:
        cur = conn.execute("SELECT COUNT(*) AS cnt FROM captures WHERE status = 'completed'")
        assert cur.fetchone()["cnt"] == 0


def test_t04_corrupted_header_rejected(temp_db):
    """T04: Corrupted file header validation.
    Acceptance criterion: Clear error raised, invalid header detected, no completed capture.
    """
    init_db(temp_db)
    corrupted_path = os.path.join(FIXTURES_DIR, "corrupted.pcap")
    with pytest.raises(ValueError) as excinfo:
        import_pcap(file_path=corrupted_path, db_path=temp_db)

    assert "magic" in str(excinfo.value).lower() or "header" in str(excinfo.value).lower()

    with get_connection(temp_db) as conn:
        cur = conn.execute("SELECT COUNT(*) AS cnt FROM captures WHERE status = 'completed'")
        assert cur.fetchone()["cnt"] == 0


def test_t04_nonexistent_file(temp_db):
    """T04: Nonexistent file error handling."""
    missing_path = os.path.join(FIXTURES_DIR, "does_not_exist.pcap")
    with pytest.raises(FileNotFoundError):
        import_pcap(file_path=missing_path, db_path=temp_db)


# ---------------------------------------------------------------------------
# T05: Repeat import of same file
# ---------------------------------------------------------------------------
def test_t05_repeat_import_duplicate_policy(temp_db):
    """T05: Repeat import of same file.
    Acceptance criterion: Duplicate handling follows selected policy (skip or overwrite).
    """
    pcap_path = os.path.join(FIXTURES_DIR, "known_packets.pcap")

    # 1. First import
    res1 = import_pcap(file_path=pcap_path, db_path=temp_db)
    assert res1["status"] == "completed"
    assert res1["duplicate"] is False
    cap_id1 = res1["capture_id"]

    # Verify captures table has 1 record
    caps = get_all_captures(temp_db)
    assert len(caps) == 1

    # 2. Second import with default 'skip' policy
    res2 = import_pcap(file_path=pcap_path, db_path=temp_db, duplicate_policy="skip")
    assert res2["status"] == "skipped"
    assert res2["duplicate"] is True
    assert res2["capture_id"] == cap_id1

    # Verify captures count remains 1 and packets count remains 5
    caps_after_skip = get_all_captures(temp_db)
    assert len(caps_after_skip) == 1
    rows, total = query_packets(temp_db, cap_id1)
    assert total == 5

    # 3. Third import with 'overwrite' policy
    res3 = import_pcap(file_path=pcap_path, db_path=temp_db, duplicate_policy="overwrite")
    assert res3["status"] == "completed"
    assert res3["duplicate"] is False
    cap_id3 = res3["capture_id"]

    # Captures count remains 1 (old one replaced)
    caps_after_overwrite = get_all_captures(temp_db)
    assert len(caps_after_overwrite) == 1
    rows3, total3 = query_packets(temp_db, cap_id3)
    assert total3 == 5


# ---------------------------------------------------------------------------
# T06: Host, protocol, port and time filters
# ---------------------------------------------------------------------------
def test_t06_query_filters(temp_db):
    """T06: Host, protocol, port and time filters.
    Acceptance criterion: Querying with filters returns exact expected rows.
    """
    pcap_path = os.path.join(FIXTURES_DIR, "known_packets.pcap")
    res = import_pcap(file_path=pcap_path, db_path=temp_db)
    cid = res["capture_id"]

    # Filter 1: Protocol
    tcp_rows, tcp_cnt = query_packets(temp_db, cid, protocol="TCP")
    assert tcp_cnt == 2
    assert {r["packet_number"] for r in tcp_rows} == {1, 2}

    udp_rows, udp_cnt = query_packets(temp_db, cid, protocol="UDP")
    assert udp_cnt == 2
    assert {r["packet_number"] for r in udp_rows} == {3, 4}

    icmp_rows, icmp_cnt = query_packets(temp_db, cid, protocol="ICMP")
    assert icmp_cnt == 1
    assert icmp_rows[0]["packet_number"] == 5

    # Filter 2: Host / IP (matches either src or dst)
    host_rows, host_cnt = query_packets(temp_db, cid, ip="93.184.216.34")
    assert host_cnt == 2
    assert {r["packet_number"] for r in host_rows} == {1, 2}

    dns_rows, dns_cnt = query_packets(temp_db, cid, ip="8.8.8.8")
    assert dns_cnt == 2
    assert {r["packet_number"] for r in dns_rows} == {3, 4}

    client_rows, client_cnt = query_packets(temp_db, cid, ip="192.168.1.10")
    assert client_cnt == 5

    # Filter 3: Port (matches either src or dst)
    port80_rows, port80_cnt = query_packets(temp_db, cid, port=80)
    assert port80_cnt == 2
    assert {r["packet_number"] for r in port80_rows} == {1, 2}

    port53_rows, port53_cnt = query_packets(temp_db, cid, port=53)
    assert port53_cnt == 2
    assert {r["packet_number"] for r in port53_rows} == {3, 4}

    unmatched_rows, unmatched_cnt = query_packets(temp_db, cid, port=9999)
    assert unmatched_cnt == 0
    assert len(unmatched_rows) == 0

    # Filter 4: Time interval
    # Packet timestamps: p1=1700000000.0, p2=1700000000.05, p3=1700000001.0, p4=1700000001.02, p5=1700000002.0
    time_rows, time_cnt = query_packets(temp_db, cid, start_time=1700000000.5, end_time=1700000001.5)
    assert time_cnt == 2
    assert {r["packet_number"] for r in time_rows} == {3, 4}

    # Combined Filter: protocol=TCP, port=80, ip=93.184.216.34
    comb_rows, comb_cnt = query_packets(
        temp_db, cid, protocol="TCP", port=80, ip="93.184.216.34"
    )
    assert comb_cnt == 2


# ---------------------------------------------------------------------------
# T07: CSV export
# ---------------------------------------------------------------------------
def test_t07_csv_export(temp_db, tmp_path):
    """T07: CSV export.
    Acceptance criterion: Exported rows equal the visible filtered selection.
    """
    pcap_path = os.path.join(FIXTURES_DIR, "known_packets.pcap")
    res = import_pcap(file_path=pcap_path, db_path=temp_db)
    cid = res["capture_id"]

    # Filter by TCP
    filters = {"protocol": "TCP"}
    filtered_rows, count = query_packets(temp_db, cid, protocol="TCP")
    assert count == 2

    # Export to StringIO buffer
    buf = io.StringIO()
    exported_count = export_packets_to_csv(temp_db, cid, filters=filters, output_file_or_buffer=buf)
    assert exported_count == 2

    csv_string = buf.getvalue()
    assert len(csv_string) > 0

    reader = csv.DictReader(io.StringIO(csv_string))
    exported_records = list(reader)

    # Acceptance check: exported count matches filtered selection
    assert len(exported_records) == len(filtered_rows) == 2

    # Check headers
    assert reader.fieldnames == CSV_HEADERS

    # Check values in rows
    assert exported_records[0]["packet_number"] == "1"
    assert exported_records[0]["protocol"] == "TCP"
    assert exported_records[0]["src_ip"] == "192.168.1.10"
    assert exported_records[0]["dst_ip"] == "93.184.216.34"
    assert exported_records[0]["src_port"] == "44321"
    assert exported_records[0]["dst_port"] == "80"

    assert exported_records[1]["packet_number"] == "2"
    assert exported_records[1]["protocol"] == "TCP"
    assert exported_records[1]["src_ip"] == "93.184.216.34"
    assert exported_records[1]["dst_ip"] == "192.168.1.10"
    assert exported_records[1]["src_port"] == "80"
    assert exported_records[1]["dst_port"] == "44321"

    # Export directly to file and verify
    csv_file_path = str(tmp_path / "export_test.csv")
    exported_file_count = export_packets_to_csv(
        temp_db, cid, filters=filters, output_file_or_buffer=csv_file_path
    )
    assert exported_file_count == 2
    assert os.path.exists(csv_file_path)
    with open(csv_file_path, "r", encoding="utf-8") as f:
        file_lines = f.readlines()
    assert len(file_lines) == 3  # Header + 2 data rows


# ---------------------------------------------------------------------------
# Additional Unit Tests: Summaries, Top Endpoints, Pagination
# ---------------------------------------------------------------------------
def test_capture_summary_and_endpoints(temp_db):
    """Test protocol aggregation and top endpoints."""
    pcap_path = os.path.join(FIXTURES_DIR, "known_packets.pcap")
    res = import_pcap(file_path=pcap_path, db_path=temp_db)
    cid = res["capture_id"]

    summary = get_capture_summary(temp_db, cid)
    assert summary["total_packets"] == 5
    assert summary["tcp_count"] == 2
    assert summary["udp_count"] == 2
    assert summary["icmp_count"] == 1
    assert summary["other_count"] == 0

    endpoints = get_top_endpoints(temp_db, cid, limit=5)
    top_src = {item["ip"]: item["count"] for item in endpoints["top_src_ips"]}
    # 192.168.1.10 is src in packets 1, 3, 5 -> count 3
    assert top_src["192.168.1.10"] == 3


def test_pagination(temp_db):
    """Test pagination bounds and offsets."""
    pcap_path = os.path.join(FIXTURES_DIR, "sample_lab.pcap")
    res = import_pcap(file_path=pcap_path, db_path=temp_db)
    cid = res["capture_id"]
    total_pkts = res["packet_count"]

    page1, cnt = query_packets(temp_db, cid, page=1, page_size=20)
    assert cnt == total_pkts
    assert len(page1) == 20
    assert page1[0]["packet_number"] == 1
    assert page1[-1]["packet_number"] == 20

    page2, _ = query_packets(temp_db, cid, page=2, page_size=20)
    assert len(page2) == 20
    assert page2[0]["packet_number"] == 21

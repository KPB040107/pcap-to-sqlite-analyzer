"""Database access layer for PCAP to SQLite Network Traffic Analyzer.

Manages SQLite schema, captures, packet batch storage, and parameterized queries.
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

DEFAULT_DB_PATH = "traffic_analysis.sqlite"


def get_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Create and return a configured SQLite connection.
    
    Enables foreign keys and sets Row factory for convenient column access.
    """
    db_abs = os.path.abspath(db_path)
    os.makedirs(os.path.dirname(db_abs), exist_ok=True)
    conn = sqlite3.connect(db_abs)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


@contextmanager
def db_session(db_path: str = DEFAULT_DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a connection and guarantees closing upon exit."""
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initialize SQLite database tables and indexes."""
    with db_session(db_path) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS captures (
                    capture_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL UNIQUE,
                    file_size_bytes INTEGER NOT NULL,
                    imported_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0.0
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    packet_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    capture_id INTEGER NOT NULL REFERENCES captures(capture_id) ON DELETE CASCADE,
                    packet_number INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    timestamp_iso TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    length_bytes INTEGER NOT NULL,
                    summary TEXT,
                    FOREIGN KEY (capture_id) REFERENCES captures(capture_id) ON DELETE CASCADE
                );
            """)

            # Performance indexes on packets table
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_capture_id ON packets(capture_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(capture_id, timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(capture_id, src_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(capture_id, dst_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(capture_id, protocol);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_packets_dst_port ON packets(capture_id, dst_port);")


def find_capture_by_sha256(db_path: str, sha256: str) -> Optional[Dict[str, Any]]:
    """Look up a capture record by SHA-256 hash."""
    with db_session(db_path) as conn:
        cur = conn.execute("SELECT * FROM captures WHERE sha256 = ?", (sha256,))
        row = cur.fetchone()
        return dict(row) if row else None


def create_capture(db_path: str, filename: str, sha256: str, file_size_bytes: int) -> int:
    """Create a new capture record in 'incomplete' status and return its capture_id."""
    imported_at = datetime.now(timezone.utc).isoformat()
    with db_session(db_path) as conn:
        with conn:
            cur = conn.execute(
                """
                INSERT INTO captures (filename, sha256, file_size_bytes, imported_at, status)
                VALUES (?, ?, ?, ?, 'incomplete')
                """,
                (filename, sha256, file_size_bytes, imported_at),
            )
            return int(cur.lastrowid)


def update_capture_status(
    db_path: str,
    capture_id: int,
    status: str,
    packet_count: int,
    error_count: int,
    duration_seconds: float = 0.0,
) -> None:
    """Update capture status and metrics upon completion or failure."""
    with db_session(db_path) as conn:
        with conn:
            conn.execute(
                """
                UPDATE captures
                SET status = ?, packet_count = ?, error_count = ?, duration_seconds = ?
                WHERE capture_id = ?
                """,
                (status, packet_count, error_count, duration_seconds, capture_id),
            )


def delete_capture(db_path: str, capture_id: int) -> bool:
    """Delete a capture and its associated packets (via CASCADE)."""
    with db_session(db_path) as conn:
        with conn:
            cur = conn.execute("DELETE FROM captures WHERE capture_id = ?", (capture_id,))
            return cur.rowcount > 0


def insert_packets_batch(
    db_path: str,
    capture_id: int,
    packets_batch: List[Union[Dict[str, Any], Tuple[Any, ...]]],
) -> int:
    """Batch insert packets for a given capture_id using executemany inside a transaction.
    
    Accepts list of dictionaries or tuples.
    Returns count of inserted packets.
    """
    if not packets_batch:
        return 0

    tuples_to_insert: List[Tuple[Any, ...]] = []
    for item in packets_batch:
        if isinstance(item, dict):
            tuples_to_insert.append((
                capture_id,
                item["packet_number"],
                item["timestamp"],
                item["timestamp_iso"],
                item.get("src_ip"),
                item.get("dst_ip"),
                item["protocol"],
                item.get("src_port"),
                item.get("dst_port"),
                item["length_bytes"],
                item.get("summary"),
            ))
        elif isinstance(item, (list, tuple)):
            if len(item) == 11 and item[0] == capture_id:
                tuples_to_insert.append(tuple(item))
            elif len(item) == 10:
                tuples_to_insert.append((capture_id, *item))
            else:
                raise ValueError(f"Unexpected tuple length {len(item)} for packet insert")
        else:
            raise TypeError(f"Unsupported packet item type: {type(item)}")

    sql = """
        INSERT INTO packets (
            capture_id, packet_number, timestamp, timestamp_iso,
            src_ip, dst_ip, protocol, src_port, dst_port,
            length_bytes, summary
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    with db_session(db_path) as conn:
        with conn:
            conn.executemany(sql, tuples_to_insert)

    return len(tuples_to_insert)


def get_capture_by_id(db_path: str, capture_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve capture record by ID."""
    with db_session(db_path) as conn:
        cur = conn.execute("SELECT * FROM captures WHERE capture_id = ?", (capture_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_all_captures(db_path: str) -> List[Dict[str, Any]]:
    """Retrieve all capture records ordered newest first."""
    with db_session(db_path) as conn:
        cur = conn.execute("SELECT * FROM captures ORDER BY capture_id DESC")
        return [dict(row) for row in cur.fetchall()]


def get_capture_summary(db_path: str, capture_id: int) -> Dict[str, Any]:
    """Retrieve high-level statistical summary for a capture.
    
    Includes total packets, protocol breakdown (TCP, UDP, ICMP, other),
    time window (min_time, max_time), and error count.
    """
    capture = get_capture_by_id(db_path, capture_id)
    if not capture:
        return {}

    with db_session(db_path) as conn:
        cur = conn.execute(
            """
            SELECT
                COUNT(*) AS total_packets,
                SUM(CASE WHEN UPPER(protocol) = 'TCP' THEN 1 ELSE 0 END) AS tcp_count,
                SUM(CASE WHEN UPPER(protocol) = 'UDP' THEN 1 ELSE 0 END) AS udp_count,
                SUM(CASE WHEN UPPER(protocol) IN ('ICMP', 'ICMPV6') THEN 1 ELSE 0 END) AS icmp_count,
                SUM(CASE WHEN UPPER(protocol) NOT IN ('TCP', 'UDP', 'ICMP', 'ICMPV6') THEN 1 ELSE 0 END) AS other_count,
                MIN(timestamp) AS min_time,
                MAX(timestamp) AS max_time,
                MIN(timestamp_iso) AS min_time_iso,
                MAX(timestamp_iso) AS max_time_iso,
                SUM(length_bytes) AS total_bytes
            FROM packets
            WHERE capture_id = ?
            """,
            (capture_id,),
        )
        stats = dict(cur.fetchone() or {})

    return {
        "capture_id": capture_id,
        "filename": capture["filename"],
        "sha256": capture["sha256"],
        "file_size_bytes": capture["file_size_bytes"],
        "imported_at": capture["imported_at"],
        "status": capture["status"],
        "duration_seconds": capture.get("duration_seconds", 0.0),
        "error_count": capture.get("error_count", 0),
        "total_packets": stats.get("total_packets") or 0,
        "tcp_count": stats.get("tcp_count") or 0,
        "udp_count": stats.get("udp_count") or 0,
        "icmp_count": stats.get("icmp_count") or 0,
        "other_count": stats.get("other_count") or 0,
        "min_time": stats.get("min_time"),
        "max_time": stats.get("max_time"),
        "min_time_iso": stats.get("min_time_iso"),
        "max_time_iso": stats.get("max_time_iso"),
        "total_bytes": stats.get("total_bytes") or 0,
    }


def get_top_endpoints(db_path: str, capture_id: int, limit: int = 5) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieve top source and destination IP endpoints for a capture."""
    with db_session(db_path) as conn:
        src_cur = conn.execute(
            """
            SELECT src_ip AS ip, COUNT(*) AS count
            FROM packets
            WHERE capture_id = ? AND src_ip IS NOT NULL AND src_ip != ''
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
            """,
            (capture_id, limit),
        )
        top_src_ips = [dict(r) for r in src_cur.fetchall()]

        dst_cur = conn.execute(
            """
            SELECT dst_ip AS ip, COUNT(*) AS count
            FROM packets
            WHERE capture_id = ? AND dst_ip IS NOT NULL AND dst_ip != ''
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT ?
            """,
            (capture_id, limit),
        )
        top_dst_ips = [dict(r) for r in dst_cur.fetchall()]

    return {
        "top_src_ips": top_src_ips,
        "top_dst_ips": top_dst_ips,
    }


def query_packets(
    db_path: str,
    capture_id: int,
    protocol: Optional[str] = None,
    ip: Optional[str] = None,
    port: Optional[Union[int, str]] = None,
    start_time: Optional[Union[float, str]] = None,
    end_time: Optional[Union[float, str]] = None,
    page: int = 1,
    page_size: int = 50,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Execute strictly parameterized query on packets table with pagination.
    
    Returns:
        (rows, total_matching_count)
    """
    where_clauses = ["capture_id = ?"]
    params: List[Any] = [capture_id]

    if protocol and protocol.strip():
        where_clauses.append("UPPER(protocol) = ?")
        params.append(protocol.strip().upper())

    if ip and ip.strip():
        ip_clean = ip.strip()
        where_clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.extend([ip_clean, ip_clean])

    if src_ip and str(src_ip).strip():
        where_clauses.append("src_ip = ?")
        params.append(str(src_ip).strip())

    if dst_ip and str(dst_ip).strip():
        where_clauses.append("dst_ip = ?")
        params.append(str(dst_ip).strip())

    if port is not None and str(port).strip():
        try:
            port_int = int(str(port).strip())
            where_clauses.append("(src_port = ? OR dst_port = ?)")
            params.extend([port_int, port_int])
        except ValueError:
            pass

    if start_time is not None and str(start_time).strip():
        st = str(start_time).strip()
        try:
            st_float = float(st)
            where_clauses.append("timestamp >= ?")
            params.append(st_float)
        except ValueError:
            where_clauses.append("timestamp_iso >= ?")
            params.append(st)

    if end_time is not None and str(end_time).strip():
        et = str(end_time).strip()
        try:
            et_float = float(et)
            where_clauses.append("timestamp <= ?")
            params.append(et_float)
        except ValueError:
            where_clauses.append("timestamp_iso <= ?")
            params.append(et)

    where_sql = " AND ".join(where_clauses)

    with db_session(db_path) as conn:
        count_sql = f"SELECT COUNT(*) AS total FROM packets WHERE {where_sql}"
        count_cur = conn.execute(count_sql, params)
        total_matching = int(count_cur.fetchone()["total"])

        safe_page = max(1, page)
        safe_size = max(1, min(page_size, 10000))
        offset = (safe_page - 1) * safe_size

        select_sql = f"""
            SELECT
                packet_id, capture_id, packet_number,
                timestamp, timestamp_iso,
                src_ip, dst_ip, protocol,
                src_port, dst_port,
                length_bytes, summary
            FROM packets
            WHERE {where_sql}
            ORDER BY packet_number ASC
            LIMIT ? OFFSET ?
        """
        rows_cur = conn.execute(select_sql, params + [safe_size, offset])
        rows = [dict(r) for r in rows_cur.fetchall()]

    return rows, total_matching

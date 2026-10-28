"""CSV Export module for PCAP packet query results.

Streams database records directly into CSV formats to support offline reporting.
"""

from __future__ import annotations

import csv
import io
import os
from typing import Any, Dict, Optional, TextIO, Union

from .database import db_session

CSV_HEADERS = [
    "packet_number",
    "timestamp_iso",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "length_bytes",
    "summary",
]


def export_packets_to_csv(
    db_path: str,
    capture_id: int,
    filters: Optional[Dict[str, Any]] = None,
    output_file_or_buffer: Union[str, os.PathLike, TextIO] = "export.csv",
    chunk_size: int = 1000,
) -> int:
    """Stream filtered packets from database directly to CSV.
    
    Args:
        db_path: Path to SQLite database.
        capture_id: ID of the capture.
        filters: Optional dict with keys: 'protocol', 'ip', 'port', 'start_time', 'end_time'.
        output_file_or_buffer: File path string or text-based stream.
        chunk_size: Batch size for database cursor fetching.
        
    Returns:
        Total number of exported packet rows.
    """
    filters = filters or {}
    where_clauses = ["capture_id = ?"]
    params = [capture_id]

    protocol = filters.get("protocol")
    if protocol and str(protocol).strip():
        where_clauses.append("UPPER(protocol) = ?")
        params.append(str(protocol).strip().upper())

    ip = filters.get("ip")
    if ip and str(ip).strip():
        ip_clean = str(ip).strip()
        where_clauses.append("(src_ip = ? OR dst_ip = ?)")
        params.extend([ip_clean, ip_clean])

    src_ip = filters.get("src_ip")
    if src_ip and str(src_ip).strip():
        where_clauses.append("src_ip = ?")
        params.append(str(src_ip).strip())

    dst_ip = filters.get("dst_ip")
    if dst_ip and str(dst_ip).strip():
        where_clauses.append("dst_ip = ?")
        params.append(str(dst_ip).strip())

    port = filters.get("port")
    if port is not None and str(port).strip():
        try:
            port_int = int(str(port).strip())
            where_clauses.append("(src_port = ? OR dst_port = ?)")
            params.extend([port_int, port_int])
        except ValueError:
            pass

    start_time = filters.get("start_time")
    if start_time is not None and str(start_time).strip():
        st = str(start_time).strip()
        try:
            st_float = float(st)
            where_clauses.append("timestamp >= ?")
            params.append(st_float)
        except ValueError:
            where_clauses.append("timestamp_iso >= ?")
            params.append(st)

    end_time = filters.get("end_time")
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
    select_sql = f"""
        SELECT
            packet_number, timestamp_iso,
            src_ip, dst_ip, protocol,
            src_port, dst_port,
            length_bytes, summary
        FROM packets
        WHERE {where_sql}
        ORDER BY packet_number ASC
    """

    def _write_records(writer_target: TextIO) -> int:
        writer = csv.writer(writer_target, lineterminator="\n")
        writer.writerow(CSV_HEADERS)
        row_count = 0

        with db_session(db_path) as conn:
            cur = conn.cursor()
            cur.execute(select_sql, params)
            while True:
                batch = cur.fetchmany(chunk_size)
                if not batch:
                    break
                for row in batch:
                    writer.writerow([
                        row["packet_number"],
                        row["timestamp_iso"],
                        row["src_ip"] if row["src_ip"] is not None else "",
                        row["dst_ip"] if row["dst_ip"] is not None else "",
                        row["protocol"],
                        row["src_port"] if row["src_port"] is not None else "",
                        row["dst_port"] if row["dst_port"] is not None else "",
                        row["length_bytes"],
                        row["summary"] if row["summary"] is not None else "",
                    ])
                    row_count += 1

        return row_count

    if isinstance(output_file_or_buffer, (str, os.PathLike)):
        out_path = os.path.abspath(str(output_file_or_buffer))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            return _write_records(f)
    else:
        return _write_records(output_file_or_buffer)

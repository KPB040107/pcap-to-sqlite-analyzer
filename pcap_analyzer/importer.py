"""Import pipeline for network packet captures.

Handles file validation, SHA-256 deduplication, chunked parsing,
batch SQLite insertion, and transaction logging.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Callable, Dict, Optional

from .database import (
    DEFAULT_DB_PATH,
    create_capture,
    delete_capture,
    find_capture_by_sha256,
    init_db,
    insert_packets_batch,
    update_capture_status,
)
from .parser import parse_pcap

VALID_MAGIC_NUMBERS = [
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (microsecond, LE)
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (microsecond, BE)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (LE)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (BE)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
]

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Calculate SHA-256 hex digest of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def validate_pcap_file(
    file_path: str,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
) -> None:
    """Validate existence, size limits, and magic bytes of a PCAP/PCAPNG file.
    
    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If file is empty, exceeds size limit, or has invalid magic header.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a regular file: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        raise ValueError(f"File is empty (0 bytes): {file_path}")

    if file_size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        current_mb = file_size / (1024 * 1024)
        raise ValueError(
            f"File size ({current_mb:.2f} MB) exceeds maximum allowed limit of {max_mb:.2f} MB"
        )

    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic not in VALID_MAGIC_NUMBERS:
        raise ValueError(
            f"Invalid capture header magic {magic.hex() if magic else 'empty'}. Expected standard PCAP or PCAPNG."
        )


def import_pcap(
    file_path: str,
    db_path: str = DEFAULT_DB_PATH,
    duplicate_policy: str = "skip",  # 'skip' or 'overwrite'
    batch_size: int = 1000,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE,
    progress_callback: Optional[Callable[[int], None]] = None,
) -> Dict[str, Any]:
    """Execute complete PCAP import pipeline into SQLite database.
    
    Args:
        file_path: Path to .pcap or .pcapng file.
        db_path: Path to target SQLite database.
        duplicate_policy: 'skip' to return existing record or 'overwrite' to re-import.
        batch_size: Number of packets inserted per batch transaction.
        max_size_bytes: Maximum permitted file size in bytes.
        progress_callback: Optional callable invoked with current packet count.
        
    Returns:
        Summary dict containing status, capture_id, packet_count, error_count, etc.
    """
    # 1. Validation
    validate_pcap_file(file_path, max_size_bytes=max_size_bytes)
    file_size = os.path.getsize(file_path)
    filename = os.path.basename(file_path)

    # 2. Database preparation
    init_db(db_path)

    # 3. SHA-256 and duplicate detection
    sha256 = compute_sha256(file_path)
    existing = find_capture_by_sha256(db_path, sha256)

    if existing:
        if existing["status"] == "completed":
            if duplicate_policy == "skip":
                return {
                    "status": "skipped",
                    "duplicate": True,
                    "capture_id": existing["capture_id"],
                    "filename": existing["filename"],
                    "sha256": sha256,
                    "file_size_bytes": existing["file_size_bytes"],
                    "imported_at": existing["imported_at"],
                    "packet_count": existing["packet_count"],
                    "error_count": existing["error_count"],
                    "duration_seconds": existing["duration_seconds"],
                    "message": f"Capture already imported on {existing['imported_at']} (ID: {existing['capture_id']}). Skipped.",
                }
            elif duplicate_policy == "overwrite":
                delete_capture(db_path, existing["capture_id"])
            else:
                raise ValueError(f"Unknown duplicate policy '{duplicate_policy}'. Expected 'skip' or 'overwrite'.")
        else:
            # Previous import incomplete or failed; remove and retry
            delete_capture(db_path, existing["capture_id"])

    # 4. Create new capture record in database
    capture_id = create_capture(db_path, filename, sha256, file_size)

    # 5. Stream packets, decode, and batch insert
    start_time = time.perf_counter()
    total_packets = 0
    total_errors = 0

    try:
        for batch, errors in parse_pcap(file_path, batch_size=batch_size):
            total_errors += errors
            if batch:
                insert_packets_batch(db_path, capture_id, batch)
                total_packets += len(batch)
                if progress_callback:
                    progress_callback(total_packets)

        elapsed = time.perf_counter() - start_time
        duration_seconds = round(elapsed, 3)

        update_capture_status(
            db_path=db_path,
            capture_id=capture_id,
            status="completed",
            packet_count=total_packets,
            error_count=total_errors,
            duration_seconds=duration_seconds,
        )

        return {
            "status": "completed",
            "duplicate": False,
            "capture_id": capture_id,
            "filename": filename,
            "sha256": sha256,
            "file_size_bytes": file_size,
            "packet_count": total_packets,
            "error_count": total_errors,
            "duration_seconds": duration_seconds,
            "message": f"Successfully imported {total_packets} packets ({total_errors} errors) in {duration_seconds}s.",
        }

    except Exception as exc:
        elapsed = time.perf_counter() - start_time
        duration_seconds = round(elapsed, 3)
        update_capture_status(
            db_path=db_path,
            capture_id=capture_id,
            status="failed",
            packet_count=total_packets,
            error_count=total_errors + 1,
            duration_seconds=duration_seconds,
        )
        raise RuntimeError(
            f"Import failed for {filename} after {total_packets} packets: {exc}"
        ) from exc

"""Packet parsing pipeline using Scapy offline streaming reader.

Processes PCAP and PCAPNG files iteratively without loading entire captures into memory.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

# Suppress Scapy verbose initialization logs
logging.getLogger("scapy").setLevel(logging.ERROR)
try:
    from scapy.config import conf
    conf.verb = 0
except ImportError:
    pass

from scapy.all import PcapReader, IP, IPv6, ARP, TCP, UDP, ICMP


def parse_packet_record(packet: Any, packet_number: int) -> Tuple[Optional[Dict[str, Any]], bool]:
    """Extract structured metadata from a single Scapy packet.
    
    Returns:
        (packet_dict, is_error)
    """
    try:
        # 1. Timestamp
        raw_time = getattr(packet, "time", None)
        if raw_time is not None:
            ts = float(raw_time)
        else:
            ts = 0.0

        try:
            timestamp_iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            timestamp_iso = datetime.now(timezone.utc).isoformat()

        # 2. Layer 3 (Network Layer)
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        protocol: str = "OTHER"

        if packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
            protocol = "IPv4"
        elif packet.haslayer(IPv6):
            src_ip = str(packet[IPv6].src)
            dst_ip = str(packet[IPv6].dst)
            protocol = "IPv6"
        elif packet.haslayer(ARP):
            protocol = "ARP"
            src_ip = str(packet[ARP].psrc) if hasattr(packet[ARP], "psrc") else None
            dst_ip = str(packet[ARP].pdst) if hasattr(packet[ARP], "pdst") else None
        else:
            # Non-IP / other L2 framing
            src_ip = None
            dst_ip = None
            protocol = packet.lastlayer().name if hasattr(packet, "lastlayer") else packet.__class__.__name__

        # 3. Layer 4 (Transport Layer) & Protocol Detection
        src_port: Optional[int] = None
        dst_port: Optional[int] = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            try:
                src_port = int(packet[TCP].sport)
                dst_port = int(packet[TCP].dport)
            except Exception:
                src_port = None
                dst_port = None
        elif packet.haslayer(UDP):
            protocol = "UDP"
            try:
                src_port = int(packet[UDP].sport)
                dst_port = int(packet[UDP].dport)
            except Exception:
                src_port = None
                dst_port = None
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = None
            dst_port = None
        elif any("ICMPv6" in getattr(cls, "__name__", "") for cls in packet.layers()):
            protocol = "ICMPv6"
            src_port = None
            dst_port = None
        elif protocol in ("IPv4", "IPv6"):
            # Check for other protocols carried by IP (e.g. IGMP, OSPF, GRE)
            if packet.haslayer(IP):
                payload = packet[IP].payload
                if payload and payload.name != "NoPayload":
                    protocol = payload.name.upper()
            elif packet.haslayer(IPv6):
                payload = packet[IPv6].payload
                if payload and payload.name != "NoPayload":
                    protocol = payload.name.upper()

        # 4. Length
        try:
            length_bytes = int(getattr(packet, "wirelen", len(packet)))
        except Exception:
            try:
                length_bytes = len(bytes(packet))
            except Exception:
                length_bytes = 0

        # 5. Summary
        try:
            summary = packet.summary()
        except Exception:
            summary = f"{protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        record = {
            "packet_number": packet_number,
            "timestamp": ts,
            "timestamp_iso": timestamp_iso,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "length_bytes": length_bytes,
            "summary": summary,
        }
        return record, False

    except Exception:
        # Fallback record on decode anomaly
        record = {
            "packet_number": packet_number,
            "timestamp": 0.0,
            "timestamp_iso": datetime.now(timezone.utc).isoformat(),
            "src_ip": None,
            "dst_ip": None,
            "protocol": "MALFORMED",
            "src_port": None,
            "dst_port": None,
            "length_bytes": 0,
            "summary": "Malformed or unparseable packet",
        }
        return record, True


def parse_pcap(
    file_path: str,
    batch_size: int = 1000,
) -> Generator[Tuple[List[Dict[str, Any]], int], None, None]:
    """Streaming generator yielding batches of parsed packet records and error counts.
    
    Yields:
        (batch_records, batch_error_count)
    """
    reader = None
    try:
        reader = PcapReader(file_path)
    except Exception as e:
        raise ValueError(f"Unable to open PCAP file {file_path}: {e}") from e

    current_batch: List[Dict[str, Any]] = []
    current_errors: int = 0
    packet_number: int = 0

    try:
        while True:
            try:
                pkt = reader.read_packet()
                if pkt is None:
                    break
            except EOFError:
                break
            except StopIteration:
                break
            except Exception:
                # Scapy error reading next raw packet
                packet_number += 1
                current_errors += 1
                malformed_record = {
                    "packet_number": packet_number,
                    "timestamp": 0.0,
                    "timestamp_iso": datetime.now(timezone.utc).isoformat(),
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": "MALFORMED",
                    "src_port": None,
                    "dst_port": None,
                    "length_bytes": 0,
                    "summary": "Packet read/decode error",
                }
                current_batch.append(malformed_record)
                if len(current_batch) >= batch_size:
                    yield current_batch, current_errors
                    current_batch = []
                    current_errors = 0
                continue

            packet_number += 1
            record, is_err = parse_packet_record(pkt, packet_number)
            if is_err:
                current_errors += 1
            current_batch.append(record)

            if len(current_batch) >= batch_size:
                yield current_batch, current_errors
                current_batch = []
                current_errors = 0

        # Yield any remaining packets
        if current_batch or current_errors > 0:
            yield current_batch, current_errors

    finally:
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

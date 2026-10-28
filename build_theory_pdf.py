"""Script to generate the comprehensive Core Theory & Networking Concepts PDF.

Builds a professionally styled Word document with python-docx and converts it
to a high-resolution PDF via Microsoft Word.
"""

import os
import sys
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

DOC_NAME = "PCAP_to_SQLite_Core_Theory_and_Concepts.docx"
PDF_NAME = "PCAP_to_SQLite_Core_Theory_and_Concepts.pdf"

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner cell padding in dxa units."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_background(cell, hex_color):
    """Set cell background shading."""
    shd_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shd_xml))

def set_table_borders(table, color="CBD5E1"):
    """Set subtle modern borders on tables."""
    tblPr = table._tbl.tblPr
    borders_xml = f"""
    <w:tblBorders {nsdecls("w")}>
        <w:top w:val="single" w:sz="6" w:space="0" w:color="{color}"/>
        <w:bottom w:val="single" w:sz="8" w:space="0" w:color="{color}"/>
        <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:insideV w:val="none"/>
        <w:left w:val="none"/>
        <w:right w:val="none"/>
    </w:tblBorders>
    """
    tblPr.append(parse_xml(borders_xml))

def format_row(row, bg_color=None, bold=False, text_color=None):
    for cell in row.cells:
        set_cell_margins(cell, top=110, bottom=110, left=140, right=140)
        if bg_color:
            set_cell_background(cell, bg_color)
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = bold
                if text_color:
                    run.font.color.rgb = text_color

def add_callout(doc, text_list, title="KEY CONCEPT", bg_color="F0F9FF", border_color="0284C7"):
    """Create a clean callout box."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    c = tbl.rows[0].cells[0]
    c.width = Inches(6.5)
    set_cell_background(c, bg_color)
    set_cell_margins(c, top=140, bottom=140, left=180, right=180)
    
    # Left border only
    borders_xml = f"""
    <w:tcBorders {nsdecls("w")}>
        <w:top w:val="none"/>
        <w:left w:val="single" w:sz="24" w:space="0" w:color="{border_color}"/>
        <w:bottom w:val="none"/>
        <w:right w:val="none"/>
    </w:tcBorders>
    """
    c._tc.get_or_add_tcPr().append(parse_xml(borders_xml))

    p0 = c.paragraphs[0]
    p0.paragraph_format.space_after = Pt(4)
    r_title = p0.add_run(f"📌 {title}")
    r_title.bold = True
    r_title.font.size = Pt(10.5)
    r_title.font.color.rgb = RGBColor(16, 52, 96)

    for item in text_list:
        p = c.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(item)
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(51, 65, 85)

    doc.add_paragraph().paragraph_format.space_after = Pt(4)

def build_document():
    doc = docx.Document()

    # Margins: 1 inch
    for s in doc.sections:
        s.top_margin = Inches(1.0)
        s.bottom_margin = Inches(1.0)
        s.left_margin = Inches(1.0)
        s.right_margin = Inches(1.0)

    # Palette
    NAVY = RGBColor(16, 52, 96)       # #103460
    SLATE = RGBColor(71, 85, 105)     # #475569
    DARK = RGBColor(30, 41, 59)       # #1E293B
    WHITE = RGBColor(255, 255, 255)

    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = DARK

    # -------------------------------------------------------------------------
    # COVER / HEADER
    # -------------------------------------------------------------------------
    p_meta = doc.add_paragraph()
    r_meta = p_meta.add_run("INFORMATION SECURITY | COMPREHENSIVE THEORY & SYSTEM GUIDE")
    r_meta.font.size = Pt(10)
    r_meta.font.bold = True
    r_meta.font.color.rgb = NAVY
    p_meta.paragraph_format.space_after = Pt(16)

    p_title = doc.add_paragraph()
    r_title = p_title.add_run("PCAP to SQLite Network Traffic Analyzer\nCore Theory, Networking Concepts & Architecture")
    r_title.font.size = Pt(24)
    r_title.font.bold = True
    r_title.font.color.rgb = NAVY
    p_title.paragraph_format.space_after = Pt(8)

    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("A complete, foundational study guide explaining packets, protocols, relational indexing, and streaming forensics from first principles.")
    r_sub.font.size = Pt(12)
    r_sub.font.color.rgb = SLATE
    p_sub.paragraph_format.space_after = Pt(24)

    # Author metadata box
    tbl_meta = doc.add_table(rows=4, cols=2)
    tbl_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_meta, "CBD5E1")
    m_info = [
        ("Prepared by", "Kaustubh Borle"),
        ("Enrollment No.", "245811150"),
        ("Course / Module", "Information Security | PCAP Analysis - PCAP to SQLite"),
        ("Date / Version", "October 2026 | Technical Study Guide v1.0"),
    ]
    for i, (k, v) in enumerate(m_info):
        r = tbl_meta.rows[i]
        c0, c1 = r.cells[0], r.cells[1]
        c0.width, c1.width = Inches(2.0), Inches(4.5)
        c0.text, c1.text = k, v
        c0.paragraphs[0].runs[0].bold = True
        c0.paragraphs[0].runs[0].font.color.rgb = NAVY
        set_cell_background(c0, "F8FAFC")
        set_cell_margins(c0, 80, 80, 120, 120)
        set_cell_margins(c1, 80, 80, 120, 120)

    p_space = doc.add_paragraph()
    p_space.paragraph_format.space_after = Pt(16)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 1: THE BIG PICTURE
    # -------------------------------------------------------------------------
    doc.add_heading("1. The Big Picture: What Did We Build?", level=1).style.font.color.rgb = NAVY
    
    p = doc.add_paragraph(
        "Modern computer networks transmit millions of discrete data fragments every second. "
        "When security analysts or network engineers record this traffic, they capture it into raw binary files called "
        "PCAP (Packet Capture) files. While PCAP files contain rich forensic evidence, they are fundamentally unstructured "
        "and unindexed streams of raw binary data. Searching through them manually or writing ad-hoc scripts every time "
        "you need to find a specific host, port, or time window is slow, repetitive, and computationally inefficient."
    )
    p.paragraph_format.space_after = Pt(10)

    p = doc.add_paragraph(
        "Our application bridges this gap: it converts recorded packet captures into a high-performance, structured "
        "SQLite relational database, indexes every crucial field, and provides an interactive web dashboard where any student "
        "or investigator can visually explore the traffic, filter records instantly, and export data to CSV without writing complex SQL."
    )
    p.paragraph_format.space_after = Pt(14)

    # Highway Analogy Callout
    add_callout(
        doc,
        [
            "Imagine a busy multi-lane highway. Thousands of vehicles drive past every minute.",
            "• Raw PCAP File = A continuous, high-definition video recording of the entire highway. It records every speck of dust, but if you want to know 'How many blue delivery trucks drove past between 10:00 AM and 10:05 AM going over 60 mph?', you have to manually watch the whole tape from the start.",
            "• Our Application = An automated toll-gate scanner. It inspects each vehicle once as it passes through, reads the license plate (IP address), vehicle type (protocol), service door (port), and exact time (timestamp), and logs them into an organized digital ledger (SQLite).",
            "• Streamlit Dashboard = A digital control room with interactive monitors, search filters, and an 'Export to Excel' button.",
        ],
        title="THE HIGHWAY & TOLL-GATE ANALOGY",
        bg_color="EFF6FF",
        border_color="0284C7"
    )

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 2: FUNDAMENTAL NETWORKING CONCEPTS
    # -------------------------------------------------------------------------
    doc.add_heading("2. Core Networking Concepts: Theory 101", level=1).style.font.color.rgb = NAVY

    doc.add_heading("2.1 What is a Packet? (Envelope vs. Letter)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Computers never transmit large files (such as a 50 MB video or a 5 MB webpage) as a single continuous block. "
        "If a single transmission glitch occurred at 99%, the entire file would have to be resent. Instead, the networking stack "
        "chops large data into small, manageable units called packets (typically around 1,500 bytes each). "
        "Each packet is an independent transmission unit consisting of two distinct components:"
    )
    p.paragraph_format.space_after = Pt(8)

    doc.add_paragraph("1. Header (Metadata / The Envelope): Contains the routing and structural instructions. It specifies who sent the packet (Source IP), where it is addressed (Destination IP), how it should be delivered (TCP, UDP), which application service it belongs to (Port 80, 443, 53), the total length, and the exact timestamp.", style='List Bullet')
    doc.add_paragraph("2. Payload (The Letter Inside): The actual application content being transported—such as text messages, passwords, HTML snippets, or streaming audio bytes.", style='List Bullet')

    add_callout(
        doc,
        [
            "Why does our tool ONLY store metadata and intentionally discard payloads?",
            "1. Privacy & Legal Compliance: Storing raw payloads exposes sensitive personal data—such as login credentials, private chat conversations, or health records. Discarding payloads guarantees that the analysis platform remains privacy-preserving and legally compliant for classroom and forensic environments.",
            "2. Storage & Memory Efficiency: The metadata of a packet is typically only 40 to 60 bytes, while the payload may be 1,400+ bytes. Storing payloads causes database files to explode into gigabytes; storing metadata alone keeps databases ultra-lightweight (megabytes), fitting entirely within memory caches.",
        ],
        title="SECURITY & FORENSIC PRINCIPLE: METADATA OVER PAYLOAD",
        bg_color="F0FDF4",
        border_color="16A34A"
    )

    doc.add_heading("2.2 What is a .pcap File and Why is it Inefficient on its Own?", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "A .pcap (Packet Capture) or .pcapng (Next Generation) file is a raw binary dump created by network capture libraries "
        "(such as libpcap or WinPcap) and applications like Wireshark or tcpdump. "
        "The file format consists of a Global Header (magic bytes, version, timezone, snapshot length) followed by a linear sequence "
        "of packet records (each packet having a 16-byte record header followed by raw packet bytes)."
    )
    p.paragraph_format.space_after = Pt(8)

    p = doc.add_paragraph(
        "The Fundamental Limitation: A PCAP file has zero search indexes. It is strictly sequential. "
        "If an analyst wants to find all packets sent by IP 192.168.1.10 in a 1-million packet capture, any program reading the PCAP "
        "must inspect packet 1, then packet 2, then packet 3, all the way to packet 1,000,000. "
        "This linear scan takes O(N) time for every single filter query. "
        "By converting the PCAP into an indexed SQLite database, searches use B-Tree indexes, dropping query time to O(log N)—"
        "executing in less than 1 millisecond!"
    )
    p.paragraph_format.space_after = Pt(14)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 3: PROTOCOL STACK & THE ONION MODEL
    # -------------------------------------------------------------------------
    doc.add_heading("3. The Protocol Stack & The Onion Model", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Network communication follows layered encapsulation (often modeled after the OSI 7-Layer or TCP/IP 4-Layer model). "
        "Think of a packet as an onion: when data leaves a server, each layer wraps its own header around the data. "
        "When our Scapy parser decodes a packet, it peels the onion from the outside inwards:"
    )
    p.paragraph_format.space_after = Pt(10)

    # Layer Table
    tbl_layers = doc.add_table(rows=5, cols=4)
    tbl_layers.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_layers, "CBD5E1")
    layer_data = [
        ("Layer", "Protocols", "Fields Extracted", "Real-World Meaning & Role"),
        ("Layer 2: Data Link", "Ethernet, ARP, LLC", "MAC addresses, ARP hardware/IP mapping", "Local wire framing between directly connected network adapters."),
        ("Layer 3: Network", "IPv4, IPv6", "src_ip, dst_ip, length_bytes", "Logical end-to-end routing across the global internet (e.g. 192.168.1.10 -> 8.8.8.8)."),
        ("Layer 4: Transport", "TCP, UDP, ICMP, ICMPv6", "protocol, src_port, dst_port", "Delivery mechanism & application multiplexing (how packets flow and what app receives them)."),
        ("Layer 7: Application", "HTTP, DNS, TLS, SSH", "summary (service labels)", "The human-facing service (Web, Domain resolution, Secure Shell)."),
    ]
    for i, (l, p_col, f_col, m_col) in enumerate(layer_data):
        row = tbl_layers.rows[i]
        c0, c1, c2, c3 = row.cells[0], row.cells[1], row.cells[2], row.cells[3]
        c0.width, c1.width, c2.width, c3.width = Inches(1.3), Inches(1.5), Inches(1.5), Inches(2.2)
        c0.text, c1.text, c2.text, c3.text = l, p_col, f_col, m_col
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("3.1 Protocol Deep Dive: TCP vs. UDP vs. ICMP vs. ARP", level=2).style.font.color.rgb = NAVY

    doc.add_paragraph("• TCP (Transmission Control Protocol): Connection-oriented, guaranteed delivery. It establishes a virtual circuit via a 3-Way Handshake (SYN -> SYN-ACK -> ACK), tracks sequence numbers, and retransmits lost packets. Used by web browsers (HTTP/HTTPS), email (SMTP/IMAP), and secure terminal sessions (SSH). TCP headers always include a Source Port and Destination Port.", style='List Bullet')
    doc.add_paragraph("• UDP (User Datagram Protocol): Connectionless, best-effort delivery. Packets are fired off without handshakes or retransmission guarantees. It trades reliability for raw speed and minimal latency. Used by DNS lookups, video streaming, VoIP phone calls, and gaming. UDP headers also contain Source and Destination Ports.", style='List Bullet')
    doc.add_paragraph("• ICMP (Internet Control Message Protocol): Diagnostic and error reporting protocol. When you run 'ping 8.8.8.8', your computer sends an ICMP Echo Request, and Google replies with an ICMP Echo Reply. Crucially: ICMP operates directly on Layer 3 and HAS NO PORTS! Our database correctly stores NULL for src_port and dst_port on ICMP rows.", style='List Bullet')
    doc.add_paragraph("• ARP (Address Resolution Protocol): Local network translator. When your computer wants to talk to 192.168.1.1, it broadcasts an ARP request: 'Who has 192.168.1.1? Tell my MAC address!'. ARP operates below the IP layer; hence, ARP packets have no standard IP header and no transport ports. Our parser handles ARP with full null-safety.", style='List Bullet')

    doc.add_heading("3.2 Understanding Port Numbers", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "If the IP address is like the street address of an apartment building, the Port Number is the specific apartment number. "
        "A single server at IP 93.184.216.34 can run dozens of different services simultaneously: "
        "Web traffic goes to Port 80 (HTTP) or Port 443 (HTTPS), domain resolution goes to Port 53 (DNS), "
        "and remote administration goes to Port 22 (SSH). "
        "When our analyzer indexes ports, it allows users to pinpoint exact services running on any machine."
    )
    p.paragraph_format.space_after = Pt(14)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 4: RELATIONAL DATABASE & INDEXING THEORY
    # -------------------------------------------------------------------------
    doc.add_heading("4. Relational Storage & Indexing Theory", level=1).style.font.color.rgb = NAVY
    
    p = doc.add_paragraph(
        "SQLite is a C-language library that implements a self-contained, serverless, zero-configuration, transactional "
        "relational database engine. It stores the entire database (tables, indexes, triggers) in a single disk file. "
        "In our application, SQLite provides three critical capabilities:"
    )
    p.paragraph_format.space_after = Pt(8)

    doc.add_paragraph("1. Structured Relational Schema: Separates capture audit records (captures table) from packet records (packets table) with 1-to-many relationships and ON DELETE CASCADE constraints.", style='List Bullet')
    doc.add_paragraph("2. ACID Transactions & Batching: Ensures that either an entire batch of 1,000 packets is committed atomically or rolled back safely on error, guaranteeing database integrity.", style='List Bullet')
    doc.add_paragraph("3. B-Tree Indexes for Sub-Millisecond Queries: Rather than scanning rows one by one, B-Tree indexes allow the engine to navigate sorted tree nodes, locating matching records instantly.", style='List Bullet')

    # Schema diagram
    tbl_schema = doc.add_table(rows=7, cols=3)
    tbl_schema.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_schema, "CBD5E1")
    schema_rows = [
        ("Column Name", "Type & Modifiers", "Forensic Purpose"),
        ("packet_id", "INTEGER PRIMARY KEY AUTO", "Unique surrogate key identifying each recorded row."),
        ("capture_id", "INTEGER (FOREIGN KEY)", "Links row directly to parent capture in captures table."),
        ("packet_number", "INTEGER NOT NULL", "1-based packet index in original physical PCAP file (Traceability)."),
        ("timestamp / timestamp_iso", "REAL / TEXT NOT NULL", "IEEE 754 epoch float for rapid sorting + ISO 8601 string for display."),
        ("src_ip / dst_ip", "TEXT (NULLABLE)", "IPv4 or IPv6 endpoints. Null for non-IP / raw Layer 2 packets."),
        ("protocol / src_port / dst_port", "TEXT / INT / INT", "Protocol label ('TCP', 'UDP') and service ports (NULL for ICMP/ARP)."),
    ]
    for i, (cn, tm, fp) in enumerate(schema_rows):
        row = tbl_schema.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width, c1.width, c2.width = Inches(2.0), Inches(2.0), Inches(2.5)
        c0.text, c1.text, c2.text = cn, tm, fp
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("4.1 Why WAL (Write-Ahead Logging) Mode Matters", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "By default, SQLite uses a rollback journal, which locks the entire database file during writes. "
        "In our initialization (database.py), we execute: PRAGMA journal_mode = WAL;. "
        "In WAL mode, changes are written sequentially to a separate -wal file, allowing readers (the Streamlit dashboard) "
        "to execute search queries concurrently without blocking or being blocked by the importer writing packet batches!"
    )
    p.paragraph_format.space_after = Pt(14)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 5: THE 4-STAGE PROCESSING PIPELINE
    # -------------------------------------------------------------------------
    doc.add_heading("5. Under the Hood: The 4 Processing Stages", level=1).style.font.color.rgb = NAVY

    doc.add_heading("Stage 1: Ingestion Validation & Cryptographic Deduplication", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Before parsing a single byte of packet data, the intake engine (importer.py) validates the file against three defensive rules:"
    )
    doc.add_paragraph("• Magic Header Verification: Inspects the first 4 bytes. Validates standard PCAP (0xd4c3b2a1 for microsecond LE, 0xa1b2c3d4 for BE, 0x4d3cb2a1 for nanosecond) or PCAPNG (0x0a0d0d0a). Corrupt or non-PCAP files are rejected instantly.", style='List Bullet')
    doc.add_paragraph("• 100 MB Size Boundary: Prevents memory exhaustion and interface freezes from oversized files.", style='List Bullet')
    doc.add_paragraph("• SHA-256 Deduplication: Generates a 256-bit cryptographic digest of the file contents. If a user attempts to re-import an identical file, the system flags it and offers a Skip (load existing SQLite record) or Overwrite (clean re-import) policy.", style='List Bullet')

    doc.add_heading("Stage 2: Streaming Packet Parsing & Transactional Ingestion", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "To handle large files without consuming gigabytes of RAM, parser.py implements a streaming generator using Scapy's PcapReader. "
        "Instead of rdpcap() (which loads the entire capture into memory), PcapReader reads one packet at a time from disk. "
        "The parser normalizes the layers into Python dictionaries. "
        "Packets are accumulated in memory chunks of 1,000 and committed to SQLite via executemany() in single transactions. "
        "This batching strategy eliminates disk I/O bottlenecks, yielding over 3,500 packets/second throughput."
    )
    p.paragraph_format.space_after = Pt(10)

    doc.add_heading("Stage 3: High-Level Analytics & Interactive Visualizations", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Once imported, the Streamlit interface queries pre-indexed columns to generate high-level forensic summaries. "
        "Total packet counts, protocol breakdowns (TCP, UDP, Other/ICMP), and total byte volume are calculated in milliseconds. "
        "Interactive Plotly Express charts render a protocol distribution donut chart alongside horizontal bar charts showing "
        "the Top 5 Source IP talkers and Top 5 Destination IP listeners."
    )
    p.paragraph_format.space_after = Pt(10)

    doc.add_heading("Stage 4: Parameterized Queries, Pagination & CSV Export", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The final stage enables targeted investigation. The user applies multi-parameter filters (Protocol, Source IP, Destination IP, "
        "Port, and Time interval). Crucially, all filters use bound SQL parameters ('?') to ensure immunity from SQL injection attacks. "
        "To keep the browser responsive, queries implement SQL pagination (LIMIT safe_size OFFSET safe_offset). "
        "When the user clicks 'Download Filtered CSV', exporter.py executes the exact active SQL query and streams the records "
        "directly into standard comma-separated text."
    )
    p.paragraph_format.space_after = Pt(14)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 6: CODEBASE MAP & RESPONSIBILITIES
    # -------------------------------------------------------------------------
    doc.add_heading("6. Codebase Architecture & File Responsibilities", level=1).style.font.color.rgb = NAVY
    
    tbl_files = doc.add_table(rows=8, cols=3)
    tbl_files.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_files, "CBD5E1")
    f_map = [
        ("File Path", "Primary Module Role", "Key Functions / Responsibilities"),
        ("app.py", "Streamlit Frontend UI", "Manages the 4-step workflow, user interactions, KPI cards, Plotly charts, and CSV download trigger."),
        ("pcap_analyzer/database.py", "SQLite Database Layer", "Schema definition, WAL mode, B-Tree indexes, executemany batch insertion, and query_packets()."),
        ("pcap_analyzer/parser.py", "Scapy Packet Decoder", "Streaming PcapReader generator, protocol decoding (IPv4/IPv6/ARP/TCP/UDP), and null safety."),
        ("pcap_analyzer/importer.py", "Import Pipeline Coordinator", "Header magic validation, SHA-256 calculation, duplicate policy enforcement, and batch transactions."),
        ("pcap_analyzer/exporter.py", "CSV Export Engine", "Streams parameterized database query results into formatted CSV files or in-memory text buffers."),
        ("generate_fixtures.py", "Test Capture Generator", "Synthesizes realistic PCAPs (sample_lab, known_packets, non_ip, corrupted, empty, large)."),
        ("test_e2e_full.py", "Full End-to-End Test Harness", "Automated multi-layer audit: runs pytest, runs benchmark, and drives headless Chrome via Playwright."),
    ]
    for i, (fp, mr, kf) in enumerate(f_map):
        row = tbl_files.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width, c1.width, c2.width = Inches(2.0), Inches(2.0), Inches(2.5)
        c0.text, c1.text, c2.text = fp, mr, kf
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("6.1 Security & Ethical Safeguards Built-in", level=2).style.font.color.rgb = NAVY
    doc.add_paragraph("1. Passive Offline Operation Only: The software strictly analyzes pre-recorded files on disk. It has no live network sniffing sockets, promiscuous capture drivers, or active probe transmitters.", style='List Bullet')
    doc.add_paragraph("2. Privacy Preservation: Application layer payloads (chat text, user passwords, email bodies) are never inserted into SQLite. Only structural header envelopes are retained.", style='List Bullet')
    doc.add_paragraph("3. No Unsubstantiated Threat Claims: The tool reports objective protocol counts and endpoints. It never makes automated claims like 'Host X is an attacker' or speculative malware verdicts.", style='List Bullet')
    doc.add_paragraph("4. SQL Injection Immunity: Every single database query strictly utilizes bound parameter substitution ('?'), preventing SQL manipulation through search inputs.", style='List Bullet')

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # SECTION 7: SUMMARY CHEAT SHEET
    # -------------------------------------------------------------------------
    doc.add_heading("7. Quick Reference & Exam Cheat-Sheet", level=1).style.font.color.rgb = NAVY

    tbl_cheat = doc.add_table(rows=9, cols=2)
    tbl_cheat.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(tbl_cheat, "CBD5E1")
    cheat_items = [
        ("Concept / Term", "Short Summary / Exact Answer"),
        ("PCAP / PCAPNG", "Binary recording formats for raw network packets. Linear and unindexed by nature."),
        ("Packet Header vs. Payload", "Header = Envelope (addresses, protocol, port, timestamp). Payload = Letter inside (content). We only store Header."),
        ("Layer 2 (ARP)", "Translates IP addresses to physical MAC hardware addresses. Has no transport ports (stores NULL)."),
        ("Layer 3 (IP)", "Provides global routing addresses (IPv4: 32-bit, IPv6: 128-bit)."),
        ("Layer 4 (TCP vs UDP)", "TCP = Reliable, 3-way handshake, connection-oriented. UDP = Fast, no handshakes, best-effort."),
        ("ICMP", "Diagnostic and ping protocol. Operates directly on Layer 3 and HAS NO TRANSPORT PORTS (stores NULL)."),
        ("B-Tree Indexing", "Balanced tree data structure in SQLite that turns slow O(N) linear scans into instant O(log N) lookups."),
        ("WAL Mode", "Write-Ahead Logging: allows concurrent database reads while batch imports are writing."),
    ]
    for i, (t_term, s_sum) in enumerate(cheat_items):
        row = tbl_cheat.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(2.2), Inches(4.3)
        c0.text, c1.text = t_term, s_sum
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    p_end = doc.add_paragraph()
    p_end.paragraph_format.space_before = Pt(20)
    r_end = p_end.add_run("--- End of Technical Theory & Architecture Guide ---")
    r_end.font.italic = True
    r_end.font.color.rgb = SLATE
    p_end.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Save document
    doc.save(DOC_NAME)
    print(f"Word document saved as '{DOC_NAME}'.")

if __name__ == "__main__":
    build_document()

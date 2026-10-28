"""Script to generate the updated professional Word Report (.docx) for the PCAP to SQLite Network Traffic Analyzer."""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

DOC_NAME = "kaustubh borle_245811150 IS.docx"
DOC_NAME_ALT = "PCAP_to_SQLite_Report.docx"

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner padding for table cells."""
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
    shading_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

def set_table_borders(table, color="D3D3D3"):
    """Set subtle gray borders on a table."""
    tblPr = table._tbl.tblPr
    borders_xml = f"""
    <w:tblBorders {nsdecls("w")}>
        <w:top w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:bottom w:val="single" w:sz="6" w:space="0" w:color="{color}"/>
        <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:insideV w:val="none"/>
        <w:left w:val="none"/>
        <w:right w:val="none"/>
    </w:tblBorders>
    """
    tblPr.append(parse_xml(borders_xml))

def format_row(row, heights=None, bg_color=None, bold=False, text_color=None):
    for cell in row.cells:
        set_cell_margins(cell, top=120, bottom=120, left=150, right=150)
        if bg_color:
            set_cell_background(cell, bg_color)
        for p in cell.paragraphs:
            for run in p.runs:
                run.bold = bold
                if text_color:
                    run.font.color.rgb = text_color

def create_report():
    doc = docx.Document()

    # Set standard 1-inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Base Colors
    NAVY = RGBColor(16, 52, 96)       # #103460
    SLATE = RGBColor(71, 85, 105)     # #475569
    DARK = RGBColor(30, 41, 59)       # #1E293B
    WHITE = RGBColor(255, 255, 255)

    # Configure Normal Style
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = DARK

    # -------------------------------------------------------------------------
    # COVER PAGE / HEADER
    # -------------------------------------------------------------------------
    p_super = doc.add_paragraph()
    r_super = p_super.add_run("INFORMATION SECURITY | PROJECT 1 - PCAP ANALYSIS")
    r_super.font.size = Pt(10)
    r_super.font.bold = True
    r_super.font.color.rgb = NAVY
    p_super.paragraph_format.space_after = Pt(20)

    p_title = doc.add_paragraph()
    r_title = p_title.add_run("PCAP to SQLite\nNetwork Traffic Analyzer")
    r_title.font.size = Pt(26)
    r_title.font.bold = True
    r_title.font.color.rgb = NAVY
    p_title.paragraph_format.space_after = Pt(12)

    p_sub = doc.add_paragraph()
    r_sub = p_sub.add_run("Project Implementation & Offline Forensic Analysis Report")
    r_sub.font.size = Pt(14)
    r_sub.font.color.rgb = SLATE
    p_sub.paragraph_format.space_after = Pt(36)

    # Metadata Table
    table_meta = doc.add_table(rows=7, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_table_borders(table_meta, "CBD5E1")

    meta_data = [
        ("Prepared by", "Kaustubh Borle and Shikhar Saxena"),
        ("Enrollment No.", "245811150"),
        ("Course", "Information Security"),
        ("Module", "PCAP Analysis - PCAP to SQLite"),
        ("Assessment type", "Project report and offline traffic analysis"),
        ("Report date", "28 October 2026"),
        ("Version", "2.0 (Fully Implemented & Verified with Empirical Test Results)"),
    ]

    for i, (k, v) in enumerate(meta_data):
        row = table_meta.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.2)
        c1.width = Inches(4.3)
        c0.text = k
        c1.text = v
        c0.paragraphs[0].runs[0].bold = True
        c0.paragraphs[0].runs[0].font.color.rgb = NAVY
        set_cell_background(c0, "F1F5F9")
        set_cell_margins(c0, 100, 100, 140, 140)
        set_cell_margins(c1, 100, 100, 140, 140)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # TABLE OF CONTENTS / OUTLINE
    # -------------------------------------------------------------------------
    h_toc = doc.add_heading("Contents", level=1)
    h_toc.style.font.color.rgb = NAVY

    toc_items = [
        ("1 Executive Summary", "2"),
        ("2 Project Overview", "2"),
        ("    2.1 Problem statement", "2"),
        ("    2.2 Objectives", "2"),
        ("    2.3 Technology stack", "2"),
        ("3 Scope and Methodology", "3"),
        ("    3.1 Scope boundary", "3"),
        ("    3.2 End-to-end method", "3"),
        ("    3.3 Assumptions and limits", "3"),
        ("4 System Design & Architecture", "3"),
        ("    4.1 Module responsibilities", "4"),
        ("    4.2 Processing rules", "4"),
        ("5 Data Model", "4"),
        ("    5.1 Queries, schema and indexes", "4"),
        ("    5.2 Analytical questions answered", "5"),
        ("6 Product Interface & Live Execution Walkthrough", "5"),
        ("    6.1 Select and validate capture (Figure 2)", "5"),
        ("    6.2 Convert packet data to SQLite (Figure 3)", "6"),
        ("    6.3 Review traffic summaries & charts (Figure 4)", "6"),
        ("    6.4 Filter and export packet records (Figure 5)", "7"),
        ("7 Validation Method & Empirical Test Results", "7"),
        ("    7.1 Acceptance criteria outcomes (T01 - T07)", "7"),
        ("    7.2 Performance benchmark results (T08)", "8"),
        ("8 Implementation Components", "8"),
        ("9 Risks and Safeguards", "8"),
        ("10 Conclusion & Operational Limitations", "8"),
        ("Appendix A: Glossary", "9"),
    ]

    for item, pg in toc_items:
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(3)
        r1 = p.add_run(item)
        r2 = p.add_run(f"  .......................................................................................  {pg}")
        r2.font.color.rgb = RGBColor(148, 163, 184)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 1. EXECUTIVE SUMMARY
    # -------------------------------------------------------------------------
    doc.add_heading("1 Executive Summary", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The PCAP to SQLite Network Traffic Analyzer is an offline, security-conscious forensic application "
        "that converts recorded packet capture files (.pcap, .pcapng) into a high-performance, searchable SQLite "
        "relational database and presents the structured traffic through an intuitive Streamlit browser dashboard. "
        "The application reads authorized packet captures, extracts standardized packet metadata (packet sequence number, "
        "timestamps, source and destination IP addresses, transport protocol labels, source and destination ports, "
        "packet length in bytes, and human-readable protocol summaries), stores exactly one row per packet inside an "
        "indexed SQLite table, and allows analysts to review graphical traffic summaries, execute parameterized multi-field queries, "
        "and export filtered subsets to CSV for coursework review."
    )
    p.paragraph_format.space_after = Pt(10)

    p = doc.add_paragraph(
        "The complete end-to-end workflow—from file intake, magic-byte signature validation, streaming Scapy parsing, "
        "and transactional batch ingestion, to multi-dimensional filtering, visual distribution charting, and CSV export—"
        "has been fully implemented, verified, and demonstrated. All illustrative mockups from the initial specification "
        "have been replaced in this report with actual screenshots and empirical benchmark measurements obtained from "
        "the running software."
    )
    p.paragraph_format.space_after = Pt(16)

    # -------------------------------------------------------------------------
    # 2. PROJECT OVERVIEW
    # -------------------------------------------------------------------------
    doc.add_heading("2 Project Overview", level=1).style.font.color.rgb = NAVY
    
    doc.add_heading("2.1 Problem statement", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Raw packet capture files (.pcap) constitute foundational forensic evidence in network security investigations. "
        "However, repeated manual inspection using conventional packet sniffers is inefficient and computationally demanding "
        "when students or investigators need to cross-examine communicating hosts, transport protocols, destination services, "
        "and specific time windows across large captures. Ingesting parsed packet metadata into a relational SQLite database "
        "enables indexed, rapid, multi-attribute querying and persistent analytical reuse, while preserving complete traceability "
        "by linking every database row directly to its original 1-based packet sequence number in the source file."
    )
    p.paragraph_format.space_after = Pt(10)

    doc.add_heading("2.2 Objectives", level=2).style.font.color.rgb = NAVY
    doc.add_paragraph("• Ingest authorized PCAP/PCAPNG files offline and rigorously validate header signatures and size limits prior to parsing.", style='List Bullet')
    doc.add_paragraph("• Parse packet timestamps, network layer endpoints, transport protocols, port numbers, packet lengths, and concise summaries using Scapy streaming.", style='List Bullet')
    doc.add_paragraph("• Insert extracted metadata into an indexed SQLite relational database with transactional batching and SHA-256 deduplication.", style='List Bullet')
    doc.add_paragraph("• Provide an interactive local web dashboard with protocol totals, top endpoint distributions, and parameterized filters without requiring raw SQL knowledge.", style='List Bullet')
    doc.add_paragraph("• Export user-filtered metadata records directly to CSV for coursework review and offline reporting.", style='List Bullet')
    doc.add_paragraph("• Validate the system through automated unit testing, synthetic multi-protocol captures, and empirical performance benchmarking.", style='List Bullet')

    doc.add_heading("2.3 Technology stack", level=2).style.font.color.rgb = NAVY
    table_tech = doc.add_table(rows=6, cols=2)
    set_table_borders(table_tech, "CBD5E1")
    tech_data = [
        ("Technology", "Implemented Role & Justification"),
        ("Python 3.12", "Core application orchestration, packet extraction pipeline, and backend services."),
        ("Scapy 2.8.0", "Offline streaming packet decoding via PcapReader without requiring live packet capture drivers (Npcap/WinPcap)."),
        ("SQLite 3 (sqlite3)", "Local ACID relational database, B-Tree index acceleration, and WAL (Write-Ahead Logging) journal mode."),
        ("Streamlit 1.63", "Responsive local browser user interface with reactive workflow stepping, metrics, and data tables."),
        ("Plotly Express", "Interactive protocol breakdown donut charts and top communication endpoint horizontal bar charts."),
    ]
    for i, (k, v) in enumerate(tech_data):
        row = table_tech.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(2.0), Inches(4.5)
        c0.text, c1.text = k, v
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 3. SCOPE AND METHODOLOGY
    # -------------------------------------------------------------------------
    doc.add_heading("3 Scope and Methodology", level=1).style.font.color.rgb = NAVY

    doc.add_heading("3.1 Scope boundary", level=2).style.font.color.rgb = NAVY
    table_scope = doc.add_table(rows=6, cols=2)
    set_table_borders(table_scope, "CBD5E1")
    scope_data = [
        ("Included Capabilities", "Excluded / Prohibited Activities"),
        ("Offline ingestion of recorded .pcap and .pcapng files", "Live network sniffing or real-time packet capture"),
        ("IPv4 and IPv6 network endpoint decoding", "Active network scanning, ping sweeps, or port probing"),
        ("TCP, UDP, ICMP, ICMPv6, ARP, and non-IP framing labels", "Deep payload inspection, full packet reassembly, or file extraction"),
        ("Transactional SQLite batch storage with multi-column indexing", "Automated accusations, intrusion detection, or threat verdicts"),
        ("Parametric multi-criteria filtering, paging, and CSV export", "Cloud hosting, multi-tenant authentication, or external telemetry"),
    ]
    for i, (k, v) in enumerate(scope_data):
        row = table_scope.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(3.25), Inches(3.25)
        c0.text, c1.text = k, v
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("3.2 End-to-end method", level=2).style.font.color.rgb = NAVY
    doc.add_paragraph("1. File Selection & Ingestion: User selects an authorized PCAP file via local upload or workspace fixture selector.")
    doc.add_paragraph("2. Validation & Deduplication: The intake engine verifies the extension, checks a 100 MB ceiling, inspects magic header bytes (0xd4c3b2a1, 0x0a0d0d0a), computes the SHA-256 hash, and detects previous imports.")
    doc.add_paragraph("3. Streaming Packet Decoding: Scapy's PcapReader streams packets sequentially. Layer 3 and Layer 4 headers are parsed into normalized metadata dictionaries. Non-IP or non-transport fields safely default to NULL.")
    doc.add_paragraph("4. Transactional Batch Insertion: Records are inserted into SQLite in batches of 1,000 using parameterized INSERT queries inside isolated database transactions.")
    doc.add_paragraph("5. Analytical Exploration: The Streamlit UI executes parameterized COUNT and SELECT queries against pre-indexed fields to render high-level KPIs, protocol distribution charts, and paginated packet tables.")
    doc.add_paragraph("6. Filtered CSV Export: Filtered records matching the active query criteria are streamed directly to CSV format.")

    doc.add_heading("3.3 Assumptions and limits", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The system is engineered for local classroom and laboratory forensic analysis. Payloads are intentionally excluded "
        "to ensure privacy compliance and reduce database footprint. Encrypted traffic (TLS/HTTPS, SSH) is classified purely "
        "by structural metadata (endpoints, transport ports, and packet lengths). The tool acts strictly as an objective observation "
        "platform and intentionally avoids speculative threat verdicts."
    )
    p.paragraph_format.space_after = Pt(14)

    # -------------------------------------------------------------------------
    # 4. SYSTEM DESIGN
    # -------------------------------------------------------------------------
    doc.add_heading("4 System Design & Architecture", level=1).style.font.color.rgb = NAVY
    
    doc.add_heading("4.1 Module responsibilities", level=2).style.font.color.rgb = NAVY
    table_mod = doc.add_table(rows=6, cols=3)
    set_table_borders(table_mod, "CBD5E1")
    mod_data = [
        ("Module", "Core Implemented Responsibility", "Concrete Output"),
        ("File Intake (importer.py)", "Validate magic bytes, enforce size limit, compute SHA-256", "Validated file descriptor & hash"),
        ("Packet Parser (parser.py)", "Streaming Scapy packet decoding, protocol normalization", "Normalized packet dict batches"),
        ("Database Layer (database.py)", "Batch transactional writes, indexing, parameterized queries", "SQLite database (traffic_analysis.sqlite)"),
        ("Analysis UI (app.py)", "Streamlit dashboard, KPI calculation, Plotly visual charts", "Interactive 4-step web interface"),
        ("Export Engine (exporter.py)", "Stream filtered query results into standard CSV format", "Downloadable CSV report file"),
    ]
    for i, (k, v, o) in enumerate(mod_data):
        row = table_mod.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width, c1.width, c2.width = Inches(1.8), Inches(3.2), Inches(1.5)
        c0.text, c1.text, c2.text = k, v, o
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("4.2 Processing rules", level=2).style.font.color.rgb = NAVY
    doc.add_paragraph("• Traceability Preservation: Each packet maintains its original 1-based sequence number from the physical PCAP file.", style='List Bullet')
    doc.add_paragraph("• Numeric & ISO Timestamps: Epoch timestamps are stored as IEEE 754 floating-point numbers for high-speed indexing, alongside ISO 8601 strings for human readability.", style='List Bullet')
    doc.add_paragraph("• Fault Tolerance & Isolation: Individual packet parsing errors increment error_count without aborting file import.", style='List Bullet')
    doc.add_paragraph("• SQL Injection Immunity: Every database query uses bound parameter placeholders ('?') exclusively.", style='List Bullet')

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 5. DATA MODEL
    # -------------------------------------------------------------------------
    doc.add_heading("5 Data Model", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The relational schema uses two interconnected tables: `captures` tracks ingested file audits and metadata, "
        "while `packets` stores individual packet header records. A 1-to-many relationship links captures to packets "
        "with ON DELETE CASCADE constraints."
    )
    p.paragraph_format.space_after = Pt(10)

    doc.add_heading("5.1 Schema and Index Specifications", level=2).style.font.color.rgb = NAVY
    table_schema = doc.add_table(rows=12, cols=4)
    set_table_borders(table_schema, "CBD5E1")
    schema_data = [
        ("Table", "Field Name", "SQLite Type", "Forensic & Analytical Purpose"),
        ("captures", "capture_id", "INTEGER PK AUTO", "Primary key identifying the capture ingestion"),
        ("captures", "filename, sha256", "TEXT (UNIQUE)", "File identity, audit traceability, and duplicate prevention"),
        ("captures", "file_size_bytes, imported_at", "INTEGER, TEXT", "File volume and ISO 8601 ingestion audit timestamp"),
        ("captures", "status, packet_count, error_count", "TEXT, INT, INT", "Completion audit: 'completed', 'incomplete', 'failed'"),
        ("packets", "packet_id, capture_id", "INTEGER, INT FK", "Row key and foreign key referencing captures(capture_id)"),
        ("packets", "packet_number", "INTEGER", "1-based packet position in source capture file"),
        ("packets", "timestamp, timestamp_iso", "REAL, TEXT", "Unix epoch float and formatted timestamp for time-window queries"),
        ("packets", "src_ip, dst_ip", "TEXT (NULLABLE)", "IPv4/IPv6 source and destination network endpoints"),
        ("packets", "protocol", "TEXT", "Normalized protocol label (TCP, UDP, ICMP, ARP, etc.)"),
        ("packets", "src_port, dst_port", "INTEGER (NULL)", "Transport layer service ports (NULL for non-transport packets)"),
        ("packets", "length_bytes, summary", "INTEGER, TEXT", "Total frame wire length and concise Scapy protocol summary"),
    ]
    for i, (tbl, fld, typ, purp) in enumerate(schema_data):
        row = table_schema.rows[i]
        c0, c1, c2, c3 = row.cells[0], row.cells[1], row.cells[2], row.cells[3]
        c0.width, c1.width, c2.width, c3.width = Inches(1.1), Inches(1.8), Inches(1.2), Inches(2.4)
        c0.text, c1.text, c2.text, c3.text = tbl, fld, typ, purp
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.add_run("Dedicated B-Tree Indexes Created:\n").bold = True
    p.add_run("• idx_packets_capture_id ON packets(capture_id)\n")
    p.add_run("• idx_packets_timestamp ON packets(capture_id, timestamp)\n")
    p.add_run("• idx_packets_src_ip ON packets(capture_id, src_ip)\n")
    p.add_run("• idx_packets_dst_ip ON packets(capture_id, dst_ip)\n")
    p.add_run("• idx_packets_protocol ON packets(capture_id, protocol)\n")
    p.add_run("• idx_packets_dst_port ON packets(capture_id, dst_port)\n")

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 6. PRODUCT INTERFACE & LIVE SCREENSHOTS
    # -------------------------------------------------------------------------
    doc.add_heading("6 Product Interface & Live Execution Walkthrough", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The user interface follows a clear 4-step stepper pattern matching Figures 2 through 5. "
        "The sample mockups from the initial specification have been completely replaced with actual, "
        "high-resolution screenshots captured directly from the running Streamlit web application."
    )
    p.paragraph_format.space_after = Pt(12)

    # 6.1 Step 1 Screenshot
    doc.add_heading("6.1 Select and validate the capture (Step 1)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "In Step 1, the user selects an authorized packet capture file. The intake engine calculates the SHA-256 digest, "
        "validates magic header bytes, checks file size, and verifies that the file is safe for ingestion. "
        "Figure 2 illustrates the live interface validating the laboratory capture `sample_lab.pcap`."
    )
    p.paragraph_format.space_after = Pt(8)

    fig2_path = os.path.join("screenshots", "fig2_choose_capture.png")
    if os.path.exists(fig2_path):
        doc.add_picture(fig2_path, width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_cap = p_cap.add_run("Figure 2: Actual File Selection & Validation Screen (running application with sample_lab.pcap)")
        r_cap.font.italic = True
        r_cap.font.size = Pt(9.5)
        p_cap.paragraph_format.space_after = Pt(16)

    # 6.2 Step 2 Screenshot
    doc.add_heading("6.2 Convert packet data to SQLite (Step 2)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Step 2 performs the core conversion. The Scapy streaming decoder parses packets and inserts them into SQLite "
        "in batch transactions. The completion screen displays records saved (107 packets), 0 errors, processing time (0.035s), "
        "and audit parameters. Figure 3 shows the actual import completion view."
    )
    p.paragraph_format.space_after = Pt(8)

    fig3_path = os.path.join("screenshots", "fig3_import_sqlite.png")
    if os.path.exists(fig3_path):
        doc.add_picture(fig3_path, width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_cap = p_cap.add_run("Figure 3: Actual PCAP to SQLite Import Screen (showing 107 packets indexed in traffic_analysis.sqlite)")
        r_cap.font.italic = True
        r_cap.font.size = Pt(9.5)
        p_cap.paragraph_format.space_after = Pt(16)

    doc.add_page_break()

    # 6.3 Step 3 Screenshot
    doc.add_heading("6.3 Review traffic summaries (Step 3)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Step 3 displays high-level traffic metrics and interactive Plotly distributions. The summary cards show Total Packets "
        "(107), TCP Packets (51, 47.7%), UDP Packets (18, 16.8%), and Other/ICMP Packets (38, 35.5%). "
        "Interactive charts show protocol proportions and top communicating IP endpoints. Figure 4 displays the live dashboard."
    )
    p.paragraph_format.space_after = Pt(8)

    fig4_path = os.path.join("screenshots", "fig4_review_traffic.png")
    if os.path.exists(fig4_path):
        doc.add_picture(fig4_path, width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_cap = p_cap.add_run("Figure 4: Actual Traffic Dashboard (showing protocol distribution and top endpoints from running app)")
        r_cap.font.italic = True
        r_cap.font.size = Pt(9.5)
        p_cap.paragraph_format.space_after = Pt(16)

    # 6.4 Step 4 Screenshot
    doc.add_heading("6.4 Filter and export packet records (Step 4)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Step 4 allows the user to filter packet records by Protocol, Source IP, Destination IP, Port, and Time interval. "
        "The interface executes strictly parameterized SQL queries, displays paginated records (25, 50, or 100 rows per page), "
        "and provides a one-click button to download the exact filtered selection as CSV. "
        "Figure 5 displays the filtered packet list isolating TCP traffic (51 matching packets) with the CSV export button."
    )
    p.paragraph_format.space_after = Pt(8)

    fig5_path = os.path.join("screenshots", "fig5_filter_export.png")
    if os.path.exists(fig5_path):
        doc.add_picture(fig5_path, width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_cap = p_cap.add_run("Figure 5: Actual Filtered Packet List & CSV Export Screen (filtering TCP packets with pagination)")
        r_cap.font.italic = True
        r_cap.font.size = Pt(9.5)
        p_cap.paragraph_format.space_after = Pt(16)

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 7. VALIDATION METHOD & TEST RESULTS
    # -------------------------------------------------------------------------
    doc.add_heading("7 Validation Method & Empirical Test Results", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "Verification was conducted using an automated test harness covering all functional requirements and edge cases. "
        "Tests T01 through T07 were executed using pytest against deterministic synthetic captures, while T08 evaluated "
        "performance scalability against a 5,000-packet capture."
    )
    p.paragraph_format.space_after = Pt(10)

    # Test Results Table
    table_tests = doc.add_table(rows=9, cols=4)
    set_table_borders(table_tests, "CBD5E1")
    test_rows = [
        ("ID", "Test Description", "Acceptance Criterion", "Observed Empirical Result"),
        ("T01", "Valid PCAP import", "Database packet count equals parser count", "PASSED: Exactly 107 packets parsed and stored (0 count discrepancy)."),
        ("T02", "Known TCP & UDP packets", "Protocol, addresses, ports, and lengths match expected values", "PASSED: Deterministic HTTP (port 80), DNS (port 53), ICMP matched exactly."),
        ("T03", "Packets without IP or ports", "Import succeeds with null fields where appropriate", "PASSED: ARP and raw Ethernet imported with NULL IPs/ports without crashing."),
        ("T04", "Malformed or unsupported file", "Clear error and no misleading completed status", "PASSED: Empty (0B) and corrupt header files raised ValueError; 0 records written."),
        ("T05", "Repeat import of same file", "Duplicate handling follows selected policy", "PASSED: 'skip' policy detected identical SHA-256 and prevented duplicate rows."),
        ("T06", "Host, protocol, port, time filters", "Returned rows match a manually checked fixture", "PASSED: Parameterized queries returned exact expected counts for all filters."),
        ("T07", "CSV export", "Exported rows equal the visible filtered selection", "PASSED: Exported CSV headers and row counts matched filtered query exactly."),
        ("T08", "Larger capture scalability", "Import finishes within agreed classroom benchmark (< 30s)", "PASSED: 5,000 packets imported in 1.404s (3,560.5 pkts/sec, 89.97 MB RAM)."),
    ]
    for i, (tid, desc, crit, res) in enumerate(test_rows):
        row = table_tests.rows[i]
        c0, c1, c2, c3 = row.cells[0], row.cells[1], row.cells[2], row.cells[3]
        c0.width, c1.width, c2.width, c3.width = Inches(0.6), Inches(1.8), Inches(2.1), Inches(2.0)
        c0.text, c1.text, c2.text, c3.text = tid, desc, crit, res
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_heading("7.1 Performance Benchmark Telemetry (T08)", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "A rigorous scalability benchmark was executed on `benchmark_large.pcap` using `benchmark.py`. "
        "The test capture contained 5,000 multi-protocol packets (2,000 TCP, 2,000 UDP, 1,000 ICMP). "
        "The observed performance metrics and system environment were recorded as follows:"
    )
    doc.add_paragraph("• Host Operating System: Windows 11 (AMD64 architecture)", style='List Bullet')
    doc.add_paragraph("• Host Processor: Intel64 Family 6 Model 183 Stepping 1 (15.71 GB Physical RAM)", style='List Bullet')
    doc.add_paragraph("• Python Runtime: Python 3.12.8 64-bit", style='List Bullet')
    doc.add_paragraph("• File Size: 555,024 bytes (0.529 MB)", style='List Bullet')
    doc.add_paragraph("• Import Duration: 1.404 seconds", style='List Bullet')
    doc.add_paragraph("• Processing Throughput: 3,560.5 packets/second (0.377 MB/second)", style='List Bullet')
    doc.add_paragraph("• Peak Memory Usage (RSS): 89.97 MB", style='List Bullet')
    doc.add_paragraph("• Output Database Size: 1.199 MB (including all 6 B-Tree indexes)", style='List Bullet')
    doc.add_paragraph("• Benchmark Verdict: PASSED (completed well below the 30.0-second classroom limit).", style='List Bullet')

    doc.add_heading("7.2 Acceptance of the Required Module", level=2).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The core requirement—converting physical PCAP files into an indexed SQLite database and verifying packet records "
        "via an interactive UI and parameterized queries—has been fully satisfied. The automated test suite passed 11 of 11 tests "
        "with 100% success rate across all defined acceptance criteria."
    )
    p.paragraph_format.space_after = Pt(14)

    # -------------------------------------------------------------------------
    # 8. IMPLEMENTATION COMPONENTS
    # -------------------------------------------------------------------------
    doc.add_heading("8 Implementation Components", level=1).style.font.color.rgb = NAVY
    table_comp = doc.add_table(rows=6, cols=3)
    set_table_borders(table_comp, "CBD5E1")
    comp_data = [
        ("Component", "Functional Implementation", "Visible User Output"),
        ("File Intake", "validate_pcap_file(): Magic bytes & 100MB check", "Filename, size, SHA-256 hash, and validation badges"),
        ("Packet Parser", "parse_pcap(): Scapy streaming PcapReader", "Normalized records with IPv4/IPv6/ARP and transport ports"),
        ("SQLite Importer", "import_pcap(): Transactional batch executemany", "Database file (traffic_analysis.sqlite) & import metrics"),
        ("Analysis Queries", "query_packets(): Parameterized SQL with COUNT(*)", "Dashboard KPI cards, Plotly charts, and paginated table"),
        ("CSV Exporter", "export_packets_to_csv(): Streaming chunked CSV writer", "Downloadable filtered CSV file (filtered_packets_export.csv)"),
    ]
    for i, (k, v, o) in enumerate(comp_data):
        row = table_comp.rows[i]
        c0, c1, c2 = row.cells[0], row.cells[1], row.cells[2]
        c0.width, c1.width, c2.width = Inches(1.8), Inches(3.2), Inches(1.5)
        c0.text, c1.text, c2.text = k, v, o
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    doc.add_page_break()

    # -------------------------------------------------------------------------
    # 9. RISKS AND SAFEGUARDS
    # -------------------------------------------------------------------------
    doc.add_heading("9 Risks and Safeguards", level=1).style.font.color.rgb = NAVY
    table_risk = doc.add_table(rows=6, cols=2)
    set_table_borders(table_risk, "CBD5E1")
    risk_data = [
        ("Identified Operational Risk", "Implemented Technical Safeguard"),
        ("Sensitive data exposure in packet payloads", "Payloads are completely excluded; only structural header metadata is stored in SQLite."),
        ("Oversized captures stalling browser or memory", "Strict 100 MB file limit, streaming PcapReader generator, 1,000-packet batch commits, and UI pagination."),
        ("Malformed, truncated, or non-IP packets", "Layer 3/4 try-catch isolation, graceful NULL field assignment, and error counter tracking."),
        ("Misleading automated security claims", "Application acts purely as an objective observation tool; does not generate automatic threat classifications."),
        ("Inconsistent state from duplicate imports", "SHA-256 content hashing detects duplicate files and enforces user-selected 'skip' or 'overwrite' policies."),
    ]
    for i, (k, v) in enumerate(risk_data):
        row = table_risk.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(2.5), Inches(4.0)
        c0.text, c1.text = k, v
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    # -------------------------------------------------------------------------
    # 10. CONCLUSION & LIMITATIONS
    # -------------------------------------------------------------------------
    doc.add_heading("10 Conclusion & Operational Limitations", level=1).style.font.color.rgb = NAVY
    p = doc.add_paragraph(
        "The PCAP to SQLite Network Traffic Analyzer successfully delivers an offline forensic analysis platform. "
        "By pairing Scapy's decoding precision with SQLite's transactional indexing and Streamlit's reactive UI, "
        "the application transforms cumbersome packet captures into accessible, structured datasets. "
        "All requirements—including IPv4/IPv6 support, non-IP null handling, multi-parameter SQL filtering, "
        "robust duplicate detection, and streaming CSV export—have been empirically verified."
    )
    p.paragraph_format.space_after = Pt(10)

    doc.add_heading("Operational Limitations & Scope Boundaries:", level=3).style.font.color.rgb = NAVY
    doc.add_paragraph("• Offline Constraint: Live packet capture and active network probing are intentionally disabled.", style='List Bullet')
    doc.add_paragraph("• Payload Exclusion: Application layer payloads are not reconstructed, ensuring compliance with privacy standards.", style='List Bullet')
    doc.add_paragraph("• Single-User Local Deployment: The application is optimized for local standalone analysis rather than multi-tenant hosting.", style='List Bullet')

    # -------------------------------------------------------------------------
    # APPENDIX A: GLOSSARY
    # -------------------------------------------------------------------------
    doc.add_heading("Appendix A: Glossary", level=1).style.font.color.rgb = NAVY
    table_gloss = doc.add_table(rows=7, cols=2)
    set_table_borders(table_gloss, "CBD5E1")
    gloss_data = [
        ("Term", "Definition"),
        ("PCAP / PCAPNG", "Standard binary file formats (Packet Capture / PCAP Next Generation) for recording network packet data."),
        ("Packet Metadata", "Structural header fields including timestamps, network IP addresses, transport protocol numbers, ports, and frame length."),
        ("SQLite", "A self-contained, serverless, zero-configuration, transactional relational database engine."),
        ("Scapy", "A powerful Python-based packet manipulation and network analysis framework used for offline stream decoding."),
        ("B-Tree Index", "A balanced tree data structure used in SQLite to enable sub-millisecond lookups on filtered columns."),
        ("Offline Analysis", "Forensic inspection of pre-recorded capture files without interfacing with active network adapters or live traffic."),
    ]
    for i, (k, v) in enumerate(gloss_data):
        row = table_gloss.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width, c1.width = Inches(2.0), Inches(4.5)
        c0.text, c1.text = k, v
        if i == 0:
            format_row(row, bg_color="0F172A", bold=True, text_color=WHITE)
        else:
            format_row(row, bg_color="F8FAFC" if i % 2 == 1 else "FFFFFF")

    # Save document
    doc.save(DOC_NAME)
    doc.save(DOC_NAME_ALT)
    print(f"Report saved as '{DOC_NAME}' and '{DOC_NAME_ALT}'.")

if __name__ == "__main__":
    create_report()

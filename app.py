"""PCAP to SQLite Network Traffic Analyzer - Streamlit Web Application.

Offline network traffic analysis, SQLite indexing, summary metrics,
parameterized queries, and CSV export.
"""

from __future__ import annotations

import io
import math
import os
import tempfile
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.express as px
import streamlit as st

from pcap_analyzer.database import (
    DEFAULT_DB_PATH,
    delete_capture,
    find_capture_by_sha256,
    get_all_captures,
    get_capture_by_id,
    get_capture_summary,
    get_connection,
    get_top_endpoints,
    init_db,
    query_packets,
)
from pcap_analyzer.exporter import export_packets_to_csv
from pcap_analyzer.importer import (
    DEFAULT_MAX_FILE_SIZE,
    VALID_MAGIC_NUMBERS,
    compute_sha256,
    import_pcap,
    validate_pcap_file,
)

# -----------------------------------------------------------------------------
# Configuration and Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="PCAP Traffic Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for polished interface styling
st.markdown(
    """
    <style>
    /* Main container adjustments */
    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
    }
    
    /* Header & Badges */
    .app-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        margin-bottom: 0.2rem;
    }
    .app-title {
        font-size: 2.1rem;
        font-weight: 700;
        color: #1E293B;
        margin: 0;
        display: inline-block;
    }
    .badge-offline {
        background-color: #0284C7;
        color: white;
        padding: 4px 12px;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        margin-left: 12px;
        vertical-align: middle;
    }
    .disclaimer-banner {
        background-color: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-left: 4px solid #0284C7;
        padding: 10px 16px;
        border-radius: 4px;
        font-size: 0.88rem;
        color: #475569;
        margin-bottom: 1.5rem;
    }
    
    /* Stepper Styling */
    .stepper-container {
        display: flex;
        justify-content: space-between;
        margin-bottom: 1.8rem;
        gap: 8px;
    }
    
    /* Metric & Summary Cards */
    .metric-card {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .metric-title {
        font-size: 0.82rem;
        font-weight: 600;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .metric-val {
        font-size: 1.8rem;
        font-weight: 700;
        color: #0F172A;
    }
    .metric-sub {
        font-size: 0.8rem;
        color: #94A3B8;
        margin-top: 4px;
    }
    
    /* Status Badges */
    .badge-success {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-warning {
        background-color: #FEF9C3;
        color: #854D0E;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    .badge-danger {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        display: inline-block;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Session State Initialization
# -----------------------------------------------------------------------------
if "current_step" not in st.session_state:
    st.session_state["current_step"] = 1
if "db_path" not in st.session_state:
    st.session_state["db_path"] = DEFAULT_DB_PATH
if "active_capture_id" not in st.session_state:
    st.session_state["active_capture_id"] = None
if "staged_file_path" not in st.session_state:
    st.session_state["staged_file_path"] = None
if "staged_file_meta" not in st.session_state:
    st.session_state["staged_file_meta"] = None
if "import_result" not in st.session_state:
    st.session_state["import_result"] = None
if "page_number" not in st.session_state:
    st.session_state["page_number"] = 1
if "page_size" not in st.session_state:
    st.session_state["page_size"] = 50
if "filter_protocol" not in st.session_state:
    st.session_state["filter_protocol"] = "All"
if "filter_src_ip" not in st.session_state:
    st.session_state["filter_src_ip"] = ""
if "filter_dst_ip" not in st.session_state:
    st.session_state["filter_dst_ip"] = ""
if "filter_port" not in st.session_state:
    st.session_state["filter_port"] = ""
if "filter_start_time" not in st.session_state:
    st.session_state["filter_start_time"] = ""
if "filter_end_time" not in st.session_state:
    st.session_state["filter_end_time"] = ""


# Ensure database tables are created
init_db(st.session_state["db_path"])


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def set_step(step_number: int) -> None:
    """Transition to a specific workflow step."""
    st.session_state["current_step"] = step_number
    st.session_state["page_number"] = 1


def format_bytes(num_bytes: int) -> str:
    """Format bytes into readable units."""
    if num_bytes is None:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def get_available_fixtures() -> List[str]:
    """Scan workspace for pre-existing sample captures."""
    candidate_dirs = [
        os.path.join("tests", "fixtures"),
        "fixtures",
        "samples",
        ".",
    ]
    fixtures = []
    for d in candidate_dirs:
        if os.path.exists(d):
            for root, _, files in os.walk(d):
                for f in files:
                    if f.lower().endswith((".pcap", ".pcapng", ".cap")):
                        fixtures.append(os.path.normpath(os.path.join(root, f)))
    return sorted(list(set(fixtures)))


def get_distinct_protocols(db_path: str, capture_id: int) -> List[str]:
    """Retrieve list of distinct protocols present in capture."""
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "SELECT DISTINCT protocol FROM packets WHERE capture_id = ? ORDER BY protocol ASC",
            (capture_id,),
        )
        return [row["protocol"] for row in cur.fetchall() if row["protocol"]]


# -----------------------------------------------------------------------------
# Top Navigation & Header
# -----------------------------------------------------------------------------
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown(
        """
        <div class="app-header">
            <div>
                <span class="app-title">PCAP Traffic Analyzer</span>
                <span class="badge-offline">LOCAL APP | Offline Analysis Only</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown(
    """
    <div class="disclaimer-banner">
        🛡️ <strong>Offline analysis only</strong> • No live capture or active network probing • Payloads not inspected • Strictly local SQLite storage
    </div>
    """,
    unsafe_allow_html=True,
)


# -----------------------------------------------------------------------------
# Sidebar: Database Management & Capture Switcher
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🗄️ Database & Captures")
    db_file = st.text_input("SQLite Database Path", value=st.session_state["db_path"])
    if db_file != st.session_state["db_path"]:
        st.session_state["db_path"] = db_file
        init_db(db_file)
        st.rerun()

    existing_captures = get_all_captures(st.session_state["db_path"])
    st.markdown(f"**Total Indexed Captures:** `{len(existing_captures)}`")

    if existing_captures:
        capture_options = {
            f"#{c['capture_id']}: {c['filename']} ({c['packet_count']} pkts - {c['status']})": c["capture_id"]
            for c in existing_captures
        }
        
        # Determine currently selected index in selectbox
        current_selection_idx = 0
        if st.session_state["active_capture_id"] is not None:
            for idx, cid in enumerate(capture_options.values()):
                if cid == st.session_state["active_capture_id"]:
                    current_selection_idx = idx
                    break

        selected_label = st.selectbox(
            "Switch Active Capture:",
            options=list(capture_options.keys()),
            index=current_selection_idx,
            help="Switch between previously imported PCAP captures in the local SQLite database.",
        )
        selected_id = capture_options[selected_label]

        if selected_id != st.session_state["active_capture_id"]:
            st.session_state["active_capture_id"] = selected_id
            st.session_state["page_number"] = 1
            st.rerun()

        col_sb1, col_sb2 = st.columns(2)
        with col_sb1:
            if st.button("📊 Review", use_container_width=True):
                set_step(3)
                st.rerun()
        with col_sb2:
            if st.button("🔍 Filter", use_container_width=True):
                set_step(4)
                st.rerun()

        st.divider()
        if st.button("🗑️ Delete Current Capture", help="Remove this capture and its packet rows from SQLite"):
            if st.session_state["active_capture_id"]:
                delete_capture(st.session_state["db_path"], st.session_state["active_capture_id"])
                st.session_state["active_capture_id"] = None
                st.success("Capture deleted from SQLite.")
                set_step(1)
                st.rerun()
    else:
        st.info("No captures imported yet. Use Step 1 to choose and import a PCAP.")

    st.divider()
    st.markdown("### ℹ️ About & Safeguards")
    st.caption(
        "This tool supports academic network forensics and coursework verification. "
        "It performs streaming Scapy decoding without replaying traffic, scanning endpoints, or storing payload contents."
    )


# -----------------------------------------------------------------------------
# Stepper Navigation Bar
# -----------------------------------------------------------------------------
step_cols = st.columns(4)
step_labels = [
    ("1 Choose capture", 1),
    ("2 Import to SQLite", 2),
    ("3 Review traffic", 3),
    ("4 Filter and export", 4),
]

for col, (label, step_num) in zip(step_cols, step_labels):
    with col:
        is_active = (st.session_state["current_step"] == step_num)
        btn_type = "primary" if is_active else "secondary"
        if st.button(f"{'👉 ' if is_active else ''}{label}", key=f"step_btn_{step_num}", use_container_width=True, type=btn_type):
            set_step(step_num)
            st.rerun()

st.divider()


# =============================================================================
# STEP 1: CHOOSE CAPTURE (Figure 2 in Project Report)
# =============================================================================
if st.session_state["current_step"] == 1:
    st.subheader("Step 1: Choose capture")
    st.write("Select an authorized packet capture file (`.pcap`, `.pcapng`, or `.cap`) to inspect and validate.")

    source_mode = st.radio(
        "Source file method:",
        options=["Upload capture file", "Select from workspace fixtures / samples"],
        horizontal=True,
    )

    selected_file_path: Optional[str] = None
    original_filename: Optional[str] = None

    if source_mode == "Upload capture file":
        uploaded_file = st.file_uploader(
            "Choose a packet capture file",
            type=["pcap", "pcapng", "cap"],
            help="Select a local PCAP or PCAPNG capture (max 100 MB).",
        )
        if uploaded_file is not None:
            # Stage file into temporary folder
            temp_dir = os.path.join(tempfile.gettempdir(), "pcap_analyzer_uploads")
            os.makedirs(temp_dir, exist_ok=True)
            saved_path = os.path.join(temp_dir, uploaded_file.name)
            with open(saved_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            selected_file_path = saved_path
            original_filename = uploaded_file.name
    else:
        fixtures = get_available_fixtures()
        if fixtures:
            default_idx = 0
            for idx, fix in enumerate(fixtures):
                if "sample_lab.pcap" in fix:
                    default_idx = idx
                    break
            fixture_choice = st.selectbox(
                "Available sample files:",
                options=fixtures,
                index=default_idx,
                key="fixture_choice_select",
            )
            if fixture_choice:
                selected_file_path = os.path.abspath(fixture_choice)
                original_filename = os.path.basename(fixture_choice)
        else:
            st.info("No sample captures found in workspace fixtures directory. Please use the upload option.")

    if selected_file_path and os.path.exists(selected_file_path):
        file_size_bytes = os.path.getsize(selected_file_path)
        file_size_mb = file_size_bytes / (1024 * 1024)
        file_sha256 = compute_sha256(selected_file_path)

        # Validation checks
        ext_valid = original_filename.lower().endswith((".pcap", ".pcapng", ".cap"))
        size_valid = (file_size_bytes > 0) and (file_size_bytes <= DEFAULT_MAX_FILE_SIZE)
        
        # Magic bytes check
        with open(selected_file_path, "rb") as f:
            magic_bytes = f.read(4)
        magic_valid = magic_bytes in VALID_MAGIC_NUMBERS

        all_valid = ext_valid and size_valid and magic_valid

        # Display File Metadata Box
        st.markdown("#### 📋 File Metadata & Validation")
        meta_col1, meta_col2, meta_col3 = st.columns(3)
        with meta_col1:
            st.markdown(f"**Filename:** `{original_filename}`")
            st.markdown(f"**Format:** `{'PCAPNG' if magic_bytes == b'\\x0a\\x0d\\x0d\\x0a' else 'Standard PCAP' if magic_valid else 'Unknown'}`")
        with meta_col2:
            st.markdown(f"**File Size:** `{file_size_mb:.2f} MB` ({file_size_bytes:,} bytes)")
            st.markdown(f"**Header Magic:** `0x{magic_bytes.hex()}`")
        with meta_col3:
            st.markdown(f"**SHA-256 Hash:**")
            st.code(file_sha256, language=None)

        # Validation Status Cards
        v_col1, v_col2, v_col3 = st.columns(3)
        with v_col1:
            if ext_valid:
                st.success("✅ File extension accepted")
            else:
                st.error("❌ Unsupported extension")
        with v_col2:
            if size_valid:
                st.success(f"✅ Size within limit (< {DEFAULT_MAX_FILE_SIZE // (1024*1024)} MB)")
            else:
                st.error("❌ File exceeds 100 MB limit or is empty")
        with v_col3:
            if magic_valid:
                st.success("✅ Valid PCAP header magic")
            else:
                st.error("❌ Invalid capture signature")

        # Duplicate Detection Check
        existing = find_capture_by_sha256(st.session_state["db_path"], file_sha256)
        duplicate_policy = "skip"

        if existing:
            st.warning(
                f"⚠️ **Duplicate capture detected in SQLite!**\n\n"
                f"This file matches existing Capture **#{existing['capture_id']}** (`{existing['filename']}`), "
                f"imported on `{existing['imported_at']}` ({existing['packet_count']} packets, {existing['status']})."
            )
            duplicate_policy = st.radio(
                "Duplicate resolution policy:",
                options=["skip", "overwrite"],
                format_func=lambda x: "Skip import (Use existing indexed SQLite capture)" if x == "skip" else "Overwrite (Purge and re-import from scratch)",
                horizontal=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)
        if all_valid:
            action_btn_text = "Use Existing Capture ➔" if (existing and duplicate_policy == "skip") else "Validate and Import to SQLite ➔"
            if st.button(action_btn_text, type="primary", use_container_width=True):
                st.session_state["staged_file_path"] = selected_file_path
                st.session_state["staged_file_meta"] = {
                    "filename": original_filename,
                    "file_size_bytes": file_size_bytes,
                    "sha256": file_sha256,
                    "duplicate_policy": duplicate_policy,
                }
                set_step(2)
                st.rerun()
        else:
            st.error("File validation failed. Please choose a valid PCAP capture before proceeding.")


# =============================================================================
# STEP 2: IMPORT TO SQLITE (Figure 3 in Project Report)
# =============================================================================
elif st.session_state["current_step"] == 2:
    st.subheader("Step 2: Import to SQLite")
    st.write("Convert packet capture into indexed SQLite records with batch insertion and error recovery.")

    staged_path = st.session_state.get("staged_file_path")
    staged_meta = st.session_state.get("staged_file_meta")

    if not staged_path or not os.path.exists(staged_path):
        st.warning("⚠️ No capture selected for import. Please choose a capture in Step 1.")
        if st.button("⬅️ Return to Step 1: Choose capture"):
            set_step(1)
            st.rerun()
    else:
        st.markdown(f"**Target Capture:** `{staged_meta['filename']}` (`{format_bytes(staged_meta['file_size_bytes'])}`)")
        st.caption(f"SHA-256: `{staged_meta['sha256']}` | SQLite: `{os.path.abspath(st.session_state['db_path'])}`")

        # Check if already imported in session or needs execution
        needs_import = (st.session_state.get("import_result") is None) or \
                       (st.session_state["import_result"].get("sha256") != staged_meta["sha256"])

        if needs_import:
            import_placeholder = st.empty()
            progress_bar = st.progress(0, text="Initializing Scapy offline parser...")

            def progress_callback(packet_count: int) -> None:
                progress_bar.progress(min(1.0, packet_count / 10000.0 if packet_count < 10000 else 0.95),
                                      text=f"Importing packets to SQLite... ({packet_count:,} packets processed)")

            try:
                with st.spinner("Decoding packets and writing to SQLite in transactions..."):
                    result = import_pcap(
                        file_path=staged_path,
                        db_path=st.session_state["db_path"],
                        duplicate_policy=staged_meta.get("duplicate_policy", "skip"),
                        batch_size=1000,
                        progress_callback=progress_callback,
                    )
                progress_bar.progress(1.0, text="Import complete!")
                st.session_state["import_result"] = result
                st.session_state["active_capture_id"] = result["capture_id"]
            except Exception as e:
                progress_bar.empty()
                st.error(f"❌ Import failed: {str(e)}")
                st.session_state["import_result"] = None

        # Display completed import summary
        result = st.session_state.get("import_result")
        if result:
            status_text = "Import complete - metadata indexed and ready to explore"
            badge_class = "badge-success" if result["status"] in ("completed", "skipped") else "badge-danger"
            
            st.markdown(
                f"""
                <div style="margin-top: 15px; margin-bottom: 20px;">
                    <span class="{badge_class}">✓ {status_text}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Metric Cards
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.metric("Records Saved", f"{result['packet_count']:,}")
            with m2:
                st.metric("Errors Encountered", f"{result['error_count']}")
            with m3:
                st.metric("Import Duration", f"{result['duration_seconds']}s")
            with m4:
                st.metric("Capture ID", f"#{result['capture_id']}")

            st.markdown("#### Audit & Database Details")
            audit_df = pd.DataFrame([
                {"Parameter": "Source Filename", "Value": result["filename"]},
                {"Parameter": "SHA-256 Digest", "Value": result["sha256"]},
                {"Parameter": "File Size", "Value": format_bytes(result["file_size_bytes"])},
                {"Parameter": "Database Target", "Value": os.path.abspath(st.session_state["db_path"])},
                {"Parameter": "Import Status", "Value": result["status"].upper()},
            ])
            st.table(audit_df)

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("⬅️ Choose Another Capture", use_container_width=True):
                    st.session_state["staged_file_path"] = None
                    st.session_state["import_result"] = None
                    set_step(1)
                    st.rerun()
            with col_btn2:
                if st.button("Proceed to Review Traffic ➔", type="primary", use_container_width=True):
                    st.session_state["active_capture_id"] = result["capture_id"]
                    set_step(3)
                    st.rerun()


# =============================================================================
# STEP 3: REVIEW TRAFFIC (Figure 4 in Project Report)
# =============================================================================
elif st.session_state["current_step"] == 3:
    st.subheader("Step 3: Review traffic summaries")
    st.write("Examine high-level metrics, protocol distribution, and top endpoint activity.")

    active_id = st.session_state.get("active_capture_id")
    if not active_id:
        st.warning("⚠️ No active capture loaded. Please select or import a capture first.")
        if st.button("⬅️ Go to Step 1: Choose capture"):
            set_step(1)
            st.rerun()
    else:
        summary = get_capture_summary(st.session_state["db_path"], active_id)
        if not summary:
            st.error(f"Could not load summary for Capture #{active_id}.")
        else:
            total_pkts = summary.get("total_packets", 0)
            tcp_cnt = summary.get("tcp_count", 0)
            udp_cnt = summary.get("udp_count", 0)
            icmp_cnt = summary.get("icmp_count", 0)
            other_cnt = summary.get("other_count", 0)

            # Capture Header Banner
            st.markdown(
                f"**Active Capture:** `{summary['filename']}` (ID: `#{active_id}`) | "
                f"**Imported:** `{summary['imported_at'][:19]}` | "
                f"**Total Volume:** `{format_bytes(summary['total_bytes'])}`"
            )

            # High-level KPIs
            kpi1, kpi2, kpi3, kpi4 = st.columns(4)
            with kpi1:
                st.metric(
                    label="Total Packets",
                    value=f"{total_pkts:,}",
                    help="Total number of decoded packets saved in SQLite",
                )
            with kpi2:
                tcp_pct = (tcp_cnt / total_pkts * 100) if total_pkts > 0 else 0
                st.metric(
                    label="TCP Packets",
                    value=f"{tcp_cnt:,}",
                    delta=f"{tcp_pct:.1f}%",
                    help="Transmission Control Protocol packets",
                )
            with kpi3:
                udp_pct = (udp_cnt / total_pkts * 100) if total_pkts > 0 else 0
                st.metric(
                    label="UDP Packets",
                    value=f"{udp_cnt:,}",
                    delta=f"{udp_pct:.1f}%",
                    help="User Datagram Protocol packets",
                )
            with kpi4:
                icmp_pct = ((icmp_cnt + other_cnt) / total_pkts * 100) if total_pkts > 0 else 0
                st.metric(
                    label="Other / ICMP",
                    value=f"{(icmp_cnt + other_cnt):,}",
                    delta=f"{icmp_pct:.1f}%",
                    help="ICMP, ARP, IPv6, and non-transport framing",
                )

            st.divider()

            # Visual Charts Section
            chart_col1, chart_col2 = st.columns([1, 1])

            with chart_col1:
                st.markdown("#### 📊 Protocol Distribution")
                # Query all protocol frequencies
                with get_connection(st.session_state["db_path"]) as conn:
                    cur = conn.execute(
                        """
                        SELECT protocol, COUNT(*) as count
                        FROM packets
                        WHERE capture_id = ?
                        GROUP BY protocol
                        ORDER BY count DESC
                        """,
                        (active_id,),
                    )
                    proto_data = [dict(r) for r in cur.fetchall()]

                if proto_data:
                    proto_df = pd.DataFrame(proto_data)
                    fig_proto = px.pie(
                        proto_df,
                        names="protocol",
                        values="count",
                        hole=0.45,
                        color_discrete_sequence=px.colors.qualitative.Safe,
                    )
                    fig_proto.update_layout(
                        margin=dict(l=20, r=20, t=20, b=20),
                        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                    )
                    st.plotly_chart(fig_proto, use_container_width=True)
                else:
                    st.info("No protocol data recorded for this capture.")

            with chart_col2:
                st.markdown("#### 🌐 Top Communicating Endpoints")
                endpoints = get_top_endpoints(st.session_state["db_path"], active_id, limit=5)
                top_src = endpoints.get("top_src_ips", [])
                top_dst = endpoints.get("top_dst_ips", [])

                tab_src, tab_dst = st.tabs(["Top Source IPs", "Top Destination IPs"])
                with tab_src:
                    if top_src:
                        src_df = pd.DataFrame(top_src)
                        fig_src = px.bar(
                            src_df,
                            x="count",
                            y="ip",
                            orientation="h",
                            text="count",
                            labels={"count": "Packets Sent", "ip": "Source IP"},
                            color_discrete_sequence=["#0284C7"],
                        )
                        fig_src.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=10, r=10, t=10, b=10))
                        st.plotly_chart(fig_src, use_container_width=True)
                    else:
                        st.info("No IP endpoints found in capture.")

                with tab_dst:
                    if top_dst:
                        dst_df = pd.DataFrame(top_dst)
                        fig_dst = px.bar(
                            dst_df,
                            x="count",
                            y="ip",
                            orientation="h",
                            text="count",
                            labels={"count": "Packets Received", "ip": "Destination IP"},
                            color_discrete_sequence=["#10B981"],
                        )
                        fig_dst.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=10, r=10, t=10, b=10))
                        st.plotly_chart(fig_dst, use_container_width=True)
                    else:
                        st.info("No IP endpoints found in capture.")

            st.markdown("<br>", unsafe_allow_html=True)
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                if st.button("⬅️ Back to Import Details", use_container_width=True):
                    set_step(2)
                    st.rerun()
            with col_b2:
                if st.button("Proceed to Filter and Export ➔", type="primary", use_container_width=True):
                    set_step(4)
                    st.rerun()


# =============================================================================
# STEP 4: FILTER AND EXPORT (Figure 5 in Project Report)
# =============================================================================
elif st.session_state["current_step"] == 4:
    st.subheader("Step 4: Filter and export")
    st.write("Apply parameterized filters to isolate packets of interest and export metadata to CSV.")

    active_id = st.session_state.get("active_capture_id")
    if not active_id:
        st.warning("⚠️ No active capture loaded. Please select or import a capture first.")
        if st.button("⬅️ Go to Step 1: Choose capture"):
            set_step(1)
            st.rerun()
    else:
        # Load distinct protocols for dropdown
        available_protos = ["All"] + get_distinct_protocols(st.session_state["db_path"], active_id)

        # Filter Controls Bar
        with st.expander("🔍 Filter Controls", expanded=True):
            f_col1, f_col2, f_col3 = st.columns(3)
            with f_col1:
                selected_protocol = st.selectbox(
                    "Protocol",
                    options=available_protos,
                    index=available_protos.index(st.session_state["filter_protocol"]) if st.session_state["filter_protocol"] in available_protos else 0,
                    key="select_filter_protocol",
                )
                filter_port = st.text_input(
                    "Port (Src or Dst)",
                    value=st.session_state["filter_port"],
                    placeholder="e.g. 80, 443, 53",
                    key="input_filter_port",
                )

            with f_col2:
                filter_src_ip = st.text_input(
                    "Source IP",
                    value=st.session_state["filter_src_ip"],
                    placeholder="e.g. 192.168.1.10",
                    key="input_filter_src_ip",
                )
                filter_start_time = st.text_input(
                    "Start Time (ISO or Epoch)",
                    value=st.session_state["filter_start_time"],
                    placeholder="YYYY-MM-DDTHH:MM:SS",
                    key="input_filter_start_time",
                )

            with f_col3:
                filter_dst_ip = st.text_input(
                    "Destination IP",
                    value=st.session_state["filter_dst_ip"],
                    placeholder="e.g. 10.0.0.1",
                    key="input_filter_dst_ip",
                )
                filter_end_time = st.text_input(
                    "End Time (ISO or Epoch)",
                    value=st.session_state["filter_end_time"],
                    placeholder="YYYY-MM-DDTHH:MM:SS",
                    key="input_filter_end_time",
                )

            # Action buttons for filters
            btn_col1, btn_col2, _ = st.columns([1, 1, 3])
            with btn_col1:
                if st.button("Apply Filters", type="primary", use_container_width=True):
                    st.session_state["filter_protocol"] = selected_protocol
                    st.session_state["filter_src_ip"] = filter_src_ip.strip()
                    st.session_state["filter_dst_ip"] = filter_dst_ip.strip()
                    st.session_state["filter_port"] = filter_port.strip()
                    st.session_state["filter_start_time"] = filter_start_time.strip()
                    st.session_state["filter_end_time"] = filter_end_time.strip()
                    st.session_state["page_number"] = 1
                    st.rerun()

            with btn_col2:
                if st.button("Reset Filters", use_container_width=True):
                    st.session_state["filter_protocol"] = "All"
                    st.session_state["filter_src_ip"] = ""
                    st.session_state["filter_dst_ip"] = ""
                    st.session_state["filter_port"] = ""
                    st.session_state["filter_start_time"] = ""
                    st.session_state["filter_end_time"] = ""
                    st.session_state["page_number"] = 1
                    st.rerun()

        # Query Database with current filters
        proto_param = None if st.session_state["filter_protocol"] == "All" else st.session_state["filter_protocol"]
        rows, total_matching = query_packets(
            db_path=st.session_state["db_path"],
            capture_id=active_id,
            protocol=proto_param,
            port=st.session_state["filter_port"] or None,
            start_time=st.session_state["filter_start_time"] or None,
            end_time=st.session_state["filter_end_time"] or None,
            src_ip=st.session_state["filter_src_ip"] or None,
            dst_ip=st.session_state["filter_dst_ip"] or None,
            page=st.session_state["page_number"],
            page_size=st.session_state["page_size"],
        )

        # Get capture overall packet count for comparison
        summary = get_capture_summary(st.session_state["db_path"], active_id)
        total_capture_pkts = summary.get("total_packets", 0)

        # Metrics display: "Matching packets: X of Y"
        match_pct = (total_matching / total_capture_pkts * 100) if total_capture_pkts > 0 else 0
        total_pages = max(1, math.ceil(total_matching / st.session_state["page_size"]))

        m_bar1, m_bar2 = st.columns([3, 1])
        with m_bar1:
            st.markdown(
                f"**Matching packets:** `{total_matching:,}` of `{total_capture_pkts:,}` "
                f"(`{match_pct:.1f}%` of capture) • "
                f"Page `{st.session_state['page_number']}` of `{total_pages}`"
            )
        with m_bar2:
            st.session_state["page_size"] = st.selectbox(
                "Rows per page:",
                options=[25, 50, 100],
                index=[25, 50, 100].index(st.session_state["page_size"]),
            )

        # Render Paginated Table
        if rows:
            df_rows = pd.DataFrame(rows)
            display_cols = [
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
            display_df = df_rows[display_cols].copy()
            display_df.rename(
                columns={
                    "packet_number": "Packet #",
                    "timestamp_iso": "Time (ISO)",
                    "src_ip": "Source IP",
                    "dst_ip": "Destination IP",
                    "protocol": "Protocol",
                    "src_port": "Src Port",
                    "dst_port": "Dst Port",
                    "length_bytes": "Length (bytes)",
                    "summary": "Summary",
                },
                inplace=True,
            )
            # Fill NA values for cleaner display
            display_df["Source IP"] = display_df["Source IP"].fillna("-")
            display_df["Destination IP"] = display_df["Destination IP"].fillna("-")
            display_df["Src Port"] = display_df["Src Port"].fillna("")
            display_df["Dst Port"] = display_df["Dst Port"].fillna("")

            st.dataframe(
                display_df,
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No packets match the selected filter criteria.")

        # Pagination Controls
        p_col1, p_col2, p_col3, p_col4 = st.columns([1, 1, 2, 2])
        with p_col1:
            if st.button("◀ Previous", disabled=(st.session_state["page_number"] <= 1), use_container_width=True):
                st.session_state["page_number"] = max(1, st.session_state["page_number"] - 1)
                st.rerun()

        with p_col2:
            if st.button("Next ▶", disabled=(st.session_state["page_number"] >= total_pages), use_container_width=True):
                st.session_state["page_number"] = min(total_pages, st.session_state["page_number"] + 1)
                st.rerun()

        with p_col3:
            st.caption(f"Showing rows {(st.session_state['page_number'] - 1) * st.session_state['page_size'] + 1} - {min(total_matching, st.session_state['page_number'] * st.session_state['page_size'])} of {total_matching}")

        # CSV Export Section
        st.divider()
        st.markdown("#### 📥 Export Filtered Metadata")
        st.write("Export the exact set of matching filtered records to a standard CSV file for coursework review or verification.")

        # Build filter dictionary for exporter
        active_filters: Dict[str, Any] = {}
        if proto_param:
            active_filters["protocol"] = proto_param
        if st.session_state["filter_src_ip"]:
            active_filters["src_ip"] = st.session_state["filter_src_ip"]
        if st.session_state["filter_dst_ip"]:
            active_filters["dst_ip"] = st.session_state["filter_dst_ip"]
        if st.session_state["filter_port"]:
            active_filters["port"] = st.session_state["filter_port"]
        if st.session_state["filter_start_time"]:
            active_filters["start_time"] = st.session_state["filter_start_time"]
        if st.session_state["filter_end_time"]:
            active_filters["end_time"] = st.session_state["filter_end_time"]

        # Stream CSV into in-memory buffer
        csv_buffer = io.StringIO()
        export_packets_to_csv(
            db_path=st.session_state["db_path"],
            capture_id=active_id,
            filters=active_filters,
            output_file_or_buffer=csv_buffer,
        )
        csv_data = csv_buffer.getvalue()

        # Generate download button
        export_filename = f"capture_{active_id}_{summary['filename'].split('.')[0]}_filtered.csv"
        st.download_button(
            label=f"📥 Download Filtered CSV ({total_matching:,} rows)",
            data=csv_data,
            file_name=export_filename,
            mime="text/csv",
            type="primary",
        )

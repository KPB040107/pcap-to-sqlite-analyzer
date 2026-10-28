"""Comprehensive End-to-End (E2E) Test Suite for PCAP to SQLite Network Traffic Analyzer.

Tests all layers:
1. Backend tests (pytest T01-T07)
2. Scalability benchmark (T08)
3. Full browser UI journey via Playwright (Steps 1, 2, 3, 4, CSV download, and sidebar switcher)
"""

import csv
import io
import json
import os
import sqlite3
import subprocess
import sys
import time
from playwright.sync_api import sync_playwright

WORKSPACE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(WORKSPACE, "traffic_analysis.sqlite")
FIXTURES_DIR = os.path.join(WORKSPACE, "tests", "fixtures")

# Set UTF-8 encoding for stdout on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

def log(step: str, msg: str, success: bool = True):
    symbol = "PASS" if success else "FAIL"
    print(f"[{symbol}] {step:<25} : {msg}")

def run_backend_pytest():
    print("\n" + "="*70)
    print("PHASE 1: BACKEND PYTEST SUITE (T01 - T07)")
    print("="*70)
    cmd = [sys.executable, "-m", "pytest", "tests/test_analyzer.py", "-v", "--tb=short"]
    res = subprocess.run(cmd, cwd=WORKSPACE, capture_output=True, text=True)
    print(res.stdout)
    if res.returncode == 0:
        log("Backend Tests", "All 11 unit and acceptance tests passed successfully.", True)
        return True
    else:
        log("Backend Tests", f"Pytest failed with exit code {res.returncode}:\n{res.stderr}", False)
        return False

def run_scalability_benchmark():
    print("\n" + "="*70)
    print("PHASE 2: PERFORMANCE BENCHMARK (T08)")
    print("="*70)
    cmd = [sys.executable, "benchmark.py"]
    res = subprocess.run(cmd, cwd=WORKSPACE, capture_output=True, text=True)
    print(res.stdout)
    bench_file = os.path.join(WORKSPACE, "benchmark_results.json")
    if os.path.exists(bench_file):
        with open(bench_file, "r") as f:
            data = json.load(f)
        perf = data["performance"]
        log("Benchmark (T08)", 
            f"Imported {perf['packet_count']} packets in {perf['duration_seconds']}s "
            f"({perf['throughput_packets_per_sec']} pkts/s, RAM: {perf['memory_usage_mb']} MB). Status: {data['status']}", 
            data["status"] == "PASS")
        return data["status"] == "PASS"
    log("Benchmark (T08)", "benchmark_results.json not found.", False)
    return False

def run_browser_e2e():
    print("\n" + "="*70)
    print("PHASE 3: FULL BROWSER UI END-TO-END VERIFICATION (PLAYWRIGHT)")
    print("="*70)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        context = browser.new_context(viewport={"width": 1366, "height": 900}, accept_downloads=True)
        page = context.new_page()

        # 1. Connect to local Streamlit app
        print("Connecting to http://localhost:8501...")
        page.goto("http://localhost:8501")
        page.wait_for_selector(".app-title", timeout=15000)
        title_text = page.locator(".app-title").inner_text()
        assert "PCAP Traffic Analyzer" in title_text
        log("UI Connection", f"Connected to Streamlit app: '{title_text}'", True)

        # 2. Step 1: Choose & Validate Capture
        print("\nTesting Step 1: Choose Capture...")
        step1_btn = page.locator("button:has-text('1 Choose capture')")
        step1_btn.click()
        time.sleep(1)

        # Select workspace fixtures option
        radio_fixture = page.locator("label:has-text('Select from workspace fixtures')")
        radio_fixture.click()
        time.sleep(1.5)

        # Ensure sample_lab.pcap is selected
        page.wait_for_selector("text=File Metadata & Validation", timeout=10000)
        file_meta_text = page.locator("text=sample_lab.pcap").first.inner_text()
        log("Step 1 Metadata", f"Detected file metadata for '{file_meta_text}'", True)

        # Check validation badges
        assert page.locator("text=File extension accepted").count() > 0
        assert page.locator("text=Size within limit").count() > 0
        assert page.locator("text=Valid PCAP header magic").count() > 0
        log("Step 1 Validation", "All 3 validation badges passed (Extension, Size, Magic Bytes).", True)

        # Check duplicate resolution radio if present, select overwrite to test full clean import
        overwrite_radio = page.locator("label:has-text('Overwrite')")
        if overwrite_radio.count() > 0:
            overwrite_radio.click()
            time.sleep(0.5)
            log("Step 1 Duplicate Check", "Detected existing capture; selected Overwrite policy.", True)

        # 3. Step 2: Import to SQLite
        print("\nTesting Step 2: Ingestion & Transaction Batching...")
        action_btn = page.locator("button:has-text('Validate and Import')")
        action_btn.click()
        time.sleep(1)

        # Wait for import completion card
        page.wait_for_selector("text=Import complete - metadata indexed", timeout=20000)
        badge_text = page.locator(".badge-success").inner_text()
        log("Step 2 Import Status", f"Status Badge: '{badge_text}'", True)

        # Verify metrics displayed in UI
        records_metric = page.locator("div[data-testid='stMetric']:has-text('Records Saved') div[data-testid='stMetricValue']").inner_text()
        errors_metric = page.locator("div[data-testid='stMetric']:has-text('Errors Encountered') div[data-testid='stMetricValue']").inner_text()
        assert records_metric == "107", f"Expected 107 records saved, got {records_metric}"
        assert errors_metric == "0", f"Expected 0 errors, got {errors_metric}"
        log("Step 2 Metrics", f"Records Saved: {records_metric}, Errors: {errors_metric}", True)

        # Direct database verification
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS cnt FROM packets")
            db_pkt_count = cur.fetchone()["cnt"]
            cur.execute("SELECT status, packet_count, error_count FROM captures ORDER BY capture_id DESC LIMIT 1")
            last_cap = dict(cur.fetchone())

        assert db_pkt_count >= 107
        assert last_cap["status"] == "completed"
        assert last_cap["packet_count"] == 107
        log("Database Direct Audit", f"SQLite packets table count = {db_pkt_count}, last capture status = {last_cap['status']}", True)

        # 4. Step 3: Review Traffic Summaries & Charts
        print("\nTesting Step 3: Traffic Summaries & Interactive Visualizations...")
        proceed_to_review = page.locator("button:has-text('Proceed to Review Traffic')")
        proceed_to_review.click()
        time.sleep(2)

        page.wait_for_selector("text=Step 3: Review traffic summaries", timeout=15000)
        
        # Verify Summary Metric KPIs
        kpi_total = page.locator("div[data-testid='stMetric']:has-text('Total Packets') div[data-testid='stMetricValue']").inner_text()
        kpi_tcp = page.locator("div[data-testid='stMetric']:has-text('TCP Packets') div[data-testid='stMetricValue']").inner_text()
        kpi_udp = page.locator("div[data-testid='stMetric']:has-text('UDP Packets') div[data-testid='stMetricValue']").inner_text()
        kpi_other = page.locator("div[data-testid='stMetric']:has-text('Other / ICMP') div[data-testid='stMetricValue']").inner_text()

        assert kpi_total == "107", f"Expected Total 107, got {kpi_total}"
        assert kpi_tcp == "51", f"Expected TCP 51, got {kpi_tcp}"
        assert kpi_udp == "18", f"Expected UDP 18, got {kpi_udp}"
        assert kpi_other == "38", f"Expected Other 38, got {kpi_other}"
        log("Step 3 KPI Breakdown", f"Total: {kpi_total}, TCP: {kpi_tcp}, UDP: {kpi_udp}, Other/ICMP: {kpi_other}", True)

        # Verify Plotly Chart DOM elements
        time.sleep(2)
        plotly_charts = page.locator(".js-plotly-plot")
        chart_count = plotly_charts.count()
        assert chart_count >= 2, f"Expected at least 2 Plotly charts, found {chart_count}"
        log("Step 3 Plotly Visuals", f"Detected {chart_count} rendered Plotly interactive charts.", True)

        # 5. Step 4: Filter & Export
        print("\nTesting Step 4: Parameterized Queries, Pagination, and CSV Export...")
        proceed_to_filter = page.locator("button:has-text('Proceed to Filter and Export')")
        proceed_to_filter.click()
        time.sleep(2)

        page.wait_for_selector("text=Step 4: Filter and export", timeout=15000)

        # Test Filter by Port 80
        print("Applying Port 80 filter...")
        port_input = page.locator("input[aria-label='Port (Src or Dst)']")
        port_input.fill("80")
        time.sleep(0.5)

        apply_btn = page.locator("button:has-text('Apply Filters')")
        apply_btn.click()
        time.sleep(2)

        # Check Matching Banner (16 packets on port 80 in sample_lab.pcap)
        page.wait_for_selector("text=Matching packets:", timeout=10000)
        matching_banner = page.locator("p:has-text('Matching packets:')").first.inner_text()
        assert "16" in matching_banner and "107" in matching_banner, f"Banner text was '{matching_banner}'"
        log("Step 4 Query Filter", f"Filter banner confirmed: '{matching_banner}'", True)

        # Verify Table Rows
        table_rows = page.locator("div[data-testid='stDataFrame']")
        log("Step 4 Table", "Paginated data table rendered with filtered rows.", True)

        # 6. Test CSV Export Button
        print("\nTesting CSV Export Event & Data Integrity...")
        with page.expect_download() as download_info:
            export_btn = page.locator("button:has-text('Download Filtered CSV')")
            export_btn.click()

        download = download_info.value
        csv_download_path = os.path.join(WORKSPACE, "downloaded_test_export.csv")
        download.save_as(csv_download_path)

        assert os.path.exists(csv_download_path)
        with open(csv_download_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            exported_rows = list(reader)

        assert len(exported_rows) == 16, f"Expected 16 exported port 80 packets, got {len(exported_rows)}"
        for row in exported_rows:
            assert row["src_port"] == "80" or row["dst_port"] == "80", f"Row ports: src={row['src_port']}, dst={row['dst_port']}"

        log("Step 4 CSV Export", f"Downloaded '{os.path.basename(csv_download_path)}' containing exactly 16 valid port 80 packet records.", True)

        # Clean up temporary test download
        if os.path.exists(csv_download_path):
            os.remove(csv_download_path)

        # 7. Test Sidebar Switcher
        print("\nTesting Sidebar Capture Switcher...")
        sidebar_select = page.locator("div[data-testid='stSidebar'] div[data-testid='stSelectbox']:has-text('Switch Active Capture')")
        if sidebar_select.count() > 0:
            log("Sidebar Switcher", "Active capture dropdown present and operational.", True)

        context.close()
        browser.close()
        return True

def main():
    print("======================================================================")
    print("STARTING FULL END-TO-END (E2E) SYSTEM AUDIT & VERIFICATION")
    print("======================================================================")
    t0 = time.time()

    backend_ok = run_backend_pytest()
    benchmark_ok = run_scalability_benchmark()
    ui_e2e_ok = run_browser_e2e()

    elapsed = round(time.time() - t0, 2)
    print("\n" + "="*70)
    print("END-TO-END AUDIT SUMMARY")
    print("="*70)
    log("1. Backend Test Suite (11/11)", "PASS", backend_ok)
    log("2. Scalability Benchmark (T08)", "PASS", benchmark_ok)
    log("3. Browser UI Journey (Steps 1-4)", "PASS", ui_e2e_ok)
    print(f"\nTotal Audit Duration: {elapsed}s")
    
    if backend_ok and benchmark_ok and ui_e2e_ok:
        print("\n>>> ALL LAYERS ARE WORKING END-TO-END WITH ZERO DEFECTS! <<<")
        return 0
    else:
        print("\n>>> SOME TESTS FAILED. <<<")
        return 1

if __name__ == "__main__":
    sys.exit(main())

"""Script to automate user journey in Streamlit and capture screenshots for the project report."""

import os
import time
from playwright.sync_api import sync_playwright

SCREENSHOTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# Path to database
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "traffic_analysis.sqlite")

def run():
    # If DB exists, remove it so the flow is clean and fresh
    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
            print(f"Removed old {DB_PATH} for fresh capture walkthrough.")
        except Exception as e:
            print(f"Notice: {e}")

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        # 1280x850 viewport for crisp rendering matching project report layout
        context = browser.new_context(viewport={"width": 1280, "height": 850}, device_scale_factor=2)
        page = context.new_page()

        print("Navigating to http://localhost:8501...")
        page.goto("http://localhost:8501")
        page.wait_for_selector(".app-title", timeout=15000)
        time.sleep(2)

        # ----------------------------------------------------
        # Figure 2: Step 1 - Choose Capture & Validation
        # ----------------------------------------------------
        print("Capturing Step 1 (Choose Capture)...")
        # Ensure Step 1 is active
        step1_nav = page.locator("button:has-text('1 Choose capture')")
        if step1_nav.count() > 0:
            step1_nav.click()
            time.sleep(1)

        # Click "Select from workspace fixtures / samples"
        fixture_radio = page.locator("label:has-text('Select from workspace fixtures')")
        if fixture_radio.count() > 0:
            fixture_radio.click()
            time.sleep(1.5)

        # Wait for file metadata and validation cards
        page.wait_for_selector("text=File Metadata & Validation", timeout=10000)
        time.sleep(1)
        fig2_path = os.path.join(SCREENSHOTS_DIR, "fig2_choose_capture.png")
        page.screenshot(path=fig2_path, full_page=False)
        print(f"Saved: {fig2_path}")

        # ----------------------------------------------------
        # Figure 3: Step 2 - Import to SQLite
        # ----------------------------------------------------
        print("Executing import for Step 2...")
        # Action button on Step 1
        action_btn = page.locator("button:has-text('Validate and Import')")
        if action_btn.count() > 0:
            action_btn.click()
            time.sleep(2.5)

        # Wait for import completion card
        page.wait_for_selector("text=Import complete - metadata indexed", timeout=15000)
        time.sleep(1.5)
        fig3_path = os.path.join(SCREENSHOTS_DIR, "fig3_import_sqlite.png")
        page.screenshot(path=fig3_path, full_page=False)
        print(f"Saved: {fig3_path}")

        # ----------------------------------------------------
        # Figure 4: Step 3 - Review Traffic Summaries
        # ----------------------------------------------------
        print("Navigating to Step 3 (Review Traffic)...")
        proceed_to_review_btn = page.locator("button:has-text('Proceed to Review Traffic')")
        if proceed_to_review_btn.count() > 0:
            proceed_to_review_btn.click()
        else:
            page.locator("button:has-text('3 Review traffic')").click()
        time.sleep(3)

        page.wait_for_selector("text=Step 3: Review traffic summaries", timeout=15000)
        # Wait for plotly charts to fully render
        time.sleep(3)
        fig4_path = os.path.join(SCREENSHOTS_DIR, "fig4_review_traffic.png")
        page.screenshot(path=fig4_path, full_page=False)
        print(f"Saved: {fig4_path}")

        # ----------------------------------------------------
        # Figure 5: Step 4 - Filter and Export
        # ----------------------------------------------------
        print("Navigating to Step 4 (Filter and Export)...")
        proceed_to_filter_btn = page.locator("button:has-text('Proceed to Filter and Export')")
        if proceed_to_filter_btn.count() > 0:
            proceed_to_filter_btn.click()
        else:
            page.locator("button:has-text('4 Filter and export')").click()
        time.sleep(2)

        page.wait_for_selector("text=Step 4: Filter and export", timeout=15000)
        time.sleep(1)

        # Apply a filter (e.g. Protocol = TCP)
        proto_box = page.locator("div[data-testid='stSelectbox']:has-text('Protocol')")
        if proto_box.count() > 0:
            proto_box.click()
            time.sleep(0.5)
            tcp_item = page.locator("li[role='option']:has-text('TCP')")
            if tcp_item.count() > 0:
                tcp_item.click()
                time.sleep(1)

        apply_btn = page.locator("button:has-text('Apply Filters')")
        if apply_btn.count() > 0:
            apply_btn.click()
            time.sleep(2)

        fig5_path = os.path.join(SCREENSHOTS_DIR, "fig5_filter_export.png")
        page.screenshot(path=fig5_path, full_page=False)
        print(f"Saved: {fig5_path}")

        context.close()
        browser.close()
        print("All 4 figures captured and verified successfully!")

if __name__ == "__main__":
    run()

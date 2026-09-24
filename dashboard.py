import html
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT_FILE = ROOT / "scan_report.json"
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"


def load_report():
    try:
        raw_report = REPORT_FILE.read_text(encoding="utf-8")
        report = json.loads(raw_report)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "checked_at_utc": "—",
            "overall_result": "INCONCLUSIVE",
            "checks": [],
            "error": "No scan report is available. Run scan to generate a fresh result.",
        }

    if not isinstance(report, dict):
        return {
            "checked_at_utc": "—",
            "overall_result": "INCONCLUSIVE",
            "checks": [],
            "error": "The scan report is in an unexpected format.",
        }

    report.setdefault("checked_at_utc", "—")
    report.setdefault("overall_result", "INCONCLUSIVE")
    report.setdefault("checks", [])
    report.setdefault("error", "")
    return report


class Dashboard(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/scan":
            self.send_error(404)
            return

        try:
            subprocess.run(
                [sys.executable, str(SCANNER_FILE)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.send_error(504, "Scan timed out")
            return

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        report = load_report()
        checks = report.get("checks") if isinstance(report.get("checks"), list) else []
        overall_result = str(report.get("overall_result", "INCONCLUSIVE")).upper()
        checked_at = str(report.get("checked_at_utc", "—"))
        error_message = str(report.get("error") or "")

        def safe(value):
            return html.escape(str(value))

        def badge_color(status):
            if status == "PASS":
                return "#22c55e"
            if status == "VULNERABLE":
                return "#ef4444"
            return "#f59e0b"

        check_cards = "".join(
            f"""
            <div class="card">
                <div class="check-header">
                    <h3>{safe(check.get('name', 'Check'))}</h3>
                    <span class="badge" style="color:{badge_color(check.get('status','INCONCLUSIVE'))}; border-color:{badge_color(check.get('status','INCONCLUSIVE'))};">{safe(check.get('status', 'INCONCLUSIVE'))}</span>
                </div>
                <div class="meta"><strong>HTTP status:</strong> {safe(check.get('status_code', '—'))}</div>
                <div class="meta"><strong>Explanation:</strong> {safe(check.get('explanation', ''))}</div>
                <div class="meta"><strong>Suggested fix:</strong> {safe(check.get('suggested_fix') or 'None')}</div>
            </div>
            """
            for check in checks
        )

        if not checks:
            check_cards = f"""
            <div class="card">
                <div class="meta"><strong>Result:</strong> {safe(overall_result)}</div>
                <div class="meta"><strong>Message:</strong> {safe(error_message or 'Run scan to generate the first result.')}</div>
            </div>
            """

        page = f"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>SentinelAPI Dashboard</title>
          <style>
            body {{ font-family: Arial, sans-serif; background: #0b1220; color: #e5e7eb; margin: 0; padding: 32px; }}
            main {{ max-width: 980px; margin: 0 auto; }}
            h1 {{ margin-bottom: 6px; font-size: 2.5rem; }}
            .subtitle {{ color: #94a3b8; margin-bottom: 28px; }}
            .summary {{ background: #172235; border: 1px solid #334155; border-radius: 16px; padding: 24px; margin-bottom: 18px; }}
            .badge {{ display: inline-block; padding: 8px 14px; border: 1px solid; border-radius: 999px; font-weight: bold; }}
            .check-header {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; }}
            .card {{ background: #172235; border: 1px solid #334155; border-radius: 16px; padding: 20px; margin-bottom: 18px; }}
            .meta {{ color: #dbeafe; margin-top: 10px; line-height: 1.6; }}
            button {{ background: #38bdf8; color: #06202d; border: 0; border-radius: 8px; padding: 12px 18px; font-weight: bold; cursor: pointer; }}
            .actions {{ margin-top: 14px; }}
            .error {{ color: #fca5a5; margin-top: 12px; }}
          </style>
        </head>
        <body>
          <main>
            <h1>SentinelAPI Dashboard</h1>
            <p class="subtitle">Order-ownership authorization checks</p>

            <div class="summary">
              <div class="badge" style="color:{badge_color(overall_result)}; border-color:{badge_color(overall_result)};">{safe(overall_result)}</div>
              <h2 style="margin-top: 16px;">Overall result</h2>
              <div class="meta"><strong>Checked at (UTC):</strong> {safe(checked_at)}</div>
              <div class="meta"><strong>Scan summary:</strong> {safe(error_message if error_message else 'All checks completed successfully.')}</div>
              <div class="actions">
                <form action="/scan" method="post" style="display:inline;">
                  <button type="submit">Run scan</button>
                </form>
                <button type="button" onclick="location.reload()">Refresh result</button>
              </div>
            </div>

            {check_cards}
          </main>
        </body>
        </html>
        """

        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print("Dashboard: http://127.0.0.1:8501")
    HTTPServer(("127.0.0.1", 8501), Dashboard).serve_forever()

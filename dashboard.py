import html
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT_FILE = ROOT / "scan_report.json"
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"


class Dashboard(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/scan":
            self.send_error(404)
            return

        try:
            run = subprocess.run(
                [sys.executable, str(SCANNER_FILE)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if run.returncode != 0:
                self.send_error(500, "Scan failed; check the dashboard terminal")
                print("Scan failed:", run.stdout, run.stderr)
                return
            print(run.stdout)
        except subprocess.TimeoutExpired:
            self.send_error(504, "Scan timed out; check the dashboard terminal")
            return

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()

    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return

        try:
            report = json.loads(REPORT_FILE.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            report = {
                "result": "NO REPORT",
                "check": "Run the scanner first",
                "explanation": "Start the sandbox API, then click Run scan.",
                "suggested_fix": None,
                "status_code": "—",
                "checked_at": "—",
            }

        def safe(key):
            return html.escape(str(report.get(key) or "—"))

        result = str(report.get("result", "NO REPORT"))
        color = "#ef4444" if result == "VULNERABLE" else (
            "#22c55e" if result == "PASS" else "#f59e0b"
        )

        page = f"""
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <title>SentinelAPI Dashboard</title>
          <style>
            body {{ font-family: Arial, sans-serif; background: #0b1220;
                    color: #e5e7eb; margin: 0; padding: 48px; }}
            main {{ max-width: 760px; margin: auto; }}
            h1 {{ font-size: 38px; margin-bottom: 6px; }}
            .subtitle {{ color: #94a3b8; margin-bottom: 36px; }}
            .card {{ background: #172235; border: 1px solid #334155;
                     border-radius: 16px; padding: 28px; margin-bottom: 18px; }}
            .badge {{ display: inline-block; color: {color}; border: 1px solid {color};
                      padding: 9px 15px; border-radius: 30px; font-weight: bold; }}
            .label {{ color: #94a3b8; font-size: 14px; margin-bottom: 7px; }}
            .value {{ font-size: 19px; margin-bottom: 24px; }}
            button {{ background: #38bdf8; border: 0; padding: 12px 18px;
                      border-radius: 8px; font-weight: bold; cursor: pointer;
                      margin-right: 8px; }}
          </style>
        </head>
        <body>
          <main>
            <h1>SentinelAPI</h1>
            <p class="subtitle">Local API authorization scan</p>
            <div class="card">
              <span class="badge">{safe("result")}</span>
              <h2>{safe("check")}</h2>
              <p>{safe("explanation")}</p>
            </div>
            <div class="card">
              <div class="label">HTTP status</div><div class="value">{safe("status_code")}</div>
              <div class="label">Suggested fix</div><div class="value">{safe("suggested_fix")}</div>
              <div class="label">Checked at (UTC)</div><div class="value">{safe("checked_at")}</div>
              <form action="/scan" method="post" style="display: inline">
                <button type="submit">Run scan</button>
              </form>
              <button onclick="location.reload()">Refresh result</button>
            </div>
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


print("Dashboard: http://127.0.0.1:8501")
HTTPServer(("127.0.0.1", 8501), Dashboard).serve_forever()
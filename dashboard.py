import html
import io
import json
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
REPORT_FILE = ROOT / "scan_report.json"
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self.serve_file(FRONTEND / "index.html", "text/html; charset=utf-8")

        if self.path == "/report":
            return self.serve_report()

        # Handle static assets (/static/... or direct root requests like /style.css)
        if self.path.startswith("/static/"):
            rel_path = self.path[len("/static/"):]
        else:
            rel_path = self.path.lstrip("/")

        target = FRONTEND / rel_path

        if target.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif target.suffix == ".js":
            content_type = "application/javascript; charset=utf-8"
        elif target.suffix in (".png", ".jpg", ".jpeg", ".svg", ".ico"):
            content_type = f"image/{target.suffix.lstrip('.')}"
        else:
            content_type = "application/octet-stream"

        return self.serve_file(target, content_type)

    def do_POST(self):
        if self.path == "/scan":
            try:
                run = subprocess.run(
                    [sys.executable, str(SCANNER_FILE)],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                out = {"returncode": run.returncode}
                self.wfile.write(json.dumps(out).encode("utf-8"))
            except subprocess.TimeoutExpired:
                self.send_error(504, "Scanner timed out")
            except Exception as e:
                self.send_error(500, str(e))
            return

        self.send_error(404, "Endpoint not found")

    def serve_file(self, path: Path, content_type: str):
        if not path.exists() or not path.is_file():
            self.send_error(404, f"File {self.path} not found")
            return

        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_report(self):
        try:
            raw = REPORT_FILE.read_text(encoding="utf-8")
            report = json.loads(raw)
        except FileNotFoundError:
            report = {
                "checked_at_utc": "—",
                "overall_result": "INCONCLUSIVE",
                "checks": [],
                "error": "No scan report available. Run scan to generate one.",
            }
        except json.JSONDecodeError:
            report = {
                "checked_at_utc": "—",
                "overall_result": "INCONCLUSIVE",
                "checks": [],
                "error": "Report is invalid JSON.",
            }

        body = json.dumps(report).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(server_class=HTTPServer, handler_class=DashboardHandler, port=8501):
    server_address = ("127.0.0.1", port)
    httpd = server_class(server_address, handler_class)
    print(f"Dashboard running at: http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    run()

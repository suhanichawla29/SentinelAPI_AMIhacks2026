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

class Dashboard(BaseHTTPRequestHandler):
    def do_GET(self):
            if self.path in ('/', '/index.html'):
                target = FRONTEND / "index.html"
                content_type = "text/html; charset=utf-8"
            elif self.path == '/report':
                self.serve_report()
                return
            else:
                # Strip leading slash to resolve static files from FRONTEND
                rel_path = self.path.lstrip('/')
                target = FRONTEND / rel_path
                if target.suffix == '.css':
                    content_type = "text/css"
                elif target.suffix == '.js':
                    content_type = "application/javascript"
                elif target.suffix in ('.png', '.jpg', '.jpeg', '.svg', '.ico'):
                    content_type = f"image/{target.suffix.lstrip('.')}"
                else:
                    content_type = "application/octet-stream"

            if target.exists() and target.is_file():
                data = target.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404, f"File {self.path} not found")
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


class DashboardHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/":
            return self.serve_file(FRONTEND / 'index.html', 'text/html; charset=utf-8')
        if self.path.startswith('/static/'):
            path = FRONTEND / self.path[len('/static/'):]
            if path.suffix == '.css':
                return self.serve_file(path, 'text/css; charset=utf-8')
            if path.suffix == '.js':
                return self.serve_file(path, 'application/javascript; charset=utf-8')
            return self.serve_file(path, 'application/octet-stream')
        if self.path == '/report':
            return self.serve_report()
        self.send_error(404)

    def do_POST(self):
        if self.path == '/scan':
            # Run scanner safely
            try:
                run = subprocess.run([sys.executable, str(SCANNER_FILE)], cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                out = {'returncode': run.returncode}
                self.wfile.write(json.dumps(out).encode('utf-8'))
            except subprocess.TimeoutExpired:
                self.send_error(504, 'Scanner timed out')
            return
        self.send_error(404)

    def serve_file(self, path: Path, content_type: str):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return


        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def serve_report(self):
        try:
            raw = REPORT_FILE.read_text(encoding='utf-8')
            report = json.loads(raw)
        except FileNotFoundError:
            report = {
                'checked_at_utc': '—',
                'overall_result': 'INCONCLUSIVE',
                'checks': [],
                'error': 'No scan report available. Run scan to generate one.'
            }
        except json.JSONDecodeError:
            report = {
                'checked_at_utc': '—',
                'overall_result': 'INCONCLUSIVE',
                'checks': [],
                'error': 'Report is invalid JSON.'
            }
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        body = json.dumps(report).encode('utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)



print("Dashboard: http://127.0.0.1:8501")
HTTPServer(("127.0.0.1", 8501), Dashboard).serve_forever()

if __name__ == '__main__':
    print('Dashboard: http://127.0.0.1:8501')
    HTTPServer(('127.0.0.1', 8501), DashboardHandler).serve_forever()


import uuid
import json
import subprocess
import sys
from pathlib import Path
from fastapi import FastAPI, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="SentinelAPI Scalable Scanner")

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"

# Serve static frontend files
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")

class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8000"

def run_scanner_job(scan_id: str, target_url: str):
    """Executes in background worker thread so the UI never hangs."""
    out_file = REPORTS_DIR / f"{scan_id}.json"
    try:
        run = subprocess.run(
            [sys.executable, str(SCANNER_FILE), "--target", target_url, "--out", str(out_file)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120
        )
        # If scanner didn't create a custom report, create a fallback
        if not out_file.exists():
            fallback = {
                "scan_id": scan_id,
                "target_url": target_url,
                "overall_result": "PASS" if run.returncode == 0 else "FAIL",
                "checks": [],
                "output": run.stdout or run.stderr
            }
            out_file.write_text(json.dumps(fallback, indent=2), encoding="utf-8")
    except Exception as e:
        err_report = {
            "scan_id": scan_id,
            "target_url": target_url,
            "overall_result": "FAIL",
            "error": str(e)
        }
        out_file.write_text(json.dumps(err_report, indent=2), encoding="utf-8")

@app.get("/")
def serve_dashboard():
    return FileResponse(FRONTEND / "index.html")

@app.get("/style.css")
def serve_css():
    return FileResponse(FRONTEND / "style.css")

@app.get("/script.js")
def serve_js():
    return FileResponse(FRONTEND / "script.js")

@app.post("/scan")
def trigger_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())[:8]
    bg.add_task(run_scanner_job, scan_id, req.target_url)
    return {"status": "queued", "scan_id": scan_id}

@app.get("/report")
def get_latest_or_default_report():
    """Backwards compatible endpoint for the dashboard."""
    report_file = ROOT / "scan_report.json"
    if report_file.exists():
        return json.loads(report_file.read_text(encoding="utf-8"))
    return {"checked_at_utc": "—", "overall_result": "INCONCLUSIVE", "checks": []}

@app.get("/report/{scan_id}")
def get_specific_report(scan_id: str):
    target_path = REPORTS_DIR / f"{scan_id}.json"
    if not target_path.exists():
        return {"status": "processing", "scan_id": scan_id}
    return json.loads(target_path.read_text(encoding="utf-8"))
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import BackgroundTasks, FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI(title="SentinelAPI Scalable Scanner")

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
SCANNER_FILE = ROOT / "Scanner" / "Scan.py"
DEFAULT_REPORT = ROOT / "scan_report.json"
SCANS = {}

app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8000"
    spec_url: Optional[str] = "http://127.0.0.1:8000/openapi.json"
    priority: str = "all"


def utc_timestamp():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fallback_report(scan_id, target_url, error, output=""):
    return {
        "scan_id": scan_id,
        "target_url": target_url,
        "checked_at_utc": utc_timestamp(),
        "overall_result": "FAIL",
        "checks": [],
        "error": error,
        "output": output,
    }


def save_report(out_file, report):
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")


def run_scanner_job(scan_id: str, target_url: str, spec_url: Optional[str], priority: str):
    out_file = REPORTS_DIR / f"{scan_id}.json"
    scan = SCANS[scan_id]
    scan["status"] = "running"
    try:
        command = [
            sys.executable,
            str(SCANNER_FILE),
            "--target", target_url,
            "--spec", spec_url or "",
            "--priority", priority,
            "--out", str(out_file),
        ]
        run = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if not out_file.exists():
            save_report(out_file, fallback_report(
                scan_id,
                target_url,
                "Scanner completed without generating the requested report file.",
                run.stdout or run.stderr,
            ))
            scan["status"] = "failed"
            return

        report = json.loads(out_file.read_text(encoding="utf-8"))
        report["scan_id"] = scan_id
        report["target_url"] = target_url
        save_report(out_file, report)
        scan["status"] = "completed" if run.returncode == 0 else "failed"
    except Exception as error:
        save_report(out_file, fallback_report(scan_id, target_url, str(error)))
        scan["status"] = "failed"


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
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "status": "queued",
        "target_url": request.target_url,
        "timestamp": utc_timestamp(),
    }
    background_tasks.add_task(
        run_scanner_job,
        scan_id,
        request.target_url,
        request.spec_url,
        request.priority,
    )
    SCANS[scan_id]["status"] = "running"
    return {"status": "queued", "scan_id": scan_id}


@app.get("/scans")
def list_scans():
    return [
        {"scan_id": scan_id, **scan}
        for scan_id, scan in SCANS.items()
    ]


@app.get("/report")
def get_latest_report():
    if DEFAULT_REPORT.exists():
        try:
            return json.loads(DEFAULT_REPORT.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return fallback_report(
        None,
        "http://127.0.0.1:8000",
        "No scan report available yet. Click Run Security Scan to generate one.",
    )


@app.get("/report/{scan_id}")
def get_specific_report(scan_id: str):
    report_path = REPORTS_DIR / f"{scan_id}.json"
    if not report_path.exists():
        return {"status": SCANS.get(scan_id, {}).get("status", "running"), "scan_id": scan_id}
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "failed", "scan_id": scan_id}
    report["status"] = "completed"
    return report
    
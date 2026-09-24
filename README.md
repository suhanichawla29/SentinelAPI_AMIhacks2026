# SentinelAPI_AMIhacks2026
Zero-Trust API Vulnerability Scanner
SentinelAPI checks whether a logged-in test user can view another test user's sample order, then shows the result and evidence in a report.

## Hackathon scope

We test only our own sandbox API using fictional accounts and orders.
Our first check focuses on order ownership.
 ## Run the demo

Install the dependencies:

```powershell
python -m pip install "fastapi[standard]" httpx
```

Start the API from the repository folder:

```powershell
python -m uvicorn Sandbox_api.main:app --reload
```

Open a second terminal and run the scanner:

```powershell
python Scanner/Scan.py
```

In fixed mode, the scanner should report `PASS` because Asha cannot read Ravi’s order. To demonstrate the finding, stop the API with Ctrl+C, then start it in vulnerable mode:

```powershell
$env:SANDBOX_MODE="vulnerable"
python -m uvicorn Sandbox_api.main:app --reload
```
### View the dashboard

With the API running, run the scanner in a second terminal:

```powershell
python Scanner/Scan.py
```

Start the dashboard in a third terminal:

```powershell
python dashboard.py
```

Open http://127.0.0.1:8501. After each scan, click **Refresh result** to see the latest result.

Run the same scanner again. It should report `VULNERABILITY FOUND`. Stop the API and run `Remove-Item Env:SANDBOX_MODE` to return to fixed mode.

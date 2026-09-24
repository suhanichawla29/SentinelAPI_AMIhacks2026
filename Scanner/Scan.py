import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

scanner_dir = Path(__file__).resolve().parent
config = json.loads((scanner_dir / "config.json").read_text(encoding="utf-8"))
report_file = scanner_dir.parent / "scan_report.json"

base_url = config["base_url"].rstrip("/")
headers = {"Authorization": f"Bearer {config['token']}"}
own_url = f"{base_url}/orders/{config['own_order_id']}"
other_url = f"{base_url}/orders/{config['other_order_id']}"

try:
    own_response = httpx.get(own_url, headers=headers, timeout=5)

    if (
        own_response.status_code != 200
        or own_response.json().get("owner") != config["own_user"]
    ):
        print("INCONCLUSIVE: The test user could not read their own order.")
        raise SystemExit(1)
    no_token_response = httpx.get(own_url, timeout=5)
    response = httpx.get(other_url, headers=headers, timeout=5)

    if no_token_response.status_code == 200:
        result = "VULNERABLE"
        explanation = "The API returned an order without a token."
        fix = "Require authentication before returning an order."
    elif (
        response.status_code == 200
        and response.json().get("owner") == config["other_user"]
    ):
        result = "VULNERABLE"
        explanation = "The test user could read another user's order."
        fix = "Check that the order belongs to the authenticated user before returning it."
    elif response.status_code == 403 and no_token_response.status_code == 401:
        result = "PASS"
        explanation = "The API blocked access to another user's order and rejected the missing token."
        fix = None
    else:
        result = "INCONCLUSIVE"
        explanation = f"Unexpected responses: order {response.status_code}, no token {no_token_response.status_code}"
        fix = None

    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "check": "Order ownership authorization",
        "request": f"GET /orders/{config['other_order_id']}",
        "status_code": response.status_code,
        "result": result,
        "explanation": explanation,
        "suggested_fix": fix,
    }

    report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{result}: {explanation}")
    print("Report saved to scan_report.json")

except (httpx.RequestError, ValueError) as error:
    print("Scan could not complete:", error)
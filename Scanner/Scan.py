import json
from datetime import datetime, timezone

import httpx

url = "http://127.0.0.1:8000/orders/202"
headers = {"Authorization": "Bearer asha-demo-token"}

    try:
    own_order = httpx.get(
        "http://127.0.0.1:8000/orders/101",
        headers=headers,
        timeout=5,
    )

    if own_order.status_code != 200 or own_order.json().get("owner") != "asha":
        print("INCONCLUSIVE: Asha cannot access her own order. Check the API or token.")
        raise SystemExit(1)

    response = httpx.get(url, headers=headers, timeout=5)

    if response.status_code == 200 and response.json().get("owner") == "ravi":
        
    response = httpx.get(url, headers=headers, timeout=5)

    if response.status_code == 200 and response.json().get("owner") == "ravi":
        result = "VULNERABLE"
        explanation = "Asha could read Ravi's order."
        fix = "Check that the order belongs to the authenticated user before returning it."
    elif response.status_code == 403:
        result = "PASS"
        explanation = "The API blocked Asha from reading Ravi's order."
        fix = None
    else:
        result = "INCONCLUSIVE"
        explanation = f"Unexpected response: {response.text[:200]}"
        fix = None

    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "check": "Order ownership authorization",
        "request": "Asha requests Ravi's order 202",
        "status_code": response.status_code,
        "result": result,
        "explanation": explanation,
        "suggested_fix": fix,
    }

    with open("scan_report.json", "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)

    print(f"{result}: {explanation}")
    print("Report saved to scan_report.json")

except (httpx.RequestError, ValueError) as error:
    print("Scan could not complete:", error)
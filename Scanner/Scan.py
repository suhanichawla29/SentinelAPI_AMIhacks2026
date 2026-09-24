import httpx

URL = "http://127.0.0.1:8000/orders/202"
HEADERS = {"Authorization": "Bearer asha-demo-token"}

try:
    response = httpx.get(URL, headers=HEADERS, timeout=5)
    print(f"Request: Asha accessing Ravi's order (202)")
    print(f"Status: {response.status_code}")

    if response.status_code == 200 and response.json().get("owner") == "ravi":
        print("VULNERABILITY FOUND: Asha can read Ravi's order.")
        print("Evidence:", response.json())
    elif response.status_code == 403:
        print("PASS: API blocked access to Ravi's order.")
    else:
        print("INCONCLUSIVE: Unexpected response:", response.text)

except httpx.RequestError as error:
    print("Could not reach the sandbox API:", error)
import os
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(title="SentinelAPI Sandbox Orders API")

# Simulation modes configured via environment variable:
# - "secure": Everything strictly protected (All PASS)
# - "vulnerable": BOLA enabled on orders (Case 3 FAILS)
# - "no_auth": Auth disabled completely / public endpoint (Case 2 FAILS)
# - "broken_auth": Rejects all tokens / server down (Case 1 FAILS)
MODE = os.getenv("SANDBOX_MODE", "secure").lower()


class DemoBearerAuth(HTTPBearer):
    async def __call__(self, request: Request):
        if MODE == "no_auth":
            # Broken Auth Simulation: completely skips token verification
            return None

        if MODE == "broken_auth":
            # Simulates revoked keys or broken auth service
            raise HTTPException(status_code=401, detail="Authentication service unavailable or invalid credentials")

        try:
            return await super().__call__(request)
        except HTTPException as exc:
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header"
            ) from exc


bearer = DemoBearerAuth(auto_error=False if MODE == "no_auth" else True)

USERS = {
    "asha-demo-token": "asha",
    "ravi-demo-token": "ravi",
}

ORDERS = {
    "ord-101": {"id": "ord-101", "owner": "asha", "item": "Laptop Sleeve", "amount": 29.99},
    "ord-102": {"id": "ord-102", "owner": "ravi", "item": "Mechanical Keyboard", "amount": 120.00},
}


@app.get("/orders/{order_id}")
async def get_order(order_id: str, creds: HTTPAuthorizationCredentials = Security(bearer)):
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")

    # If in no_auth mode, return data openly
    if MODE == "no_auth":
        return order

    user = USERS.get(creds.credentials if creds else None)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Vulnerable mode allows reading anyone's order (BOLA)
    if MODE == "vulnerable":
        return order

    # Secure zero-trust enforcement: verify ownership
    if order["owner"] != user:
        raise HTTPException(status_code=403, detail="Forbidden: You do not own this order")

    return order
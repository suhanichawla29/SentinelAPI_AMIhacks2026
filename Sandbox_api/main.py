import os

from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(title="SentinelAPI Sandbox Orders API")


class DemoBearerAuth(HTTPBearer):
    async def __call__(self, request: Request):
        try:
            return await super().__call__(request)
        except HTTPException as exc:
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header",
            ) from exc


bearer = DemoBearerAuth()

# Fictional test data only. These are demo tokens, not real credentials.
USERS = {
    "asha-demo-token": "asha",
    "ravi-demo-token": "ravi",
}

ORDERS = {
    101: {"order_id": 101, "owner": "asha", "item": "Notebook"},
    202: {"order_id": 202, "owner": "ravi", "item": "Backpack"},
}


@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    credentials: HTTPAuthorizationCredentials = Security(bearer),
):
    user = USERS.get(credentials.credentials)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid demo token")

    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # The intentionally faulty mode exists only for this local sandbox demo.
    if os.getenv("SANDBOX_MODE") != "vulnerable" and order["owner"] != user:
        raise HTTPException(status_code=403, detail="Not your order")

    return order

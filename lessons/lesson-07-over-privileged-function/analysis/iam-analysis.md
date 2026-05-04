# IAM Permission Analysis — DVSA-SEND-RECEIPT-EMAIL

## Granted vs. Actually Used

| Policy | Permissions Granted | Permissions Actually Used |
|--------|--------------------|--------------------------| 
| `SendReceiptFunctionRolePolicy1` | `s3:GetObject`, `s3:PutObject`, `s3:GetObjectAcl`, `s3:PutObjectAcl` on **all buckets** | Upload to receipts bucket only |
| `SendReceiptFunctionRolePolicy2` | `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:Scan`, `dynamodb:DeleteItem` on **all tables** | Read from DVSA-ORDERS-DB only |
| `AmazonSESFullAccess` | 40+ SES actions including `ses:CreateConfigurationSet`, `ses:DeleteIdentity`, etc. | `ses:SendEmail` only |
| `SendReceiptFunctionRolePolicy3` | `sts:GetCallerIdentity` | `sts:GetCallerIdentity` ✓ |
| `AWSLambdaBasicExecutionRole` | CloudWatch Logs access | `logs:CreateLogStream` ✓ |

CloudTrail policy generation confirms only 3 actions were observed during normal operation:
- `logs:CreateLogStream`
- `kms:Decrypt`
- `sts:GetCallerIdentity`

## Blast Radius Before Fix

If `DVSA-SEND-RECEIPT-EMAIL` were compromised (e.g., via a supply chain attack on an npm
dependency, or via code injection from another Lambda):

- **S3:** attacker can read/write any S3 bucket in the account — including source code buckets,
  CloudTrail logs, config exports, and all other DVSA buckets.
- **DynamoDB:** attacker can read/modify/delete all rows in any DynamoDB table in the account.
- **SES:** attacker can send email as any verified identity, delete SES identities, or configure
  email forwarding.

## Blast Radius After Fix

If `DVSA-SEND-RECEIPT-EMAIL` were compromised after applying the least-privilege fixes:

- **S3:** attacker can only access the receipts bucket — no other buckets.
- **DynamoDB:** attacker can only query DVSA-ORDERS-DB — no other tables.
- **SES:** attacker can only send email — cannot modify SES configuration.

## How to Generate a CloudTrail-Based Least-Privilege Policy

1. Create a CloudTrail trail: **CloudTrail → Create trail** → name `dvsa-policygen-trail`.
2. Trigger the Lambda by placing a DVSA order.
3. Wait ~5 minutes for events to propagate.
4. **IAM → Roles → SendReceiptFunctionRole → Generate policy**.
5. Select the trail and "Last 1 day" → Generate.
6. Review and download the generated policy JSON.

# API Gateway Throttling Configuration

## Steps to Apply

1. Open **AWS Console → API Gateway**.
2. Click on your DVSA API (e.g., `dvsa`).
3. In the left sidebar, click **Stages** → select the `dvsa` stage.
4. Click the **Default Route Settings** tab (or the specific route `/dvsa/order`).
5. Under **Throttling**, enable throttling and set:
   - **Rate limit:** `5` (requests per second)
   - **Burst limit:** `10` (maximum concurrent requests)
6. Click **Save**.

## Verification

Re-run the DoS exploit script. Requests exceeding the rate limit should receive HTTP 429
(Too Many Requests) instead of being forwarded to the Lambda.

## Important Limitation

API Gateway throttling alone may not fully prevent DoS if:
- The Lambda still processes requests before throttling kicks in
- Multiple stages or routes are configured differently

For complete protection, combine throttling with:
- **DynamoDB conditional writes** to prevent duplicate billing (see Lesson 8 fix)
- **Idempotency keys** stored in DynamoDB to deduplicate requests
- **SQS queue** in front of the billing Lambda to absorb traffic spikes

## AWS CLI Alternative

```bash
aws apigateway update-stage \
  --rest-api-id <your-api-id> \
  --stage-name dvsa \
  --patch-operations \
    op=replace,path=//defaultRouteSettings/throttlingRateLimit,value=5 \
    op=replace,path=//defaultRouteSettings/throttlingBurstLimit,value=10
```

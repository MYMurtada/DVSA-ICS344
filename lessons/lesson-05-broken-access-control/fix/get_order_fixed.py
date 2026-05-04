"""
Lesson 5 — Broken Access Control Fix

Root cause: is_admin and status were read directly from the request body, letting
any authenticated user escalate privileges by simply adding "isAdmin": "true".

Fixes applied:
  1. is_admin is derived solely from the cryptographically verified Cognito JWT.
  2. Dangerous client-supplied fields (isAdmin, status) are stripped before dispatch.
  3. All fields are filtered through an explicit allowlist.
  4. A top-level exception boundary prevents stack traces from reaching clients.
     (This also closes the Lesson 10 information-disclosure issue.)
"""
import json
import os
import logging
import urllib.request
from functools import lru_cache

import jwt  # pip install PyJWT[cryptography]

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_BODY_ALLOWLIST = {"action", "order-id", "cart-id", "items"}


# ── Response helpers ──────────────────────────────────────────────────────────

def _respond(http_status: int, body_dict: dict) -> dict:
    return {
        "statusCode": http_status,
        "headers":    {"Content-Type": "application/json"},
        "body":       json.dumps(body_dict),
    }

def _ok(**kwargs) -> dict:
    return _respond(200, {"status": "ok",  **kwargs})

def _fail(http_status: int, msg: str) -> dict:
    return _respond(http_status, {"status": "err", "msg": msg})


# ── JWT verification ──────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _cached_jwks() -> dict:
    region   = os.environ["AWS_REGION"]
    pool_id  = os.environ["userpoolid"]
    url      = f"https://cognito-idp.{region}.amazonaws.com/{pool_id}/.well-known/jwks.json"
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read())


def _verify_token(event: dict) -> dict:
    """
    Extract, verify, and return the JWT claims from the Authorization header.
    Raises PermissionError on any failure.
    """
    raw_header = event.get("headers", {}).get("Authorization", "")
    token      = raw_header.replace("Bearer ", "").strip()
    if not token:
        raise PermissionError("Missing Authorization header")

    try:
        kid       = jwt.get_unverified_header(token)["kid"]
        jwks_keys = _cached_jwks()["keys"]
        match     = next((k for k in jwks_keys if k["kid"] == kid), None)
        if match is None:
            raise PermissionError("No matching key found in JWKS")
        pub_key = jwt.algorithms.RSAAlgorithm.from_jwk(match)
        return jwt.decode(token, pub_key, algorithms=["RS256"], options={"verify_aud": False})
    except PermissionError:
        raise
    except Exception as exc:
        raise PermissionError(f"Token verification failed: {exc}") from exc


# ── Handler ───────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    try:
        claims = _verify_token(event)

        # Privilege ALWAYS comes from the verified token — never from the body.
        is_admin = "admins" in claims.get("cognito:groups", [])
        caller   = claims["sub"]

        raw  = event.get("body", "{}")
        body = json.loads(raw) if isinstance(raw, str) else raw

        # Silently remove any privilege-escalation fields the client supplied.
        body.pop("isAdmin", None)
        body.pop("status",  None)

        # Keep only known-safe fields.
        body     = {k: v for k, v in body.items() if k in _BODY_ALLOWLIST}
        order_id = body.get("order-id")

        if is_admin:
            return _ok(order=fetch_any_order(order_id))
        return _ok(order=fetch_own_order(order_id, caller))

    except PermissionError as exc:
        logger.warning("Auth failure: %s", exc)
        return _fail(401, "unauthorized")

    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("Bad request: %s", exc)
        return _fail(400, "bad request")

    except Exception:
        # Stack trace goes to CloudWatch; the client receives nothing diagnostic.
        logger.exception("Unhandled exception")
        return _fail(500, "internal error")


# ── Data-layer stubs ─ replace with real DynamoDB calls ──────────────────────

def fetch_own_order(order_id: str, owner_sub: str):
    """Return the order only when its userId matches owner_sub."""
    raise NotImplementedError

def fetch_any_order(order_id: str):
    """Admin path — return any order regardless of owner."""
    raise NotImplementedError

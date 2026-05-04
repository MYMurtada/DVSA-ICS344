"""
Lesson 10 — Unhandled Exceptions Fix

Vulnerable pattern:
    def lambda_handler(event, context):
        body     = json.loads(event.get("body", "{}"))
        is_admin = json.loads(event.get("isAdmin", "false").lower())
        # No exception boundary → AttributeError on non-string isAdmin leaks
        # the full stack trace to the caller via the Lambda error format.

This version:
  - wraps the entire handler in a try/except chain
  - validates and sanitises the body before any business logic runs
  - logs full tracebacks to CloudWatch only — nothing diagnostic goes to clients
"""
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_ALLOWED_FIELDS = {"action", "order-id", "cart-id", "items"}


# ── Response builders ─────────────────────────────────────────────────────────

def _respond(status_code: int, body_dict: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers":    {"Content-Type": "application/json"},
        "body":       json.dumps(body_dict),
    }

def _ok(**kwargs)    -> dict: return _respond(200, {"status": "ok",  **kwargs})
def _bad(msg: str)   -> dict: return _respond(400, {"status": "err", "msg": msg})
def _fault()         -> dict: return _respond(500, {"status": "err", "msg": "internal error"})


# ── Input validation ──────────────────────────────────────────────────────────

def _sanitise(raw_body) -> dict:
    """
    Validate the request body type and strip any field not on the allowlist.
    Raises ValueError for structurally invalid input.
    """
    if not isinstance(raw_body, dict):
        raise ValueError("Request body must be a JSON object")
    action = raw_body.get("action")
    if not action or not isinstance(action, str):
        raise ValueError("'action' must be a non-empty string")
    # Stripping unknown keys removes isAdmin, status, and anything else injected
    return {k: v for k, v in raw_body.items() if k in _ALLOWED_FIELDS}


# ── Handler ───────────────────────────────────────────────────────────────────

def lambda_handler(event, context):
    try:
        raw  = event.get("body", "{}")
        body = _sanitise(json.loads(raw) if isinstance(raw, str) else raw)

        # isAdmin never survives _sanitise() — derive from verified JWT instead
        is_admin = _admin_from_token(event)
        caller   = _sub_from_token(event)
        order_id = body.get("order-id")

        if is_admin:
            return _ok(order=fetch_any_order(order_id))
        return _ok(order=fetch_own_order(order_id, caller))

    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        logger.warning("Request rejected: %s", exc)
        return _bad("bad request")

    except Exception:
        # Full context available in CloudWatch; client sees only a generic 500.
        logger.exception("Unexpected error in lambda_handler")
        return _fault()


# ── Stubs — implement with real JWT verification and DynamoDB calls ───────────

def _admin_from_token(event: dict) -> bool:
    """Verify the JWT and check cognito:groups. See Lesson 5 fix for full impl."""
    return False

def _sub_from_token(event: dict) -> str:
    raise NotImplementedError

def fetch_own_order(order_id: str, owner_sub: str):
    raise NotImplementedError

def fetch_any_order(order_id: str):
    raise NotImplementedError

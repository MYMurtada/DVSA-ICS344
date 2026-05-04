#!/usr/bin/env bash
# Helper — decode a DVSA JWT and print the key identity fields.
# Usage: TOKEN="eyJ..." bash scripts/get_token.sh

set -euo pipefail

if [[ -z "${TOKEN:-}" ]]; then
    printf 'Usage: TOKEN="<your-jwt>" bash %s\n' "$0"
    exit 1
fi

python3 - << 'PYEOF'
import os, json, base64, sys

def _decode_payload(token: str) -> dict:
    segment = token.split('.')[1]
    padding = (4 - len(segment) % 4) % 4
    return json.loads(base64.urlsafe_b64decode((segment + '=' * padding).encode()))

try:
    data = _decode_payload(os.environ["TOKEN"])
except Exception as exc:
    print(f"Failed to decode token: {exc}", file=sys.stderr)
    sys.exit(1)

fields = [
    ("username", data.get("username") or data.get("cognito:username", "n/a")),
    ("sub",      data.get("sub",     "n/a")),
    ("email",    data.get("email",   "n/a")),
    ("groups",   data.get("cognito:groups", [])),
    ("expires",  data.get("exp",    "n/a")),
]
for label, value in fields:
    print(f"{label:<10}: {value}")
PYEOF

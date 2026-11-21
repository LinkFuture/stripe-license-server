#!/usr/bin/env bash
# Fill one Wrangler environment's D1 id, and optional sender/issuer vars, on the runner.
# Usage: D1_DATABASE_ID=... [LICENSE_ISSUER=...] [MAIL_FROM=...] [MAIL_REPLY_TO=...] \
#        server/scripts/prepare-deploy.sh dev|production
set -euo pipefail

ENV_NAME="${1:?expected dev or production}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "$ENV_NAME" in
  dev) PLACEHOLDER="00000000-0000-4000-8000-000000000001" ;;
  production) PLACEHOLDER="00000000-0000-4000-8000-000000000002" ;;
  *)
    echo "expected dev or production, got ${ENV_NAME}" >&2
    exit 1
    ;;
esac

if [[ ! "${D1_DATABASE_ID:-}" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  echo "D1_DATABASE_ID must be a UUID from the GitHub ${ENV_NAME} environment (variable or secret)." >&2
  exit 1
fi

python3 - "$ENV_NAME" "$PLACEHOLDER" "$D1_DATABASE_ID" << 'PY'
import os
import pathlib
import sys

env_name, placeholder, database_id = sys.argv[1:4]
path = pathlib.Path("wrangler.toml")
text = path.read_text()
needle = f'database_id = "{placeholder}"'
if needle not in text:
    raise SystemExit(f"placeholder {placeholder} not found in wrangler.toml")
text = text.replace(needle, f'database_id = "{database_id}"', 1)

header = f"[env.{env_name}.vars]\n"
if header not in text:
    raise SystemExit(f"missing {header.strip()} in wrangler.toml")
lines = []
for key in ("LICENSE_ISSUER", "MAIL_FROM", "MAIL_REPLY_TO"):
    value = os.environ.get(key, "")
    if not value:
        continue
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    lines.append(f'{key} = "{escaped}"')
if lines:
    text = text.replace(header, header + "\n".join(lines) + "\n", 1)
path.write_text(text)
print(f"prepared wrangler env {env_name}")
PY

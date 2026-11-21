#!/usr/bin/env bash
# Fill one Wrangler environment's D1 id on the runner.
# Usage: D1_DATABASE_ID=... server/scripts/prepare-deploy.sh dev|production
# Sender, reply-to, and issuer are Worker secrets, not fields written into wrangler.toml.
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

python3 - "$PLACEHOLDER" "$D1_DATABASE_ID" << 'PY'
import pathlib
import sys

placeholder, database_id = sys.argv[1:3]
path = pathlib.Path("wrangler.toml")
text = path.read_text()
needle = f'database_id = "{placeholder}"'
if needle not in text:
    raise SystemExit(f"placeholder {placeholder} not found in wrangler.toml")
path.write_text(text.replace(needle, f'database_id = "{database_id}"', 1))
print(f"prepared wrangler database id for {placeholder}")
PY

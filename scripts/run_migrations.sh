#!/usr/bin/env bash
set -euo pipefail

: "${SURREAL_URL:=http://localhost:8000}"
: "${SURREAL_NS:=app}"
: "${SURREAL_DB:=dashboard}"
: "${SURREAL_USER:=root}"
: "${SURREAL_PASS:=root}"

echo "Applying migrations to $SURREAL_URL (NS=$SURREAL_NS DB=$SURREAL_DB)"
curl -sS -X POST \
  -u "${SURREAL_USER}:${SURREAL_PASS}" \
  -H "Surreal-NS: ${SURREAL_NS}" \
  -H "Surreal-DB: ${SURREAL_DB}" \
  -H "Accept: application/json" \
  --data-binary @db/migrations/001_init.surql \
  "${SURREAL_URL}/sql" | jq -r '.[].status // "ok"'

echo "Done."

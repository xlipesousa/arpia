#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8000"
HAS_JQ="no"
if command -v jq >/dev/null 2>&1; then
  HAS_JQ="yes"
fi

echo "Health (api): ${BASE}/api/health/"
if [ "$HAS_JQ" = "yes" ]; then
  curl -sS "${BASE}/api/health/" | jq .
else
  curl -sS "${BASE}/api/health/"
fi

echo
echo "Health (core): ${BASE}/health/"
if [ "$HAS_JQ" = "yes" ]; then
  curl -sS "${BASE}/health/" | jq .
else
  curl -sS "${BASE}/health/"
fi

echo
echo "List projects:"
if [ "$HAS_JQ" = "yes" ]; then
  curl -sS "${BASE}/api/projects/" | jq .
else
  curl -sS "${BASE}/api/projects/"
fi

echo
echo "Post endpoint (reconcile) - substitua <PROJECT_UUID> antes de executar:"
cat <<'JSON'
{
  "ip": "192.0.2.10",
  "port": 8080,
  "raw": {"service":"web","protocol":"tcp"},
  "project": "<PROJECT_UUID>",
  "source": "smoke-test"
}
JSON
echo
echo "Uso: PROJECT_UUID=<uuid> bash tests/smoke_test.sh"
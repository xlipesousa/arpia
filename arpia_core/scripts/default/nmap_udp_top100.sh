#!/usr/bin/env bash

# Nmap top 100 UDP ports scan.
# Placeholders:
#   {{PROJECT_NAME}} -> project name
#   {{TARGET_HOSTS}} -> newline-separated hostnames/IPs

set -euo pipefail

PROJECT_NAME="{{PROJECT_NAME}}"
HOSTS=$(cat <<'EOF'
{{TARGET_HOSTS}}
EOF
)

if [[ -z "${HOSTS//[[:space:]]/}" ]]; then
  echo "[WARN] Nenhum host definido para ${PROJECT_NAME}." >&2
  exit 0
fi

OUTPUT_DIR="${OUTPUT_DIR:-./recon/${PROJECT_NAME// /_}}"
mkdir -p "$OUTPUT_DIR"

NMAP_BIN="{{TOOL_NMAP}}"
if [[ -z "${NMAP_BIN//[[:space:]]/}" || "${NMAP_BIN}" == "None" ]]; then
  if command -v nmap >/dev/null 2>&1; then
    NMAP_BIN="$(command -v nmap)"
  else
    NMAP_BIN="nmap"
  fi
fi

echo "[INFO] Executando Nmap UDP top-100"
while IFS= read -r HOST; do
  [[ -z "${HOST//[[:space:]]/}" ]] && continue
  SAFE_HOST=${HOST//[^A-Za-z0-9_.-]/_}
  echo "[INFO] Varredura UDP para ${HOST}"
  "${NMAP_BIN}" -sU --top-ports 100 --open "$HOST" -oA "${OUTPUT_DIR}/nmap_udp_top100_${SAFE_HOST}" || true
  echo
done <<< "$HOSTS"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

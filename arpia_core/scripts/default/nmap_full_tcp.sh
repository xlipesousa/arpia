#!/usr/bin/env bash

# Nmap full TCP scan against discovered hosts.
# Placeholders:
#   {{PROJECT_NAME}} -> project name
#   {{TARGET_HOSTS}} -> newline-separated hostnames/IPs
#   {{TARGET_PORTS}} -> comma-separated ports or range expression

set -euo pipefail

PROJECT_NAME="{{PROJECT_NAME}}"
HOSTS=$(cat <<'EOF'
{{TARGET_HOSTS}}
EOF
)

if [[ -z "${HOSTS//[[:space:]]/}" ]]; then
  echo "[ERROR] Nenhum host configurado para o projeto ${PROJECT_NAME}." >&2
  exit 1
fi

PORT_SPEC="${PORT_SPEC:-{{TARGET_PORTS}}}"
OUTPUT_DIR="${OUTPUT_DIR:-./recon/${PROJECT_NAME// /_}}"
mkdir -p "$OUTPUT_DIR"

echo "[INFO] Escaneando hosts definidos (ports: ${PORT_SPEC})"
while IFS= read -r HOST; do
  [[ -z "${HOST//[[:space:]]/}" ]] && continue
  SAFE_HOST=${HOST//[^A-Za-z0-9_.-]/_}
  echo "[INFO] Nmap full TCP em ${HOST}"
  nmap -sS -sV -O -p "$PORT_SPEC" "$HOST" -oA "${OUTPUT_DIR}/nmap_full_tcp_${SAFE_HOST}" || true
  echo
done <<< "$HOSTS"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

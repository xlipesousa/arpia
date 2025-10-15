#!/usr/bin/env bash

# Nmap network discovery scan.
# Placeholders:
#   {{PROJECT_NAME}}    -> project name
#   {{TARGET_NETWORKS}} -> newline-separated CIDR ranges

set -euo pipefail

PROJECT_NAME="{{PROJECT_NAME}}"
NETWORKS=$(cat <<'EOF'
{{TARGET_NETWORKS}}
EOF
)

if [[ -z "${NETWORKS//[[:space:]]/}" ]]; then
  echo "[WARN] Nenhuma rede configurada para o projeto ${PROJECT_NAME}." >&2
  exit 1
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

echo "[INFO] Executando descoberta de hosts para ${PROJECT_NAME}..."
while IFS= read -r NETWORK; do
  [[ -z "${NETWORK//[[:space:]]/}" ]] && continue
  echo "[INFO] Varredura Nmap -sn em ${NETWORK}"
  "${NMAP_BIN}" -sn "$NETWORK" -oA "${OUTPUT_DIR}/nmap_discovery_${NETWORK//\/-}" || true
  echo
done <<< "$NETWORKS"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

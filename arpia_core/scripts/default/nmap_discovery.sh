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

echo "[INFO] Executando descoberta de hosts para ${PROJECT_NAME}..."
while IFS= read -r NETWORK; do
  [[ -z "${NETWORK//[[:space:]]/}" ]] && continue
  echo "[INFO] Varredura Nmap -sn em ${NETWORK}"
  nmap -sn "$NETWORK" -oA "${OUTPUT_DIR}/nmap_discovery_${NETWORK//\//-}" || true
  echo
done <<< "$NETWORKS"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

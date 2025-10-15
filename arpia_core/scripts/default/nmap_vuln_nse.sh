#!/usr/bin/env bash

# Nmap vulnerability scan leveraging NSE scripts.
# Placeholders:
#   {{PROJECT_NAME}} -> project name
#   {{TARGET_HOSTS}} -> newline-separated hostnames/IPs

set -euo pipefail

PROJECT_NAME="{{PROJECT_NAME}}"
HOSTS=$(cat <<'EOF'
{{TARGET_HOSTS}}
EOF
)

if [[ -z "${HOSTS//[[:space:]]/}" ]] && [[ -z "{{TARGET_NETWORKS}}" ]]; then
  echo "[WARN] Nenhum alvo configurado para ${PROJECT_NAME}." >&2
  exit 0
fi

TARGET_LIST="$HOSTS"
if [[ -z "${TARGET_LIST//[[:space:]]/}" ]]; then
  TARGET_LIST=$(cat <<'EOF'
{{TARGET_NETWORKS}}
EOF
  )
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

echo "[INFO] Executando varredura NSE de vulnerabilidades"
while IFS= read -r TARGET; do
  [[ -z "${TARGET//[[:space:]]/}" ]] && continue
  SAFE_TARGET=${TARGET//[^A-Za-z0-9_.-]/_}
  echo "[INFO] Nmap --script vuln para ${TARGET}"
  "${NMAP_BIN}" -sV --script vuln "$TARGET" -oA "${OUTPUT_DIR}/nmap_vuln_${SAFE_TARGET}" || true
  echo
done <<< "$TARGET_LIST"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

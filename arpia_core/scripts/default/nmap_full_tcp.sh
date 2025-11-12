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

sanitize_port_spec(){
  local raw="$1"
  local tokens=()
  local token
  local cleaned="${raw//[\n\r\t;]/,}"
  IFS=',' read -r -a tokens <<<"$cleaned"
  local result=()
  for token in "${tokens[@]}"; do
    token="${token// /}"
    [[ -z "$token" ]] && continue
    local proto=""
    local port="$token"
    if [[ "$token" == */* ]]; then
      proto="${token##*/}"
      port="${token%%/*}"
    fi
    if [[ ! "$port" =~ ^[0-9]+(-[0-9]+)?$ ]]; then
      continue
    fi
    proto="${proto,,}"
    if [[ "$proto" == "udp" || "$proto" == "u" ]]; then
      continue
    fi
    result+=("${port}")
  done
  local joined="${result[*]}"
  echo "${joined// /,}"
}

PORT_SPEC="${PORT_SPEC:-{{TARGET_PORTS}}}"
PORT_SPEC="$(sanitize_port_spec "$PORT_SPEC")"
if [[ -z "$PORT_SPEC" ]]; then
  PORT_SPEC="1-65535"
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

echo "[INFO] Escaneando hosts definidos (ports: ${PORT_SPEC})"
while IFS= read -r HOST; do
  [[ -z "${HOST//[[:space:]]/}" ]] && continue
  SAFE_HOST=${HOST//[^A-Za-z0-9_.-]/_}
  echo "[INFO] Nmap full TCP em ${HOST}"
  "${NMAP_BIN}" -sS -sV -O -p "$PORT_SPEC" "$HOST" -oA "${OUTPUT_DIR}/nmap_full_tcp_${SAFE_HOST}" || true
  echo
done <<< "$HOSTS"

echo "[INFO] Resultados em ${OUTPUT_DIR}"

#!/usr/bin/env bash

# Rustscan top 1000 TCP/UDP scan for ARPIA
# Placeholders provided by ARPIA macros:
#   PROJECT_NAME      -> nome do projeto
#   TARGET_HOSTS      -> hosts de destino (um por linha)
#   TOOL_RUSTSCAN     -> caminho para o executável rustscan
#   OUTPUT_DIR        -> diretório base opcional para salvar resultados (quando definido)
# Estes placeholders são substituídos quando o script é executado pelo orquestrador.

set -euo pipefail

RUSTSCAN_BIN="{{TOOL_RUSTSCAN}}"
PROJECT_NAME="{{PROJECT_NAME}}"
HOSTS=$(cat <<'EOF'
{{TARGET_HOSTS}}
EOF
)

if [[ -z "${HOSTS//[[:space:]]/}" ]]; then
  echo "[WARN] Nenhum host definido para ${PROJECT_NAME}." >&2
  exit 0
fi

if [[ -z "${RUSTSCAN_BIN}" || ! -x "${RUSTSCAN_BIN}" ]]; then
  echo "[ERROR] Rustscan não encontrado ou sem permissão de execução em '${RUSTSCAN_BIN}'." >&2
  exit 1
fi

OUTPUT_ROOT="${OUTPUT_DIR:-./recon/${PROJECT_NAME// /_}}"
mkdir -p "${OUTPUT_ROOT}"

TCP_RANGE="1-65535"
UDP_RANGE="1-65535"

run_rustscan() {
  local label="$1"
  local output_file="$2"
  shift 2

  set +e
  "${RUSTSCAN_BIN}" "$@" | tee "${output_file}"
  local -a pipe_status=(${PIPESTATUS[@]})
  set -e

  local rustscan_status="${pipe_status[0]:-0}"
  local tee_status="${pipe_status[1]:-0}"

  if [[ "${tee_status}" -ne 0 ]]; then
    echo "[ERROR] Falha ao salvar a saída em '${output_file}' (código ${tee_status})." >&2
    exit "${tee_status}"
  fi

  case "${rustscan_status}" in
    0)
      return 0
      ;;
    2)
      echo "[WARN] Rustscan retornou código 2 durante ${label}. Registro mantido, verifique o log para detalhes." >&2
      return 0
      ;;
    *)
      echo "[ERROR] Rustscan retornou código ${rustscan_status} durante ${label}. Abortando execução." >&2
      exit "${rustscan_status}"
      ;;
  esac
}

while IFS= read -r HOST; do
  [[ -z "${HOST//[[:space:]]/}" ]] && continue
  SAFE_HOST=${HOST//[^A-Za-z0-9_.-]/_}
  HOST_DIR="${OUTPUT_ROOT}/rustscan_${SAFE_HOST}"
  mkdir -p "${HOST_DIR}"

  echo "[INFO] Executando Rustscan TCP completo em ${HOST}"
  run_rustscan "a varredura TCP" "${HOST_DIR}/rustscan_tcp.txt" \
    -a "${HOST}" -r "${TCP_RANGE}"

  echo "[INFO] Executando Rustscan UDP completo em ${HOST}"
  run_rustscan "a varredura UDP" "${HOST_DIR}/rustscan_udp.txt" \
    -a "${HOST}" -r "${UDP_RANGE}" --udp

  echo "[INFO] Resultados salvos em ${HOST_DIR}"
done <<< "${HOSTS}"


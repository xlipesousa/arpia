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

PORT_SPEC_RAW=$(cat <<'EOF'
{{TARGET_PORTS}}
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

DEFAULT_TCP_RANGE="1-65535"
DEFAULT_UDP_RANGE="1-65535"

trim() {
  local value="$1"
  value="${value#${value%%[![:space:]]*}}"
  value="${value%${value##*[![:space:]]}}"
  printf '%s' "$value"
}

add_unique_port() {
  local port="$1"
  local array_name="$2"
  local -n array_ref="$array_name"
  for existing in "${array_ref[@]-}"; do
    if [[ "$existing" == "$port" ]]; then
      return
    fi
  done
  array_ref+=("$port")
}

declare -a TCP_PORTS=()
declare -a UDP_PORTS=()

sanitized_spec=$(echo "$PORT_SPEC_RAW" | tr ';' ',' | tr '\n' ',' | tr '\r' ',' | tr '\t' ',' )
custom_ports_defined=0
if [[ -n "${PORT_SPEC_RAW//[[:space:]]/}" ]]; then
  custom_ports_defined=1
fi

if [[ -n "${sanitized_spec//[[:space:],]/}" ]]; then
  IFS=',' read -r -a port_tokens <<<"$sanitized_spec"
  for token in "${port_tokens[@]}"; do
    trimmed=$(trim "$token")
    [[ -z "$trimmed" ]] && continue

    lower=${trimmed,,}
    if [[ "$lower" == */udp ]]; then
      port_value="${trimmed%/*}"
      [[ -n "$port_value" ]] && add_unique_port "$port_value" UDP_PORTS
    elif [[ "$lower" == */tcp ]]; then
      port_value="${trimmed%/*}"
      [[ -n "$port_value" ]] && add_unique_port "$port_value" TCP_PORTS
    else
      add_unique_port "$trimmed" TCP_PORTS
    fi
  done
fi

TCP_ARG_MODE="range"
UDP_ARG_MODE="range"

if ((${#TCP_PORTS[@]})); then
  TCP_ARG_MODE="list"
  TCP_PORT_SPEC=$(IFS=','; printf '%s' "${TCP_PORTS[*]}")
fi

if ((${#UDP_PORTS[@]})); then
  UDP_ARG_MODE="list"
  UDP_PORT_SPEC=$(IFS=','; printf '%s' "${UDP_PORTS[*]}")
fi

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

  if [[ "${TCP_ARG_MODE}" == "list" ]]; then
    echo "[INFO] Executando Rustscan TCP personalizado em ${HOST} (portas: ${TCP_PORT_SPEC})"
    run_rustscan "a varredura TCP" "${HOST_DIR}/rustscan_tcp.txt" \
      -a "${HOST}" -p "${TCP_PORT_SPEC}"
  elif [[ "$custom_ports_defined" -eq 0 ]]; then
    echo "[INFO] Executando Rustscan TCP completo em ${HOST}"
    run_rustscan "a varredura TCP" "${HOST_DIR}/rustscan_tcp.txt" \
      -a "${HOST}" -r "${DEFAULT_TCP_RANGE}"
  else
    echo "[WARN] Nenhuma porta TCP definida nas macros; pulando varredura TCP para ${HOST}."
  fi

  if [[ "${UDP_ARG_MODE}" == "list" ]]; then
    echo "[INFO] Executando Rustscan UDP personalizado em ${HOST} (portas: ${UDP_PORT_SPEC})"
    run_rustscan "a varredura UDP" "${HOST_DIR}/rustscan_udp.txt" \
      -a "${HOST}" -p "${UDP_PORT_SPEC}" --udp
  elif [[ "$custom_ports_defined" -eq 0 ]]; then
    echo "[INFO] Executando Rustscan UDP completo em ${HOST}"
    run_rustscan "a varredura UDP" "${HOST_DIR}/rustscan_udp.txt" \
      -a "${HOST}" -r "${DEFAULT_UDP_RANGE}" --udp
  else
    echo "[WARN] Nenhuma porta UDP definida nas macros; pulando varredura UDP para ${HOST}."
  fi

  echo "[INFO] Resultados salvos em ${HOST_DIR}"
done <<< "${HOSTS}"


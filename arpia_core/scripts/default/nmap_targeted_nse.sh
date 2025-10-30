#!/usr/bin/env bash

# Nmap focused NSE execution on previously detected services.
# Macros disponíveis:
#   PROJECT_NAME             -> project name
#   TARGET_HOSTS             -> list of hosts (newline separated)
#   SCAN_TARGETS_WITH_PORTS  -> host;port1,port2 lines (newline separated)
#   SCAN_OPEN_PORTS          -> comma separated aggregated port list
#   OUTPUT_DIR               -> destination directory (optional)

set -euo pipefail

PROJECT_NAME="{{PROJECT_NAME}}"
TARGET_HOSTS=$(cat <<'EOF'
{{TARGET_HOSTS}}
EOF
)
TARGETS_WITH_PORTS=$(cat <<'EOF'
{{SCAN_TARGETS_WITH_PORTS}}
EOF
)
AGGREGATED_PORTS="{{SCAN_OPEN_PORTS}}"

trim() {
	local value="$1"
	value="${value#"${value%%[![:space:]]*}"}"
	value="${value%"${value##*[![:space:]]}"}"
	printf '%s' "$value"
}

has_non_empty() {
	local data="${1:-}"
	[[ -n "${data//[[:space:]]/}" ]]
}

if ! has_non_empty "${TARGETS_WITH_PORTS}"; then
	if ! has_non_empty "${AGGREGATED_PORTS}"; then
		echo "[WARN] Nenhuma porta elegível para NSE focado." >&2
		exit 0
	fi
fi

OUTPUT_DIR="${OUTPUT_DIR:-./recon/${PROJECT_NAME// /_}/vuln}"
mkdir -p "${OUTPUT_DIR}"

NMAP_BIN="{{TOOL_NMAP}}"
if [[ -z "${NMAP_BIN//[[:space:]]/}" || "${NMAP_BIN}" == "None" ]]; then
	if command -v nmap >/dev/null 2>&1; then
		NMAP_BIN="$(command -v nmap)"
	else
		NMAP_BIN="nmap"
	fi
fi

run_nse_scan() {
	local target="$1"
	local ports="$2"
	local safe_target=${target//[^A-Za-z0-9_.-]/_}
	echo "[INFO] Nmap NSE (default,safe,vuln) para ${target} (${ports})"
	"${NMAP_BIN}" -Pn -sV --reason --script "default,safe,vuln" -p "${ports}" "$target" \
		-oA "${OUTPUT_DIR}/nmap_nse_targeted_${safe_target}" || true
	printf '\n'
}

if has_non_empty "${TARGETS_WITH_PORTS}"; then
	while IFS= read -r line; do
		line=$(trim "${line}")
		[[ -z "${line}" ]] && continue
		IFS=';' read -r host ports <<<"${line}"
		host=$(trim "${host}")
		ports=$(trim "${ports:-}")
		[[ -z "${host}" ]] && continue
		if [[ -z "${ports}" ]]; then
			ports="${AGGREGATED_PORTS}"
		fi
		if [[ -z "${ports//[[:space:]]/}" ]]; then
			echo "[WARN] Nenhuma porta definida para ${host}, ignorando." >&2
			continue
		fi
		run_nse_scan "${host}" "${ports}"
	done <<< "${TARGETS_WITH_PORTS}"
else
	echo "[INFO] Utilizando portas agregadas para NSE focado." >&2
	if ! has_non_empty "${TARGET_HOSTS}"; then
		echo "[WARN] Não há hosts configurados no projeto." >&2
		exit 0
	fi
	while IFS= read -r host; do
		host=$(trim "${host}")
		[[ -z "${host}" ]] && continue
		run_nse_scan "${host}" "${AGGREGATED_PORTS}"
	done <<< "${TARGET_HOSTS}"
fi

echo "[INFO] Resultados em ${OUTPUT_DIR}"

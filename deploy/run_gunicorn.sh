#!/usr/bin/env bash
# Script para subir o ARPIA fora do modo de desenvolvimento usando Gunicorn.
# Executa migrações, coleta arquivos estáticos e inicia o servidor.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
ENV_FILE="${PROJECT_DIR}/.env.production"
VENV_PATH="${PROJECT_DIR}/.venv/bin/activate"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[ERRO] Arquivo ${ENV_FILE} não encontrado. Crie ou ajuste para prosseguir." >&2
  exit 1
fi

if [[ ! -f "${VENV_PATH}" ]]; then
  echo "[ERRO] Virtualenv não encontrado em ${VENV_PATH}. Execute install.sh antes." >&2
  exit 1
fi

# Ativa o virtualenv
# shellcheck disable=SC1090
source "${VENV_PATH}"

# Carrega variáveis de ambiente de produção
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

# Garante que banco e assets estejam atualizados
python "${PROJECT_DIR}/manage.py" migrate --noinput
python "${PROJECT_DIR}/manage.py" collectstatic --noinput

# Opcional: valida configuração para produção
python "${PROJECT_DIR}/manage.py" check --deploy

# Inicia o Gunicorn
exec gunicorn --bind "${ARPIA_BIND_ADDRESS:-0.0.0.0:8000}" \
  --workers "${ARPIA_WORKERS:-3}" \
  --timeout "${ARPIA_TIMEOUT:-60}" \
  arpia_project.wsgi

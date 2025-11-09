#!/usr/bin/env bash
# Script de orquestração para executar o ARPIA em modo "produção" usando gunicorn.
# Uso: ./arpia.sh {start|stop|status|restart}
set -euo pipefail

detect_host_ips(){
  local output
  output="$(hostname -I 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$')"
  if [ -z "$output" ]; then
    output="$(ip route get 1.1.1.1 2>/dev/null | awk 'NR==1 {for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')"
  fi
  if [ -z "$output" ]; then
    output="127.0.0.1"
  fi
  printf '%s\n' "$output" | awk '!seen[$0]++'
}

append_unique(){
  local list="${1:-}"
  local value="$2"
  list="${list//$'\n'/,}"
  list="${list//;/,}"
  list="${list// /}"
  if [ -z "$list" ]; then
    printf '%s' "$value"
    return
  fi
  case ",${list}," in
    *,"$value",*) printf '%s' "$list" ;;
    *) printf '%s,%s' "$list" "$value" ;;
  esac
}

ensure_list_contains(){
  local var_name="$1"
  shift
  local current="${!var_name:-}"
  local value
  for value in "$@"; do
    current="$(append_unique "$current" "$value")"
  done
  printf -v "$var_name" '%s' "$current"
}

CMD="${1:-}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PIDFILE=".arpia_gunicorn.pid"
LOGDIR="logs"
LOGFILE="$LOGDIR/gunicorn.log"
ENV_FILE="${ENV_FILE:-.env.production}"
GUNICORN_PATTERN="gunicorn.*arpia_project.wsgi:application"
mapfile -t HOST_IPS < <(detect_host_ips)
DEFAULT_HOST_IP="${HOST_IPS[0]:-127.0.0.1}"
DEFAULT_BIND="0.0.0.0:8000"
BIND="${BIND:-$DEFAULT_BIND}"
WORKERS="${WORKERS:-3}"
RUN_MIGRATIONS="${RUN_MIGRATIONS:-true}"
RUN_COLLECTSTATIC="${RUN_COLLECTSTATIC:-false}"

die(){ echo "$1" >&2; exit "${2:-1}"; }

if [ ! -f "manage.py" ]; then
  die "Arquivo manage.py não encontrado. Execute o script a partir da raiz do projeto."
fi

load_env(){
  if [ -f "$ENV_FILE" ]; then
    echo "Carregando variáveis de $ENV_FILE"
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
  else
    echo "[aviso] Arquivo $ENV_FILE não encontrado. Continuando com variáveis atuais." >&2
  fi
}

ensure_runtime_env(){
  local ip="$DEFAULT_HOST_IP"
  local previous_bind="${BIND:-}"
  local port_part="8000"

  if [ -z "$previous_bind" ] || [[ "${previous_bind,,}" == "auto" ]]; then
    BIND="$DEFAULT_BIND"
    echo "[info] BIND configurado automaticamente para $BIND."
  elif [[ "$previous_bind" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?$ ]]; then
    local host_part="${previous_bind%%:*}"
    port_part="${previous_bind##*:}"
    if [ "$port_part" = "$previous_bind" ]; then
      port_part="8000"
    fi
    if [ "$host_part" != "0.0.0.0" ]; then
      local known=false
      local addr
      for addr in "${HOST_IPS[@]}"; do
        if [ "$addr" = "$host_part" ]; then
          known=true
          break
        fi
      done
      if [ "$known" = false ]; then
        BIND="0.0.0.0:$port_part"
        echo "[info] BIND ajustado automaticamente para $BIND (anterior: $previous_bind)."
      fi
    fi
  fi
  export BIND

  local before_allowed="${ALLOWED_HOSTS:-}"
  ensure_list_contains ALLOWED_HOSTS "127.0.0.1" "localhost" "${HOST_IPS[@]}"
  export ALLOWED_HOSTS
  if [ "$before_allowed" != "$ALLOWED_HOSTS" ]; then
    echo "[info] ALLOWED_HOSTS atualizado: $ALLOWED_HOSTS"
  fi

  local before_csrf="${CSRF_TRUSTED_ORIGINS:-}"
  local csrf_values=("http://127.0.0.1" "https://127.0.0.1" "http://localhost" "https://localhost")
  local addr
  for addr in "${HOST_IPS[@]}"; do
    csrf_values+=("http://$addr" "https://$addr")
  done
  ensure_list_contains CSRF_TRUSTED_ORIGINS "${csrf_values[@]}"
  export CSRF_TRUSTED_ORIGINS
  if [ "$before_csrf" != "$CSRF_TRUSTED_ORIGINS" ]; then
    echo "[info] CSRF_TRUSTED_ORIGINS atualizado: $CSRF_TRUSTED_ORIGINS"
  fi
}

python_bin(){
  if [ -d ".venv" ] && [ -x ".venv/bin/python" ]; then
    echo ".venv/bin/python"
    return
  fi
  command -v python3 >/dev/null 2>&1 && { command -v python3; return; }
  command -v python >/dev/null 2>&1 && { command -v python; return; }
  die "Python não encontrado no PATH."
}

gunicorn_bin(){
  if [ -d ".venv" ] && [ -x ".venv/bin/gunicorn" ]; then
    echo ".venv/bin/gunicorn"
    return
  fi
  command -v gunicorn >/dev/null 2>&1 && { command -v gunicorn; return; }
  die "gunicorn não encontrado. Instale com 'pip install gunicorn'."
}

start_service(){
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "Serviço já em execução (PID $(cat "$PIDFILE"))."
    exit 0
  fi

  load_env
  ensure_runtime_env

  local PY
  PY="$(python_bin)"

  if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo "Aplicando migrations (python manage.py migrate --noinput)"
    "$PY" manage.py migrate --noinput
  else
    echo "[skip] Migrações automáticas desativadas (RUN_MIGRATIONS=false)."
  fi

  if [ "$RUN_COLLECTSTATIC" = "true" ]; then
    echo "Coletando arquivos estáticos (python manage.py collectstatic --noinput)"
    "$PY" manage.py collectstatic --noinput
  else
    echo "[skip] Collectstatic automático desativado (RUN_COLLECTSTATIC=false)."
  fi

  mkdir -p "$LOGDIR"
  local GUNICORN
  GUNICORN="$(gunicorn_bin)"

  echo "Iniciando gunicorn em $BIND (workers=$WORKERS) — logs: $LOGFILE"
  nohup "$GUNICORN" \
    --bind "$BIND" \
    --workers "$WORKERS" \
    --pid "$PIDFILE" \
    --log-file "$LOGFILE" \
    --capture-output \
    arpia_project.wsgi:application >"$LOGFILE" 2>&1 &

  sleep 0.5
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "gunicorn iniciado (PID $(cat "$PIDFILE"))."
  else
    die "Falha ao iniciar gunicorn. Consulte $LOGFILE."
  fi
}

kill_residual_gunicorn(){
  local pids=()
  mapfile -t pids < <(pgrep -f "$GUNICORN_PATTERN" 2>/dev/null || true)
  if [ "${#pids[@]}" -eq 0 ]; then
    return
  fi

  echo "[info] Processos gunicorn adicionais detectados: ${pids[*]} — tentando encerrar."
  kill "${pids[@]}" 2>/dev/null || true
  sleep 1

  mapfile -t pids < <(pgrep -f "$GUNICORN_PATTERN" 2>/dev/null || true)
  if [ "${#pids[@]}" -eq 0 ]; then
    echo "[info] Processos gunicorn encerrados com sucesso."
    return
  fi

  echo "[aviso] Processos gunicorn persistem apos sinal TERM: ${pids[*]} — aplicando kill -9."
  kill -9 "${pids[@]}" 2>/dev/null || true
  sleep 1

  mapfile -t pids < <(pgrep -f "$GUNICORN_PATTERN" 2>/dev/null || true)
  if [ "${#pids[@]}" -eq 0 ]; then
    echo "[info] Processos gunicorn encerrados com kill -9."
  else
    echo "[aviso] Alguns processos gunicorn ainda estao ativos: ${pids[*]} — verifique manualmente."
  fi
}

stop_service(){
  local had_pidfile=false
  if [ -f "$PIDFILE" ]; then
    had_pidfile=true
    local PID
    PID="$(cat "$PIDFILE")"
    if kill "$PID" 2>/dev/null; then
      echo "Processo gunicorn $PID encerrado."
    else
      echo "[aviso] Falha ao enviar sinal para o PID $PID — removendo arquivo pid e prosseguindo."
    fi
    rm -f "$PIDFILE"
    sleep 0.5
  else
    echo "[info] Nenhum arquivo $PIDFILE encontrado. Verificando processos ativos."
  fi

  kill_residual_gunicorn

  if [ "$had_pidfile" = false ]; then
    echo "[info] Stop concluido."
  fi
}

service_status(){
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "gunicorn em execução (PID $(cat "$PIDFILE")), logs em $LOGFILE"
  else
    echo "gunicorn não está em execução."
  fi
}

case "$CMD" in
  start)
    start_service
    ;;
  stop)
    stop_service
    ;;
  status)
    service_status
    ;;
  restart)
    stop_service || true
    sleep 0.5
    start_service
    ;;
  *)
    cat <<USAGE
Uso: $0 {start|stop|status|restart}

Variáveis de ambiente:
  ENV_FILE           Caminho para arquivo .env (padrão: $ENV_FILE)
  BIND               Endereço:porta para bind (padrão: $BIND)
  WORKERS            Número de workers gunicorn (padrão: $WORKERS)
  RUN_MIGRATIONS     Executa migrate antes de iniciar (true/false, padrão: $RUN_MIGRATIONS)
  RUN_COLLECTSTATIC  Executa collectstatic antes de iniciar (true/false, padrão: $RUN_COLLECTSTATIC)

Exemplos:
  BIND="0.0.0.0:9000" WORKERS=4 ./arpia.sh start
  RUN_MIGRATIONS=false ./arpia.sh restart
USAGE
    exit 1
    ;;
esac
#!/usr/bin/env bash
# Script simples para iniciar/parar o runserver em background
# Usage: ./arpia.sh {start|stop|status|restart}
set -euo pipefail

CMD="${1:-}"
PIDFILE=".arpia_runserver.pid"
LOGDIR="logs"
LOGFILE="$LOGDIR/runserver.log"
HOST="${HOST:-127.0.0.1:8000}"

die(){ echo "$1" >&2; exit "${2:-1}"; }

if [ ! -f "manage.py" ]; then
  die "Arquivo manage.py não encontrado. Execute o script a partir da raiz do projeto."
fi

case "$CMD" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "Já está em execução (PID $(cat "$PIDFILE"))."
      exit 0
    fi

    # seleciona python do venv se existir
    if [ -d ".venv" ] && [ -x ".venv/bin/python" ]; then
      PY=".venv/bin/python"
    else
      PY="$(command -v python3 || command -v python)" || die "Python não encontrado."
    fi

    mkdir -p "$LOGDIR"
    echo "Iniciando runserver em $HOST — logs: $LOGFILE"
    nohup "$PY" manage.py runserver "$HOST" >"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 0.2
    echo "PID $(cat "$PIDFILE") registrado."
    ;;

  stop)
    if [ ! -f "$PIDFILE" ]; then
      echo "Não está em execução (sem $PIDFILE)."
      exit 0
    fi
    PID="$(cat "$PIDFILE")"
    if kill "$PID" 2>/dev/null; then
      rm -f "$PIDFILE"
      echo "Processo $PID parado."
    else
      rm -f "$PIDFILE"
      die "Falha ao encerrar PID $PID (já não existia)."
    fi
    ;;

  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "Em execução (PID $(cat "$PIDFILE"))."
    else
      echo "Não está em execução."
    fi
    ;;

  restart)
    "$0" stop || true
    sleep 0.5
    "$0" start
    ;;

  *)
    cat <<USAGE
Uso: $0 {start|stop|status|restart}

start   - inicia django runserver em background (salva PID em $PIDFILE)
stop    - para o processo em background
status  - verifica se o servidor está rodando
restart - reinicia
Variáveis:
  HOST    - endereço:porta para runserver (ex: 0.0.0.0:8000). Padrão: $HOST
Logs: $LOGFILE
USAGE
    exit 1
    ;;
esac
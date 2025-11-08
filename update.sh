#!/usr/bin/env bash
# Atualiza o repositório local a partir do remote (GitHub).
# Uso: ./update.sh
# Para aceitar stash automático use: AUTO_STASH=1 ./update.sh

set -euo pipefail

TARGET_BRANCH="${TARGET_BRANCH:-main}"
VENV_DIR="${VENV_DIR:-.venv}"
PYTHON=""

REPO_EXPECTED="https://github.com/xlipesousa/arpia.git"
CWD="$(pwd)"

install_rustscan() {
  if command -v rustscan >/dev/null 2>&1; then
    info "Rustscan já instalado — pulando."
    return
  fi

  info "Instalando Rustscan (kit básico)..."

  if ! command -v cargo >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      info "Instalando cargo via apt-get..."
      if ! sudo apt-get update; then
        warn "Falha ao executar apt-get update. Instale cargo manualmente para prosseguir com o Rustscan."
        return
      fi
      if ! sudo apt-get install -y cargo; then
        warn "Falha ao instalar cargo. Execute manualmente 'sudo apt-get install -y cargo'."
        return
      fi
    else
      warn "apt-get não disponível. Instale cargo manualmente para habilitar o Rustscan."
      return
    fi
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo continua indisponível. Rustscan não foi instalado automaticamente."
    return
  fi

  if ! cargo install rustscan; then
    warn "Falha ao instalar Rustscan via cargo. Execute manualmente: cargo install rustscan"
  else
    info "Rustscan instalado com sucesso."
  fi
}

ensure_python_env() {
  if [ -n "$PYTHON" ] && [ -x "$PYTHON" ]; then
    return
  fi

  if [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON="${VIRTUAL_ENV}/bin/python"
    if [ -x "$PYTHON" ]; then
      info "Virtualenv ativo detectado: $VIRTUAL_ENV"
      return
    fi
  fi

  local base_python
  base_python="$(command -v python3 || command -v python || true)"
  if [ -z "$base_python" ]; then
    warn "Interpreter Python não encontrado no PATH."
    PYTHON=""
    return
  fi

  if [ ! -d "$VENV_DIR" ]; then
    info "Virtualenv não encontrado em $VENV_DIR — criando..."
    if ! "$base_python" -m venv "$VENV_DIR"; then
      warn "Falha ao criar virtualenv em $VENV_DIR. Prosseguindo com Python do sistema."
      PYTHON="$base_python"
      return
    fi
  fi

  local activate_file
  activate_file="$VENV_DIR/bin/activate"
  if [ -f "$activate_file" ]; then
    info "Ativando virtualenv $VENV_DIR"
    # shellcheck disable=SC1090
    source "$activate_file"
    PYTHON="$VENV_DIR/bin/python"
  else
    warn "Arquivo de ativação $activate_file ausente — utilizando Python do sistema."
    PYTHON="$base_python"
  fi
}

info(){ echo "[INFO] $*"; }
warn(){ echo "[WARN] $*"; }
err(){ echo "[ERROR] $*" >&2; exit 1; }

# confirma que estamos dentro de um repositório git
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  err "Não parece ser um repositório git: $CWD"
fi

# checa remote origin
REMOTE_URL="$(git remote get-url origin 2>/dev/null || true)"
if [ -z "$REMOTE_URL" ]; then
  err "Remote 'origin' não configurado."
fi

if [ "$REMOTE_URL" != "$REPO_EXPECTED" ]; then
  warn "URL do remote origin difere do esperado:"
  warn "  origin: $REMOTE_URL"
  warn "  esperado: $REPO_EXPECTED"
  read -r -p "Continuar mesmo assim? [y/N]: " CONF
  case "$CONF" in
    [Yy]* ) ;; 
    * ) err "Abortado pelo usuário." ;;
  esac
fi

# detectar branch atual
CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)"
info "Branch atual: $CURRENT_BRANCH"

if [ "$CURRENT_BRANCH" = "HEAD" ]; then
  CURRENT_BRANCH="$(git remote show origin | awk -F': ' '/HEAD branch/ {print $2}')"
  CURRENT_BRANCH="${CURRENT_BRANCH:-$TARGET_BRANCH}"
  info "Detached HEAD detectado — assumindo branch '$CURRENT_BRANCH'."
fi

# buscar e limpar refs obsoletas
info "Buscando atualizações do remoto..."
git fetch --prune origin

# verificar alterações locais não comitadas
DIRTY=0
if ! git diff --quiet || ! git diff --staged --quiet || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  DIRTY=1
fi

STASHED=0
if [ "$DIRTY" -eq 1 ]; then
  if [ "${AUTO_STASH:-0}" = "1" ]; then
    info "Alterações locais detectadas — realizando git stash automático..."
    git stash push -u -m "auto-stash/update.sh: $(date -Iseconds)"
    STASHED=1
  else
    echo
    warn "Alterações locais não comitadas foram detectadas."
    read -r -p "Deseja fazer stash automático e prosseguir? [y/N]: " ST
    case "$ST" in
      [Yy]* )
        git stash push -u -m "auto-stash/update.sh: $(date -Iseconds)"
        STASHED=1
        ;;
      * )
        err "Commit ou stash suas mudanças antes de atualizar (ou execute com AUTO_STASH=1)."
        ;;
    esac
  fi
fi

# garantir que a branch alvo existe localmente depois de lidar com alterações locais
if ! git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
  info "Branch local '$TARGET_BRANCH' inexistente — criando a partir de origin/$TARGET_BRANCH..."
  if git show-ref --verify --quiet "refs/remotes/origin/$TARGET_BRANCH"; then
    git checkout -B "$TARGET_BRANCH" "origin/$TARGET_BRANCH"
  else
    err "origin/$TARGET_BRANCH não encontrado. Verifique se o remoto possui a branch desejada."
  fi
  CURRENT_BRANCH="$TARGET_BRANCH"
fi

if [ "$CURRENT_BRANCH" != "$TARGET_BRANCH" ]; then
  info "Alternando para branch '$TARGET_BRANCH'..."
  git checkout "$TARGET_BRANCH"
  CURRENT_BRANCH="$TARGET_BRANCH"
fi

BRANCH="$CURRENT_BRANCH"

# pull com rebase para integrar mudanças remotas
info "Atualizando branch '$BRANCH' a partir de origin/$BRANCH..."
# garantir que existe origin/$BRANCH
if git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
  git pull --rebase origin "$BRANCH"
else
  warn "origin/$BRANCH não existe — tentando 'git pull --rebase origin HEAD'"
  git pull --rebase origin HEAD || true
fi

if [ "${FORCE_RESET:-0}" = "1" ]; then
  info "FORCE_RESET=1 — aplicando 'git reset --hard origin/$BRANCH' e limpando arquivos não rastreados."
  git reset --hard "origin/$BRANCH"
  git clean -fd
fi

# atualizar submódulos, se houver
if [ -f .gitmodules ] || git submodule status >/dev/null 2>&1; then
  info "Atualizando submódulos..."
  git submodule sync --recursive || true
  git submodule update --init --recursive
fi

# --- instalar requirements.txt se existir ---
if [ -f "requirements.txt" ]; then
  info "requirements.txt encontrado — instalando dependências..."

  ensure_python_env

  if [ -z "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
    warn "Não foi possível localizar um interpretador Python executável. Pulando instalação de dependências."
  else
    info "Usando Python: $PYTHON"
    # atualizar pip (silenciosamente) e instalar requirements; não falhar o script se a instalação der problema
    if ! "$PYTHON" -m pip install --upgrade pip setuptools wheel >/dev/null 2>&1; then
      warn "Falha ao atualizar pip (continuando para instalar requirements)."
    fi

    if ! "$PYTHON" -m pip install --upgrade -r requirements.txt; then
      warn "Falha ao instalar algumas dependências. Verifique manualmente: $PYTHON -m pip install -r requirements.txt"
    else
      info "Dependências instaladas com sucesso."
    fi
  fi
else
  info "Nenhum requirements.txt encontrado — pulando instalação de dependências."
fi

install_rustscan

# --- aplicar migrações automaticamente ---
ensure_python_env

if [ -n "$PYTHON" ] && [ -x "$PYTHON" ] && [ -f "manage.py" ]; then
  info "Aplicando migrações do Django (manage.py migrate --noinput)..."
  if ! "$PYTHON" manage.py migrate --noinput; then
    warn "Falha ao aplicar migrações automaticamente. Execute manualmente: $PYTHON manage.py migrate"
  else
    info "Migrações aplicadas com sucesso."
  fi
else
  warn "Não foi possível determinar interpreter Python ou manage.py ausente — migrações não foram executadas."
fi
# --- fim das migrações automáticas ---
# --- FIM da instalação de requirements ---

# reaplicar stash caso tenha sido aplicado
if [ "$STASHED" -eq 1 ]; then
  info "Tentando aplicar stash salvo..."
  # tentar aplicar o stash anterior com pop (se conflito, usuário deve resolver)
  if git stash list | grep -q "auto-stash/update.sh"; then
    git stash pop || {
      warn "Conflito ao aplicar stash. Verifique manualmente com 'git status' e 'git stash list'."
      exit 0
    }
  else
    info "Nenhum stash automático encontrado para aplicar."
  fi
fi

info "Atualização concluída com sucesso."
echo
echo "Próximos passos possíveis:"
echo " - revisar mudanças: git status / git log --oneline -n 10"
echo " - reiniciar serviços se necessário (systemd, uwsgi, gunicorn, etc.)"

exit 0
#!/usr/bin/env bash
# Atualiza o repositório local a partir do remote (GitHub).
# Uso: ./update.sh
# Para aceitar stash automático use: AUTO_STASH=1 ./update.sh

set -euo pipefail

REPO_EXPECTED="https://github.com/xlipesousa/arpia.git"
CWD="$(pwd)"

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
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
info "Branch atual: $BRANCH"

# detectar branch remoto padrão se branch atual for HEAD detached
if [ "$BRANCH" = "HEAD" ]; then
  BRANCH="$(git remote show origin | awk -F': ' '/HEAD branch/ {print $2}')"
  BRANCH="${BRANCH:-main}"
  info "Detached HEAD — usando branch remoto padrão: $BRANCH"
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

# pull com rebase para integrar mudanças remotas
info "Atualizando branch '$BRANCH' a partir de origin/$BRANCH..."
# garantir que existe origin/$BRANCH
if git show-ref --verify --quiet "refs/remotes/origin/$BRANCH"; then
  git pull --rebase origin "$BRANCH"
else
  warn "origin/$BRANCH não existe — tentando 'git pull --rebase origin HEAD'"
  git pull --rebase origin HEAD || true
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

  # detectar intérprete / virtualenv preferencial
  if [ -n "${VIRTUAL_ENV:-}" ]; then
    PYTHON="${VIRTUAL_ENV}/bin/python"
  elif [ -x "./.venv/bin/python" ]; then
    PYTHON="./.venv/bin/python"
  else
    PYTHON="$(command -v python3 || command -v python || true)"
  fi

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
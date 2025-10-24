#!/usr/bin/env bash
# Simple bootstrap para testar o ARPIA localmente
# Uso: ./scripts/bootstrap.sh [--run] [GIT_URL]
set -euo pipefail

install_rustscan() {
  if command -v rustscan >/dev/null 2>&1; then
    echo "Rustscan já instalado — pulando."
    return
  fi

  echo "Instalando Rustscan (kit básico)..."

  if ! command -v cargo >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "Instalando cargo via apt-get..."
      if ! sudo apt-get update; then
        echo "[WARN] Falha ao executar apt-get update. Instale cargo manualmente e reexecute." >&2
        return
      fi
      if ! sudo apt-get install -y cargo; then
        echo "[WARN] Falha ao instalar cargo. Instale manualmente e reexecute 'cargo install rustscan'." >&2
        return
      fi
    else
      echo "[WARN] apt-get não disponível. Instale cargo manualmente para prosseguir com o Rustscan." >&2
      return
    fi
  fi

  if ! command -v cargo >/dev/null 2>&1; then
    echo "[WARN] cargo ainda não disponível após tentativa de instalação. Rustscan não foi configurado." >&2
    return
  fi

  if ! cargo install rustscan; then
    echo "[WARN] Falha ao instalar Rustscan via cargo. Tente manualmente: cargo install rustscan" >&2
  else
    echo "Rustscan instalado com sucesso."
  fi
}

GIT_URL="${1:-https://github.com/xlipesousa/arpia.git}"
RUN_SERVER=false
if [[ "${1:-}" == "--run" ]]; then
  RUN_SERVER=true
  GIT_URL="${2:-$GIT_URL}"
fi

# diretório alvo (se já estiver dentro do repo, keep)
if [ -d ".git" ]; then
  echo "Já dentro do repositório, skip clone."
else
  echo "Clonando $GIT_URL ..."
  git clone "$GIT_URL" arpia || { echo "Clone falhou"; exit 1; }
  cd arpia
fi

# garantir venv
PY="python3"
if ! command -v $PY &>/dev/null; then PY="python"; fi

echo "Criando virtualenv .venv (se não existir)..."
$PY -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Atualizando pip e instalando requirements..."
pip install --upgrade pip
if [ -f requirements.txt ]; then
  pip install -r requirements.txt
else
  echo "requirements.txt não encontrado — instalando Django minimo."
  pip install "Django>=4.2,<5"
fi

install_rustscan

# criar .env básico se não existir
if [ ! -f .env ]; then
  echo "Gerando .env básico..."
  SECRET_KEY=$(python - <<PY
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
PY
)
  cat > .env <<EOF
ALLOWED_HOSTS=127.0.0.1,localhost
SECRET_KEY=${SECRET_KEY}
DEBUG=True
EOF
  echo ".env criado."
else
  echo ".env já existe — pulando criação."
fi

# migrations
echo "Aplicando migrations..."
python manage.py migrate --noinput

# criar superuser se variáveis de ambiente fornecidas ou criar demo/admin (opcional)
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASS="${ADMIN_PASS:-admin}"

echo "Criando superuser '${ADMIN_USER}' (se não existir)..."
python - <<PY
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpia_project.settings')
import django
django.setup()
from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.filter(username=os.environ.get('ADMIN_USER','admin')).first()
if not u:
    User.objects.create_superuser(
        username=os.environ.get('ADMIN_USER','admin'),
        email=os.environ.get('ADMIN_EMAIL','admin@example.com'),
        password=os.environ.get('ADMIN_PASS','admin')
    )
    print("Superuser criado.")
else:
    print("Superuser já existe.")
PY

# coletar estáticos
echo "Coletando arquivos estáticos..."
python manage.py collectstatic --noinput

echo "Bootstrap concluído. Para rodar o servidor localmente:"
echo "  source .venv/bin/activate"
echo "  python manage.py runserver 127.0.0.1:8000"

if [ "$RUN_SERVER" = true ]; then
  python manage.py runserver 0.0.0.0:8000
fi
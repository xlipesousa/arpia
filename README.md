# ARPIA — Instalação e execução local (dev)

Este repositório contém o sistema ARPIA. Instruções para instalar e iniciar localmente em um ambiente de desenvolvimento.

Pré-requisitos
- Git
- Python 3.8+
- (opcional) Acesso ao repositório privado como colaborador

Passos de instalação (rápido)
1. Clone o repositório:
   - git clone https://github.com/xlipesousa/arpia.git
   - cd arpia

2. Roda o instalador (cria .venv, instala dependências, aplica migrations e cria superuser demo)
   - chmod +x install.sh
   - ./install.sh
   - (opcional) export ADMIN_USER=meuuser ADMIN_PASS=minhasenha ADMIN_EMAIL=meu@ex.com antes de executar

3. Alternativa: criar e ativar venv manualmente
   - python3 -m venv .venv
   - source .venv/bin/activate
   - pip install -r requirements.txt
   - python manage.py migrate
   - python manage.py createsuperuser

Scripts úteis
- install.sh
  - Executa bootstrap completo: cria .venv, instala requirements, aplica migrations, cria superuser demo e collectstatic.

- arpia.sh
  - Controla o servidor de desenvolvimento em background.
  - Torne executável: chmod +x arpia.sh
  - Uso:
    - ./arpia.sh start    — inicia runserver em background (PID salvo em .arpia_runserver.pid)
    - ./arpia.sh stop     — para o servidor em background
    - ./arpia.sh status   — verifica estado
    - ./arpia.sh restart  — reinicia

Parâmetros e logs
- HOST (opcional) — define host:porta para runserver; ex:
  - HOST="0.0.0.0:8000" ./arpia.sh start
- Logs do runserver ficam em logs/runserver.log
- PID do processo fica em .arpia_runserver.pid

Atenção
- O script arpia.sh usa o python do .venv se presente; garanta que o .venv foi criado pelo install.sh ou manualmente.
- Para desenvolvimento, DEBUG=True (configurado via .env). Não use em produção.
- Se o repositório for privado, garanta que os colaboradores têm acesso SSH/HTTPS conforme preferir.

Suporte rápido
- Problemas ao rodar o servidor ou migrar? Cole a saída de:

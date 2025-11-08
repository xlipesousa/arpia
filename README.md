# ARPIA — Instalação e execução local (dev)

Este repositório contém o sistema ARPIA. Instruções para instalar e iniciar localmente em um ambiente de desenvolvimento.

## Execução fora do modo de desenvolvimento

Para publicar o ARPIA na rede interna expondo via HTTP pelo IP do host, utilize um `.env` específico (por exemplo `.env.production`) com as variáveis:

```
DEBUG=False
SECRET_KEY=<gere-um-valor-único>
ALLOWED_HOSTS=192.168.0.10,127.0.0.1,localhost  # ajuste para o IP/nome do host
CSRF_TRUSTED_ORIGINS=http://192.168.0.10        # precisa conter o esquema (http:// ou https://)
```

Passos recomendados (com o novo orquestrador `arpia.sh`):
- Garanta que o `.venv` esteja criado (via `install.sh` ou manualmente).
- Ajuste as variáveis em `.env.production`.
- Inicie o serviço com `./arpia.sh start` (opções abaixo). O script carrega o `.env`, executa `migrate` por padrão e sobe o Gunicorn em segundo plano.

Detalhes do script de produção `arpia.sh`:
- Detecta automaticamente todos os IPs do host e, por padrão, expõe o serviço em `0.0.0.0:8000` (acessível por qualquer IP local).
- `ENV_FILE=.env.custom ./arpia.sh start` — usa um arquivo `.env` alternativo.
- `BIND="0.0.0.0:9000" WORKERS=4 ./arpia.sh restart` — customiza bind e quantidade de workers.
- `RUN_MIGRATIONS=false ./arpia.sh start` — pula `migrate`; útil se a step já foi executada previamente.
- `RUN_COLLECTSTATIC=true ./arpia.sh start` — dispara o `collectstatic` automaticamente.
- Logs: `logs/gunicorn.log`; PID: `.arpia_gunicorn.pid`.
- Se `BIND` estiver vazio, definido como `auto` ou apontar para um IP antigo, o script o ajusta para o IP detectado.

Enquanto o serviço estiver rodando, o ARPIA ficará acessível em `http://<IP-do-host>:8000/` (ou na porta configurada em `BIND`).

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

- update.sh
  - Sincroniza com o remoto (git pull --rebase), instala dependências e aplica migrações automaticamente.
  - Recomendado após qualquer git pull ou antes de rodar o servidor para garantir que o banco esteja em dia.

- arpia-dev.sh
  - Controla o servidor de desenvolvimento (`runserver`) em background.
  - Torne executável: `chmod +x arpia-dev.sh`
  - Uso:
    - `./arpia-dev.sh start`    — inicia runserver em background (PID salvo em `.arpia_runserver.pid`)
    - `./arpia-dev.sh stop`     — para o servidor em background
    - `./arpia-dev.sh status`   — verifica estado
    - `./arpia-dev.sh restart`  — reinicia
  - Detecta automaticamente o IP do host e usa `<ip_detectado>:8000` como bind padrão (sobreponha com `HOST=ip:porta`).

- arpia.sh
  - Novo orquestrador de produção usando Gunicorn.
  - Torne executável: `chmod +x arpia.sh`
  - Uso básico: `./arpia.sh start` (carrega `.env.production`, aplica migrações e sobe Gunicorn).
  - `./arpia.sh stop` encerra o processo; `./arpia.sh status` exibe o PID/log; `./arpia.sh restart` aplica stop/start.
  - Garante que `BIND` permaneça válido (ajustando para `0.0.0.0` quando necessário) e acrescenta todos os IPs detectados em `ALLOWED_HOSTS` e `CSRF_TRUSTED_ORIGINS`.

Parâmetros e logs (desenvolvimento)
- HOST (opcional) — define host:porta para `runserver`; por padrão usa `<ip_detectado>:8000`.
- Logs do runserver ficam em `logs/runserver.log`
- PID do processo fica em `.arpia_runserver.pid`

Parâmetros e logs (produção)
- `BIND` e `WORKERS` controlam bind e número de workers (`./arpia.sh start`). Use `BIND=auto` (ou deixe vazio) para manter o padrão `0.0.0.0:8000`; se definir um IP estático que não pertença mais ao host, o script o ajusta automaticamente.
- Logs do Gunicorn ficam em `logs/gunicorn.log`.
- PID do Gunicorn fica em `.arpia_gunicorn.pid`.

Atenção
- Os scripts `arpia-dev.sh` e `arpia.sh` usam o Python do `.venv` se presente; garanta que o `.venv` foi criado pelo `install.sh` ou manualmente.
- O `arpia.sh` acrescenta o IP detectado em `ALLOWED_HOSTS` e `CSRF_TRUSTED_ORIGINS`, mesmo que existam outros valores no `.env`.
- Para desenvolvimento, DEBUG=True (configurado via .env). Não use em produção.
- Se o repositório for privado, garanta que os colaboradores têm acesso SSH/HTTPS conforme preferir.
- O comando `python manage.py runserver` agora aplica migrações pendentes automaticamente antes de subir o servidor.
  - Caso precise pular esse comportamento (ex.: scripts de CI), use `python manage.py runserver --skip-auto-migrate`.

Documentacao adicional
- [Integracoes de enriquecimento do Hunt](docs/hunt-integracoes.md): detalha configuracao de NVD, Vulners, searchsploit e importacao do catalogo ATT&CK, alem de fixtures e contratos de teste.
- [Modelo de dados ATT&CK](docs/hunt-phase3-modelagem.md): diagrama PlantUML dos relacionamentos entre AttackTactic, AttackTechnique, CveAttackTechnique, HuntFinding e HuntRecommendation.
- [Planejamento de migracoes Fase 4](docs/hunt-phase4-migracoes.md): lista indices adicionais, campos complementares e passos de validacao antes do rollout.

## Módulo de vulnerabilidades — visão rápida

- Dashboard dinâmico com polling a cada 30 segundos via endpoint `GET /vuln/api/dashboard/`, exibindo métricas consolidadas e links diretos para os módulos de Scan e Reports.
- Distribuição de severidade, contagem de findings abertos e resumo das últimas sessões agora aparecem em tempo real para o projeto selecionado.
- A lista de achados recentes e a tabela de sessões são atualizadas automaticamente sem recarregar a página.
- Automação de playbooks:
  - Acione `plan_vulnerability_session` (ou o endpoint `POST /vuln/api/sessions/plan/`) para provisionar sessões com pipeline padrão ou personalizado.
  - O dashboard agora possui o botão “Nova sessão automatizada”, que agenda tarefas pendentes reutilizáveis (Nmap vuln/targeted, Greenbone) com um clique.
  - O payload suporta `include_targeted`, `include_targeted_nse`, `include_greenbone` e listas `pipeline` para ajustar rapidamente o playbook.
- Cada `VulnScanSession` armazena `macros_snapshot`, garantindo que as macros do projeto fiquem disponíveis mesmo fora de ambiente conectado (execuções offline, replays, etc.).
- Para consumir o snapshot em integrações externas, autentique-se normalmente e consulte `https://<host>/vuln/api/dashboard/?project=<uuid_do_projeto>`.

Suporte rápido
- Problemas ao rodar o servidor ou migrar? Cole a saída de:

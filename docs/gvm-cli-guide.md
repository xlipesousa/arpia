# Guia rápido: Greenbone Vulnerability Management (GVM)

Este guia complementa o `install-gvm.md` e resume os comandos essenciais para operar o GVM em linha de comando no Kali Linux, com foco em integrações automatizadas no ARPIA.

## Serviços principais

| Serviço | Comando systemd | Função |
| --- | --- | --- |
| **ospd-openvas** | `sudo systemctl start ospd-openvas` | Scanner OpenVAS (execução de varreduras).
| **gvmd** | `sudo systemctl start gvmd` | Gerenciador, mantém tasks, targets e credenciais.
| **gsad** | `sudo systemctl start gsad` | Interface Web (GSA).

Atalho completo (já configurado no Kali):

```bash
sudo gvm-start
sudo gvm-stop
sudo gvm-status
```

Use `sudo gvm-check-setup` para validar dependências (feeds, Redis, certificados).

## Operações com `gvm-cli`

O `gvm-cli` troca mensagens com o daemon `gvmd` usando o protocolo GMP (Greenbone Management Protocol). Exemplos abaixo usam o socket local `/run/gvmd/gvmd.sock`.

### Autenticação e conexão

```bash
# Conectar via socket Unix
sudo gvm-cli --gmp-username admin --gmp-password 'kali' socket --socketpath /run/gvmd/gvmd.sock

# Conectar via TLS ao gsad (quando remoto)
sudo gvm-cli --gmp-username admin --gmp-password 'kali' tls --hostname 127.0.0.1 --port 9392
```

Você também pode exportar variáveis para evitar repetir credenciais:

```bash
export GVM_USERNAME=admin
export GVM_PASSWORD='kali'
```

E usar `sudo gvm-cli socket --gmp-username $GVM_USERNAME --gmp-password "$GVM_PASSWORD" --socketpath /run/gvmd/gvmd.sock`.

### Comandos GMP mais úteis

Os comandos são estruturas XML. O `gvm-cli` aceita a opção `--xml` ou o modo interativo.

```bash
# Listar scans (tasks)
sudo gvm-cli socket --xml '<get_tasks/>'

# Listar alvos
gvm-cli socket --xml '<get_targets/>'

# Criar alvo usando host único
TARGET_ID=$(sudo gvm-cli socket --xml "<create_target><name>Host 192.168.0.10</name><hosts>192.168.0.10</hosts></create_target>" | xmllint --xpath 'string(//create_target_response/@id)' -)

# Criar tarefa aproveitando scan config "Full and fast"
TASK_ID=$(sudo gvm-cli socket --xml "<create_task><name>Scan rápido</name><comment>Executado pelo ARPIA</comment><targets id='$TARGET_ID'/><scan_config id='daba56c8-73ec-11df-a475-002264764cea'/></create_task>" | xmllint --xpath 'string(//create_task_response/@id)' -)

# Iniciar tarefa recém criada
sudo gvm-cli socket --xml "<start_task task_id='$TASK_ID'/>"

# Ver status de execução
sudo gvm-cli socket --xml "<get_tasks task_id='$TASK_ID' details='1'/>"

# Obter resultados (findings) em formato XML compacto
sudo gvm-cli socket --xml "<get_results task_id='$TASK_ID' report_id='CURRENT'/>"
```

IDs importantes:

- **Scan configs** padrão: `Full and fast` → `daba56c8-73ec-11df-a475-002264764cea`; `Full and very deep` → `74db13d6-7489-11df-91b9-002264764cea`.
- **Port lists**: `All IANA assigned TCP` → `33d0cd82-57c6-11e1-8161-406186ea4fc5`; `Discovery` → `730ef368-7489-11df-91b9-002264764cea`.

Para limitar às portas detectadas pelo `arpia_scan`, crie port lists dinâmicas:

```bash
PORT_LIST_ID=$(sudo gvm-cli socket --xml "<create_port_list><name>Ports from ARPIA</name><port_range>22,80,443,8080</port_range><comment>Gerado via automação</comment></create_port_list>" | xmllint --xpath 'string(//create_port_list_response/@id)' -)
```

Em seguida vincule o port list ao target: `<create_target> ... <port_list id='$PORT_LIST_ID'/> ...`.

### Exportando relatórios

```bash
# Obter relatório em XML (identificador 'CURRENT' ou ID específico)
sudo gvm-cli socket --xml "<get_reports report_id='CURRENT' details='1' format_id='5057e5cc-b825-11e4-9d0a-28d24461215b'/>" > report.xml

# Outros formatos: PDF (`c402cc3e-b531-11e1-9163-406186ea4fc5`), CSV (`9087b18c-626c-11e3-b7ae-406186ea4fc5`).
```

Use `xmllint` ou `jq` (via `gvm-cli --pretty`) para pós-processar.

## Ferramentas auxiliares

- `gvm-manage-certs`: regenera certificados.
- `greenbone-feed-sync --type SCAP|CERT|GVMD_DATA`: atualiza feeds manualmente.
- `gvmd --get-scanners` / `--modify-scanner`: configura scanners remotos.
- `omp`: cliente legado compatível; comandos similares (não recomendado em novas integrações).

## Integração com ARPIA

1. **Geração de port lists**: converte resultados do `arpia_scan` para `<create_port_list>`.
2. **Automação de tasks**: cria target e task por projeto/sessão.
3. **Execução e monitoramento**: `start_task`, pooling com `get_tasks` até `status=Done`.
4. **Parse de relatórios**: extrair CVE, CVSS, NVT, host, port, solução e impacto.
5. **Limpeza opcional**: remover tasks/targets (`<delete_task>`, `<delete_target>`) para evitar acúmulo.

### Variáveis de configuração

O wrapper `run_greenbone_scan` lê os seguintes parâmetros do `settings.py`/variáveis de ambiente (vide `ARPIA_GVM_*`):

| Variável | Descrição | Default |
| --- | --- | --- |
| `ARPIA_GVM_HOST` | Hostname para conexão TLS | `127.0.0.1` |
| `ARPIA_GVM_PORT` | Porta GMP via TLS | `9390` |
| `ARPIA_GVM_SOCKET_PATH` | Caminho do socket Unix opcional | — (TLS) |
| `ARPIA_GVM_USERNAME` / `ARPIA_GVM_PASSWORD` | Credenciais GMP | — |
| `ARPIA_GVM_SCANNER_ID` | Scanner padrão (`gvmd --get-scanners`) | `08b69003-5fc2-4037-a479-93b440211c73` |
| `ARPIA_GVM_SCAN_CONFIG_ID` | Scan config (ex.: “Full and fast”) | `daba56c8-73ec-11df-a475-002264764cea` |
| `ARPIA_GVM_REPORT_FORMAT_ID` | Formato do relatório exportado | `a994b278-1f62-11e1-96ac-406186ea4fc5` |
| `ARPIA_GVM_REPORT_DIR` | Diretório base para salvar relatórios | `./recon/greenbone` |
| `ARPIA_GVM_POLL_INTERVAL` | Intervalo entre chamadas `get_tasks` (s) | `5` |
| `ARPIA_GVM_MAX_ATTEMPTS` | Máximo de polls antes de abortar | `60` |
| `ARPIA_GVM_TASK_TIMEOUT` | Timeout absoluto em segundos | — |

Se `ARPIA_GVM_SOCKET_PATH` estiver definido, o modo socket tem prioridade; do contrário, o wrapper usa TLS com host/porta. Para ambientes com múltiplos scanners/configs, sobreponha os IDs via env ou `settings.{ENV}.py`.

Mantenha logs via `--verbose` e monitore `/var/log/gvm/` para troubleshooting (especialmente `gsad.log`, `gvmd.log`, `ospd-openvas.log`).

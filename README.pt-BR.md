# zabbix-autodiscovery

🇺🇸 [Read in English](README.md)

**Varre as suas redes, identifica os equipamentos de infraestrutura e os cadastra no Zabbix com o template, o grupo, a interface e as tags certos.** Desktops e notebooks ficam de fora. Os dashboards do Grafana são opcionais.

## Recursos

- **Descoberta** por ping, portas TCP, SNMP v1/v2c/v3, agente Zabbix, NetBIOS e DNS reverso confirmado. Uma segunda passada, com timeout maior, evita falsos negativos em redes carregadas ou via VPN.
- **Classificação pelo que o equipamento responde, nunca pelo nome.** As regras usam sysObjectID/sysDescr do SNMP, o `system.uname` do agente e as portas abertas, então funcionam com qualquer padrão de nomenclatura. Já vêm regras para Cisco, HPE/Aruba, H3C, Huawei, Juniper, TP-Link, D-Link, MikroTik, Dell, Fortinet, pfSense, Palo Alto, Sophos, Ubiquiti/UniFi, Ruckus, Meraki, as principais marcas de impressora, nobreaks APC/Eaton/NHS, Synology/QNAP, iDRAC/iLO, ESXi e servidores Windows/Linux.
- **Estações de trabalho ficam de fora.** O sysObjectID da Microsoft separa estação, servidor e controlador de domínio; o Windows 11 e o Server 2025 têm o mesmo build (26100) e mesmo assim são distinguidos. Para máquinas sem SNMP, valem a resposta do agente e o perfil de portas.
- **Hostname real**, buscado nesta ordem: `Hostname=` do agente, sysName do SNMP (nomes de fábrica são descartados), NetBIOS e DNS confirmado. O CSV mostra de onde veio cada nome.
- **Revisão antes de alterar.** O `scan` gera um CSV editável no Excel. O `apply --dry-run` mostra exatamente o que seria criado. O `check` valida tudo sem tocar no Zabbix.
- **Seguro num Zabbix que já existe.** Hosts já monitorados (mesmo IP ou DNS) são pulados. Macros, grupos, usuários e dashboards existentes nunca são alterados. Tudo o que o zabbix-autodiscovery cria leva o prefixo `AutoDiscovery -` ou a tag `origin=autodiscovery`.
- **Servidores sem agente Zabbix** recebem um template que gera o problema *"Zabbix agent missing"*. O `agent-sync` troca esses hosts para os templates de agente depois da instalação.
- **Certificados SSL e vencimento de domínios** (RDAP), com alertas e um dashboard ordenado por dias restantes. O scan também identifica servidores web (IIS, nginx, Apache…) e seus certificados.
- **Várias filiais**, cada uma com nome (vira a tag `site` e o grupo `Sites/<nome>`) e, opcionalmente, um proxy Zabbix.
- **Dashboards por tipo de dispositivo:** nativos do Zabbix (sem precisar de Grafana) e/ou do Grafana, montados com os nomes dos seus grupos de hosts.
- Zabbix **6.0 a 8.0**. Roda em Linux, macOS e Windows (Python 3.10+).

## Início rápido

```bash
pip install git+https://github.com/GustavoMS0/zabbix-autodiscovery   # ou: pipx / uv tool install
mkdir minha-rede && cd minha-rede
zabbix-autodiscovery init            # cria config.yaml e .env
```

1. No Zabbix, crie um token de API (*Usuários → API tokens*) para um usuário Super admin. No Zabbix 8.0, o papel do usuário precisa ter **acesso à API** habilitado.
2. Coloque o token e a comunidade SNMP no `.env`. Ajuste `zabbix.url` e `scan.networks` no `config.yaml`.
3. Execute:

```bash
zabbix-autodiscovery check                              # validação somente leitura
zabbix-autodiscovery scan  -o inventory.csv             # varre e classifica; o Zabbix não é alterado
#   revise o inventory.csv: coluna "action" = add | review | ignore
zabbix-autodiscovery apply -i inventory.csv --dry-run   # mostra o plano
zabbix-autodiscovery setup                              # grupos, template de agente ausente, dashboards
zabbix-autodiscovery apply -i inventory.csv             # cria os hosts
```

Para não instalar nada no Windows, use `.\zabbix-autodiscovery.ps1 init` (precisa do [uv](https://docs.astral.sh/uv/)). No Linux/macOS, `./zabbix-autodiscovery.sh init`.

> Rode o scan de uma máquina que alcance todas as redes, de preferência o próprio servidor ou proxy Zabbix. O agente Zabbix só responde aos IPs listados no `Server=` dele.

## Comandos

| Comando | Altera o Zabbix? | O que faz |
|---|---|---|
| `zabbix-autodiscovery init` | não | Cria um `config.yaml` e um `.env` iniciais |
| `zabbix-autodiscovery check` | não | Valida token, papel, templates disponíveis por regra, macro, regras de descoberta sobrepostas e o que seria alterado |
| `zabbix-autodiscovery scan -o ARQ` | não | Varre `scan.networks`, classifica cada IP que responde e grava o CSV |
| `zabbix-autodiscovery apply -i ARQ [--dry-run]` | sim | Cria as linhas com `action=add`; pula o que já é monitorado |
| `zabbix-autodiscovery setup [--native-discovery] [--no-dashboards]` | sim | Grupos, `{$SNMP_COMMUNITY}` (só se não existir), template de agente ausente, dashboards do Zabbix, usuário somente leitura do Grafana (opcional) e descoberta contínua (opcional) |
| `zabbix-autodiscovery agent-sync [--dry-run]` | sim | Passa os hosts `agent=missing` para os templates de agente quando o agente responde |
| `zabbix-autodiscovery web [--dry-run] [-i ARQ]` | sim | Monitoramento de certificados SSL e vencimento de domínios |
| `zabbix-autodiscovery grafana-dashboards -o DIR` | não | Gera os JSON dos dashboards do Grafana a partir do seu config |

## O CSV de inventário

Cada IP que responde vira uma linha. As colunas que você normalmente edita:

| Coluna | Significado |
|---|---|
| `action` | `add` (será criado), `review` (incerto: decida), `ignore` |
| `hostname` / `visible_name` | Nome técnico e nome visível no Zabbix; `name_source` diz de onde o nome veio |
| `group`, `templates`, `interface`, `site` | O que o `apply` vai usar. Em templates, `A\|B` usa o primeiro que existir |

As demais colunas (`sysobjectid`, `sysdescr`, `ports`, `agent_uname`, `netbios`, `dns`…) servem de evidência para a decisão.

## Como os dispositivos são classificados

As regras ficam no `config.yaml` e são avaliadas **em ordem**; a primeira que casar vence:

```yaml
- name: intelbras-switch
  category: switch
  group: Network/Switches                  # nomes de grupo são livres: use o padrão da sua empresa
  match:                                   # lista = "qualquer um"; dicionário = "todos"
    - {sysobjectid_prefix: [1.3.6.1.4.1.26138]}
    - {sysdescr_regex: 'intelbras'}
  templates: ["Intelbras by SNMP|Network Generic Device by SNMP"]
  interface: snmp                          # snmp | agent | icmp
  tags: {}                                 # tags extras no host
  action: add                              # add | review | ignore
```

Condições disponíveis: `sysobjectid_prefix`, `sysdescr_regex`, `agent_uname_regex`, `ports_any`, `ports_all`, `ports_none`, `snmp`, `agent`, `alive`.

Como estação e servidor são separados, sem usar nome:

| Evidência | Resultado |
|---|---|
| sysObjectID SNMP `…311.1.1.3.1.1` | estação → ignorar |
| sysObjectID SNMP `…311.1.1.3.1.2` / `…3.1.3` | servidor Windows / controlador de domínio |
| `system.uname` do agente contém "Windows … Server" | servidor Windows → **cadastrar** |
| `system.uname` do agente é Windows sem "Server" (Windows 10/11 com agente) | estação → ignorar |
| Sem SNMP/agente, Kerberos + LDAP (88 + 389) | controlador de domínio sem agente |
| Sem SNMP/agente, SMB + WinRM ou SQL (445 + 5985/1433) | provável servidor → revisar |
| Sem SNMP/agente, só portas de Windows (135/139/445/3389) | estação → ignorar |
| Sem SNMP/agente, SSH sem portas de Windows/impressora | provável Linux → revisar |

> Não junte `ICMP Ping` com templates `… by SNMP`: eles já trazem os itens de ICMP, e a chave duplicada faz o cadastro falhar.

## Várias filiais e proxies

```yaml
site_group: "Sites/{site}"                 # grupo extra por filial ("" desliga); pode ser "Filiais/{site}"
scan:
  networks:
    - {network: 192.168.0.0/24, site: Matriz}
    - {network: 10.20.0.0/23,   site: Recife, proxy: proxy-recife}
    - 172.16.5.0/24                        # sem filial
```

Cada host recebe a tag `site=<nome>` e entra também no grupo da filial, então dá para filtrar por tipo ou por filial, no Zabbix e no Grafana. Se uma filial não for roteável a partir de onde você roda o zabbix-autodiscovery, faça o scan de uma máquina dessa filial, com um config contendo só as redes dela. O `apply` aceita qualquer um dos CSVs gerados.

## Servidores sem agente Zabbix

Servidores detectados sem agente entram com a tag `agent=missing` e o template **AutoDiscovery - Zabbix agent missing**. O servidor Zabbix testa a porta 10050 a cada 5 minutos. O trigger *"Zabbix agent missing on {HOST.NAME}"* só dispara enquanto o host responde ping, então um host fora do ar não gera esse alerta também. Depois que o agente é instalado, o problema se resolve sozinho; rode `zabbix-autodiscovery agent-sync` para vincular os templates de agente. Para receber aviso, crie uma ação de trigger com a condição *tag agent = missing*.

## Certificados SSL e vencimento de domínios

O `zabbix-autodiscovery web` monitora os sites e domínios listados na seção `web` do config:

```yaml
web:
  certificates:
    group: Web/Certificados
    agent2_host: Zabbix server       # host existente cujo Zabbix agent 2 lê os certificados
    warn_days: 30
    high_days: 7
    sites: [https://www.exemplo.com.br/, mail.exemplo.com.br:443]
  domains:
    group: Web/Dominios
    warn_days: 60                    # renovação de domínio pede mais antecedência
    high_days: 15
    list: [exemplo.com.br, exemplo.com]
```

- **Certificados:** um host por site, com o template *AutoDiscovery - SSL certificate*. Ele acompanha os dias até o vencimento, o resultado da validação (inválido, vencido, nome divergente), o emissor e os nomes alternativos (SANs). A verificação roda num **Zabbix agent 2** (plugin WebCertificate): o agent clássico responde "Unsupported item key". Aponte `agent2_host` para um host com agent 2, por exemplo o próprio servidor Zabbix.
- **Domínios:** um host por domínio, com o template *AutoDiscovery - Domain expiration*. O servidor Zabbix consulta o **RDAP**, substituto oficial do WHOIS, a cada 12 horas, direto no registro de cada TLD (registro.br, Verisign…), descoberto pela lista oficial da IANA. Não precisa de script, só de acesso à internet a partir do servidor ou proxy Zabbix.
- **Alertas:** aviso abaixo de `warn_days`, alta severidade abaixo de `high_days` e um problema quando a verificação falha repetidamente.
- **Dashboard:** *AutoDiscovery - Certificates and domains* lista tudo ordenado pelos dias restantes.
- **Certificados descobertos:** o `scan` também registra o servidor (IIS, nginx, Apache…) e o certificado de cada porta HTTP(S) (colunas `web_servers` e `cert_*`). O `web -i inventario.csv` inclui os certificados públicos; os autoassinados (impressoras, iDRAC…) ficam de fora.

## Dashboards

O `setup` cria um **dashboard nativo do Zabbix** para cada tipo de dispositivo presente nas regras: visão geral, switches, roteadores, firewalls, access points, impressoras, servidores, nobreaks, storage e hardware de servidor. Cada um mostra os problemas dos grupos daquele tipo, um mapa *honeycomb* de disponibilidade ICMP e métricas (Zabbix 7.0+) e os hosts com maior latência ICMP. Não precisa de Grafana.

O **Grafana** é opcional:

- **Stack nova:** o `deploy/docker-compose.yml` sobe o Zabbix 8.0 + PostgreSQL e/ou o Grafana 12, com plugin Zabbix, datasource e os dashboards do projeto já provisionados:

  ```bash
  cd deploy && cp .env.example .env      # troque todas as senhas
  docker compose --profile zabbix --profile grafana up -d    # ou só um dos profiles
  ```

  Só com `--profile grafana`, defina `ZABBIX_API_URL` no `.env` apontando para o seu Zabbix existente. O `zabbix-autodiscovery setup` cria o usuário somente leitura de que o Grafana precisa (`grafana_user` no config).
- **Grafana que já existe:** rode `zabbix-autodiscovery grafana-dashboards -o dashboards/` e importe em *Dashboards → New → Import*. Cada dashboard tem um seletor de datasource, então não é preciso editar UID.

Os painéis do Grafana buscam os itens por regex, porque cada fabricante nomeia os itens de um jeito. Se algum painel ficar vazio para um modelo específico, ajuste `SPECS` em `src/zabbix_autodiscovery/dashboards.py`.

## Usando num Zabbix que já existe

| Situação | Comportamento |
|---|---|
| Host já monitorado (mesmo IP ou DNS) | pulado; nada é alterado nele |
| Nome já usado por outro host (mesmo equipamento com outro IP?) | pulado como possível duplicata (`--allow-duplicate-names` cria como `nome-IP`) |
| Macro global `{$SNMP_COMMUNITY}` já existe | mantida; a comunidade vai como macro no host novo |
| Grupos com o mesmo nome | reaproveitados |
| Template, dashboard, papel ou usuário com os nomes do zabbix-autodiscovery | criados só se não existirem |
| `--native-discovery` com hosts já monitorados nas faixas | recusado (as ações também valeriam para eles), a não ser com `--force` |
| Templates com nome diferente na sua versão | alternativas por regra (`A\|B`); o `check` lista o que faltar |

Comece por uma rede pequena, sempre rode o `apply --dry-run` antes e filtre por `origin=autodiscovery` para revisar ou desfazer.

## Pré-requisitos nos equipamentos

- **Rede, impressoras e nobreaks:** SNMP habilitado, com ACL liberando o servidor Zabbix e a máquina que faz o scan.
- **Servidores:** Zabbix agent 2 com `Server=` / `ServerActive=` apontando para o Zabbix. Se o IP do scanner não estiver no `Server=`, o servidor é detectado como *agente instalado, scanner recusado* (`review`).
- **Firewalls entre redes:** ICMP, UDP 161 e TCP 10050 liberados para o Zabbix e para o scanner.

## Contribuindo

Regras para novos fabricantes, dashboards e correções são bem-vindos; veja o [CONTRIBUTING.md](CONTRIBUTING.md). Quando um equipamento for classificado errado, o [modelo de issue](.github/ISSUE_TEMPLATE/device-rule.md) pede as colunas do CSV necessárias para escrever a regra.

## Licença

[MIT](LICENSE)

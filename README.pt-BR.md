# zabbix-autodiscovery

🇺🇸 [Read in English](README.md)

**Varre as suas redes corporativas, identifica automaticamente os equipamentos de infraestrutura e os cadastra no Zabbix com o template, o grupo de hosts, a interface e as tags ideais.** Estações de trabalho e notebooks são filtrados e descartados automaticamente. Dashboards nativos do Zabbix inclusos (e Grafana opcional).

```text
$ zabbix-autodiscovery scan -o inventory.csv
Scanning: 192.168.0.0/24, 192.168.10.0/24, 192.168.20.0/24
  category            action    count
  switch              add       12
  firewall            add       2
  ap                  add       16
  printer             add       8
  cctv                add       14
  server-windows      add       6
  server-hardware     add       4
  workstation         ignore    73
  unknown             ignore    110
  Host name sources (add/review): snmp=48, agent=6, netbios=4, dns=2

$ zabbix-autodiscovery apply -i inventory.csv --dry-run
  + 192.168.10.52   printer     PRN-FINANCEIRO    [Rede/Impressoras + Filiais/PR]  name via snmp
      templates: AutoDiscovery - Printer by SNMP, Generic by SNMP
  + 192.168.10.22   server-hw   idrac-SRV01       [Infra/Server Hardware + Filiais/PR]  name via snmp
      templates: Dell iDRAC by SNMP
  = 192.168.0.1     firewall    IP already monitored, skipped
```

---

## Recursos Principais

- **Descoberta Completa e Concorrente:** Varredura rápida assíncrona por ICMP Ping, portas TCP, SNMP v1/v2c/v3, Zabbix Agent (passivo), NetBIOS (UDP 137), banner HTTP/TLS e DNS reverso confirmado. Uma segunda passada automática com timeout estendido elimina falsos negativos causados por latência ou enlaces VPN.
- **Classificação Agnóstica de Nome:** A regra nunca adivinha a função pelo nome do host. A decisão baseia-se estritamente no que o ativo responde (OIDs SNMP do `sysObjectID`, `sysDescr`, portas abertas, banner do servidor e `system.uname`). Já conta com regras prontas para:
  - **Rede & Wi-Fi:** Cisco, HPE/Aruba, H3C, Huawei, Juniper, MikroTik, TP-Link, D-Link, Ubiquiti/UniFi, Ruckus, Meraki;
  - **Segurança & Firewalls:** Fortinet/FortiGate, pfSense, OPNsense, Palo Alto, Sophos, SonicWall, Check Point;
  - **CFTV & Câmeras IP:** Hikvision, Dahua, Intelbras (MHDX/NVD/VIP), Axis (portas RTSP 554, 8000, 37777);
  - **Telefonia IP & VoIP:** Grandstream, Yealink, centrais Asterisk, FreePBX e Issabel (porta SIP 5060);
  - **Servidores & Hipervisores:** Windows Server, Linux (Debian, Ubuntu, RHEL), VMware ESXi, Hyper-V, Proxmox VE, iDRAC (Dell), iLO (HPE);
  - **Energia, Storage & Periféricos:** Nobreaks APC, Eaton, SMS e NHS; PDUs de rack gerenciáveis; storages Synology, QNAP e TrueNAS; impressoras HP, Brother, Epson, Kyocera, Ricoh, Lexmark, Xerox e Zebra.
- **Exclusão Precisa de Estações de Trabalho:** O `sysObjectID` da Microsoft diferencia workstations de servidores mesmo no Windows 11 e Windows Server 2025 (que compartilham o build 26100). Em máquinas sem SNMP, o perfil de portas e o agent Zabbix impedem o cadastro acidental de notebooks e desktops.
- **Detecção de Servidores sem Agente:** Servidores encontrados sem porta 10050 recebem o template `AutoDiscovery - Zabbix agent missing` e a tag `agent=missing`. Um alarme dedicado é disparado (somente se o host responder ping, evitando duplicidade com host down). Após a instalação do agente, o comando `agent-sync` migra o host para os templates de SO correspondentes.
- **Auditoria de Mudanças (`diff`):** Compare dois inventários para detectar imediatamente novos equipamentos conectados à rede (*rogue devices*), hosts desligados ou mudanças de portas e hostnames.
- **Templates Nativos Add-on Inclusos:**
  - **Impressoras (RFC 3805):** Contador vitalício de páginas, suprimentos (toner/cilindro) descobertos automaticamente com % e cálculo de nível, status de painel e número de série;
  - **Switches:** Ocupação percentual de portas físicas em uso a partir do walk IF-MIB (Zabbix 7.0+).
- **Dashboards Nativos Otimizados no Próprio Zabbix:** Dashboards pré-configurados por categoria com gráficos vetoriais (tráfego de rede, erros, temperatura), Top Hosts de latência e consumo, e matrizes Honeycomb (7.0+) ou tabelas de disponibilidade `hostavail` (6.0 LTS). Sem dependência obrigatória de Grafana.
- **Monitoramento de Certificados SSL e Domínios:** Verificação de validade de certificados TLS via Zabbix Agent 2 e expiração de domínios via RDAP (RFC 7480/9082), sem necessidade de scripts externos.
- **Mapas de Rede por Filial:** Geração de mapas visuais no Zabbix por localidade/filial, com posicionamento ordenado por categoria e ícones de status.
- **Compatibilidade:** Zabbix **6.0 LTS a 8.0**. Executável em Linux, Windows e macOS (Python 3.10+).

---

## Instalação e Requisitos

### Instalação rápida:
```bash
# Via pip ou uv (recomendado)
pip install git+https://github.com/GustavoMS0/zabbix-autodiscovery
```

No Windows sem instalar Python globalmente: execute `./zabbix-autodiscovery.ps1 init` (usa o [uv](https://docs.astral.sh/uv/) ou Python local).  
No Linux/macOS: execute `./zabbix-autodiscovery.sh init`.

---

## Guia de Implementação: Escolha o seu Cenário

O `zabbix-autodiscovery` foi arquitetado tanto para iniciar o monitoramento de uma infraestrutura do zero quanto para atuar com **total segurança** em um ambiente Zabbix que já está em produção há anos.

```
                           ┌───────────────────────────────────────────────┐
                           │          zabbix-autodiscovery init            │
                           └──────────────────────┬────────────────────────┘
                                                  ▼
                                      Qual é o seu cenário?
                                                  │
                 ┌────────────────────────────────┴────────────────────────────────┐
                 ▼                                                                 ▼
      【 CENÁRIO 1: ZABBIX NOVO 】                                     【 CENÁRIO 2: ZABBIX EM PRODUÇÃO 】
      • zabbix-autodiscovery check                                     • zabbix-autodiscovery check
      • zabbix-autodiscovery setup                                     • zabbix-autodiscovery audit  (diagnóstico)
      • zabbix-autodiscovery scan -o inventory.csv                     • zabbix-autodiscovery scan -o inventory.csv
      • zabbix-autodiscovery apply -i inventory.csv                    • zabbix-autodiscovery diff (compara scans)
      • zabbix-autodiscovery maps                                      • zabbix-autodiscovery apply (só novos)
      • zabbix-autodiscovery web                                       • zabbix-autodiscovery organize (organiza antigos)
                                                                       • zabbix-autodiscovery update-templates --all
```

---

### Cenário 1: Novo Ambiente Zabbix (Do Zero / Greenfield)

Ideal para quem está configurando uma nova instalação do Zabbix e deseja cadastrar dezenas ou centenas de equipamentos rapidamente com templates e grupos padronizados.

1. **Suba o Zabbix (se ainda não tiver):**
   Você pode usar a stack Docker inclusa neste repositório:
   ```bash
   cd deploy
   cp .env.example .env     # Defina senhas seguras no .env
   docker compose --profile zabbix --profile grafana up -d
   ```
2. **Gere o Token da API:**
   No frontend do Zabbix, acesse *Users → API tokens* e crie um token para um usuário com privilégio **Super admin**. (No Zabbix 8.0, certifique-se de que a role do usuário possui o acesso à API habilitado).
3. **Crie os arquivos de configuração do projeto:**
   ```bash
   mkdir meu-monitoramento && cd meu-monitoramento
   zabbix-autodiscovery init
   ```
   Isso criará o `config.yaml` e o arquivo `.env`.
4. **Configure os segredos e parâmetros:**
   * No arquivo `.env`: insira seu `ZABBIX_TOKEN` e a `SNMP_COMMUNITY`.
   * No arquivo `config.yaml`: informe a URL do frontend Zabbix (`zabbix.url`) e as faixas de rede em `scan.networks`.
5. **Valide os pré-requisitos:**
   ```bash
   zabbix-autodiscovery check
   ```
   O `check` verifica conectividade com a API, permissões do token e disponibilidade dos templates.
6. **Provisione a base no Zabbix:**
   ```bash
   zabbix-autodiscovery setup
   ```
   Cria os grupos de hosts, a macro global `{$SNMP_COMMUNITY}` (apenas se não existir), o template de detecção de agente ausente e os dashboards nativos otimizados.
7. **Varra e classifique a rede:**
   ```bash
   zabbix-autodiscovery scan -o inventory.csv
   ```
   O comando gera uma planilha CSV com todos os ativos identificados e suas respectivas categorias.
8. **Revise e aplique:**
   Abra o arquivo `inventory.csv` no Excel ou editor de texto. Apenas as linhas com a coluna `action = add` serão cadastradas. Linhas marcadas como `review` dependem da sua decisão, e a coluna `note` explica o motivo. Quando um equipamento casa com uma regra que exige SNMP, mas não respondeu SNMP (por exemplo, uma câmera encontrada pela porta RTSP), a ferramenta não adivinha nada: habilite o SNMP no equipamento e refaça o scan, ou ajuste `interface`/`templates` você mesmo (por exemplo, `icmp` / `ICMP Ping`) e mude `action` para `add`.
   ```bash
   zabbix-autodiscovery apply -i inventory.csv --dry-run   # Simula o cadastro
   zabbix-autodiscovery apply -i inventory.csv             # Cadastra os hosts no Zabbix
   ```
9. **Gere os mapas de topologia:**
   ```bash
   zabbix-autodiscovery maps
   ```
   Cria um mapa topológico por filial com ícones categorizados por tipo de equipamento.

---

### Cenário 2: Zabbix Já em Produção / Ativo (Brownfield)

Se o seu Zabbix já está ativo e monitora a sua infraestrutura, **você pode usar a ferramenta sem nenhum receio**:

> [!IMPORTANT]
> **Garantias de Não Destruição em Ambientes de Produção:**
> - **Nenhum host existente é sobrescrito ou apagado.** Hosts com IP ou DNS já cadastrados no Zabbix são automaticamente ignorados pelo `apply`.
> - **Macros globais existentes são preservadas.** Se `{$SNMP_COMMUNITY}` já tiver um valor diferente no Zabbix, ele não será alterado; os novos hosts receberão a comunidade como macro a nível de host.
> - **Todos os objetos gerados são rastreáveis.** Levam o prefixo `AutoDiscovery - ` e a tag `origin=autodiscovery`.
> - **Simulação disponível em tudo.** Os comandos aceitam `--dry-run`.

#### Fluxo Seguro Recomendado para Zabbix Ativo:

1. **Audite a saúde atual do Zabbix (100% Leitura):**
   ```bash
   zabbix-autodiscovery audit
   ```
   Emite um relatório detalhado sem alterar absolutamente nada:
   - Identifica IPs duplicados (mais de um host apontando para o mesmo IP);
   - Detecta máquinas virtuais clonadas com o mesmo `system.hostname`;
   - Aponta hosts onde o `Hostname=` do agente não coincide com o nome técnico do Zabbix (causa comum de falha em checagens ativas);
   - Lista hosts com templates de agente onde o agente está offline;
   - Lista os hosts com maior número de itens não suportados.

2. **Varra a rede para descobrir ativos não monitorados:**
   ```bash
   zabbix-autodiscovery scan -o inventory.csv
   ```
   *Dica:* Para varrer apenas uma sub-rede ou filial específica sem mexer no config:
   ```bash
   zabbix-autodiscovery scan --network 192.168.10.0/24 -o filial-pr.csv
   zabbix-autodiscovery scan --site Matriz -o matriz.csv
   ```

3. **Verifique novos ativos com o comando `diff`:**
   Se você já fez uma varredura anterior, compare os inventários para identificar equipamentos novos (*rogue devices*) ou mudanças de porta:
   ```bash
   zabbix-autodiscovery diff -old inventory-anterior.csv -new inventory.csv
   ```

4. **Cadastre apenas os ativos novos que faltavam no Zabbix:**
   ```bash
   zabbix-autodiscovery apply -i inventory.csv --dry-run
   zabbix-autodiscovery apply -i inventory.csv
   ```
   Qualquer dispositivo que já estava monitorado no Zabbix exibirá `IP already monitored, skipped` e não sofrerá alteração.

5. **Organize os hosts legados em grupos e tags padronizados:**
   Se os hosts antigos estavam desorganizados, o comando `organize` insere cada host das redes configuradas no grupo do seu tipo (ex: *Network/Switches*, *Network/Firewalls*) e no grupo da sua filial, adicionando as tags `type` e `site`:
   ```bash
   zabbix-autodiscovery organize --dry-run
   zabbix-autodiscovery organize
   ```
   *Nota:* O `organize` é estritamente aditivo. Ele não remove grupos existentes a menos que você especifique `--remove-groups GrupoAntigo1,GrupoAntigo2`.

6. **Vincule templates complementares a equipamentos antigos:**
   Se você tem switches ou impressoras legadas no Zabbix e deseja adicionar as métricas de suprimento ou portas em uso sem alterar o template do fabricante:
   ```bash
   zabbix-autodiscovery update-templates --all --dry-run
   zabbix-autodiscovery update-templates --all
   ```

---

## Tabela de Comandos

| Comando | Altera o Zabbix? | Descrição |
|---|---|---|
| `zabbix-autodiscovery init [--force]` | Não | Cria os arquivos iniciais `config.yaml` e `.env`. |
| `zabbix-autodiscovery check` | Não | Valida conexão, permissões de token, disponibilidade de templates e faixas de rede. |
| `zabbix-autodiscovery audit` | Não | Relatório de auditoria de consistência, IPs duplicados, itens não suportados e agentes. |
| `zabbix-autodiscovery scan [-o CSV] [--network CIDR] [--site NOME]` | Não | Varre as redes, classifica os dispositivos e grava a planilha de inventário. |
| `zabbix-autodiscovery diff -old CSV1 -new CSV2` | Não | Compara dois inventários gerados por scan e detalha inclusões, remoções e alterações. |
| `zabbix-autodiscovery apply -i CSV [--dry-run]` | **Sim** | Cadastra no Zabbix os hosts marcados com `action=add`. Pula o que já existe. |
| `zabbix-autodiscovery setup [--no-dashboards] [--rebuild-dashboards]` | **Sim** | Provisiona grupos de hosts, macro SNMP, template de agente ausente e dashboards. `--rebuild-dashboards` atualiza os dashboards existentes (ex.: depois de um `apply`, para os gráficos incluírem os hosts novos). |
| `zabbix-autodiscovery agent-sync [--dry-run]` | **Sim** | Migra servidores com tag `agent=missing` para os templates de agente quando responderem. |
| `zabbix-autodiscovery organize [--dry-run] [--remove-groups G1,G2]` | **Sim** | Insere hosts legados dos blocos escaneados nos grupos e tags de tipo/filial padronizados. |
| `zabbix-autodiscovery update-templates [--all] [--dry-run]` | **Sim** | Vincula templates extras (portas de switch, impressoras) a hosts legados do Zabbix. |
| `zabbix-autodiscovery maps [--dry-run] [--rebuild]` | **Sim** | Cria um mapa de topologia por filial com ícones por categoria e dashboard de mapas. |
| `zabbix-autodiscovery web [-i CSV] [--dry-run]` | **Sim** | Cadastra monitoramento de certificados SSL (via Agent 2) e vencimento de domínios (RDAP). |
| `zabbix-autodiscovery grafana-dashboards -o DIR` | Não | Exporta os arquivos JSON dos dashboards formatados para importação no Grafana. |

---

## Otimizações nos Dashboards Nativos do Zabbix

Ao rodar `zabbix-autodiscovery setup`, a ferramenta cria dashboards nativos no Zabbix construídos a partir dos seus próprios grupos de hosts. Os dashboards foram aprimorados para entregar máxima utilidade técnica:

1. **Visão Geral e Painéis por Categoria:**
   - Dashboards para: *Switches*, *Roteadores*, *Firewalls*, *Access Points*, *Impressoras*, *Servidores*, *Nobreaks*, *Storage*, *CFTV*, *Telefonia VoIP* e *PDUs*.
2. **Gráficos Vetoriais SVG (`svggraph`):**
   - Tráfego de interfaces de rede (Bits in/out), pacotes descartados/erros e temperatura exibidos diretamente na tela inicial do Zabbix sem plugins externos.
   - O gráfico do Zabbix seleciona hosts pelo nome (não por grupo): os gráficos listam os hosts dos grupos de cada tipo no momento em que o dashboard é criado. Depois de cadastrar hosts novos, rode `zabbix-autodiscovery setup --rebuild-dashboards`.
3. **Métricas de Desempenho e Top Hosts (`tophosts`):**
   - Ranking dos hosts com maior latência e perda de pacotes ICMP;
   - Ranking dos servidores com maior consumo de CPU e Memória (Zabbix 6.4+ / 7.0+).
4. **Disponibilidade e Visão Matricial:**
   - **Zabbix 7.0 / 8.0:** Painéis Honeycomb de disponibilidade ICMP e status da porta do agente Zabbix.
   - **Zabbix 6.0 LTS:** Tabela completa de disponibilidade de hosts (`hostavail`) com contagem de ativos Up/Down/Unknown por grupo.
5. **Servidores sem Agente:**
   - Painel de alerta dedicado filtrado por tag `agent:missing`.

---

## Gerenciamento de Múltiplas Filiais

No `config.yaml`, estruture suas redes por localidade:

```yaml
site_group: "Filiais/{site}"               # Cria grupos como "Filiais/Matriz" e "Filiais/PR"
scan:
  networks:
    - {network: 192.168.0.0/24, site: Matriz}
    - {network: 10.20.0.0/23,   site: Curitiba, proxy: proxy-curitiba}
    - 172.16.5.0/24                        # Rede sem filial específica
```

Cada host recebe automaticamente a tag `site=<nome>` e entra no respectivo grupo da filial, permitindo filtros cruzados no Zabbix e Grafana (ex.: visualizar apenas switches da filial de Curitiba).

---

## Contribuindo

Contribuições com novas regras de fabricantes, melhorias em dashboards e relatórios são sempre bem-vindas! Consulte o arquivo [CONTRIBUTING.md](CONTRIBUTING.md) para detalhes sobre como submeter pull requests.

## Licença

Este projeto é distribuído sob os termos da licença [MIT](LICENSE).

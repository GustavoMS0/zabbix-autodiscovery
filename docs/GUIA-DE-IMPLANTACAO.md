# Guia de implantação

🇺🇸 [English version](DEPLOYMENT-GUIDE.md)

Passo a passo para usar o zabbix-autodiscovery em três situações. Escolha a sua:

| Cenário | Quando usar | Vá para |
|---|---|---|
| **A** | Ainda não tem Zabbix e quer **Zabbix + Grafana** | [Cenário A](#cenário-a-nova-implantação-com-grafana) |
| **B** | Ainda não tem Zabbix e quer **só o Zabbix** (dashboards nativos) | [Cenário B](#cenário-b-nova-implantação-sem-grafana) |
| **C** | **Já tem um Zabbix em produção** (com ou sem Grafana) | [Cenário C](#cenário-c-zabbix-já-existente) |

> A ferramenta é para **redes locais**: LAN, VLANs e filiais via VPN/MPLS. Rode o scan de uma máquina dentro da rede, de preferência o próprio servidor ou proxy Zabbix, e só em redes sob a sua responsabilidade.

---

## Atalho: assistente interativo

Se preferir não editar arquivos à mão, um comando instala a ferramenta e abre um assistente que cobre os cenários A, B e C:

```bash
curl -fsSL https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.sh | bash        # Linux, por exemplo no servidor do Zabbix
```

```powershell
irm https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.ps1 | iex               # Windows, só com a URL e o token de API
```

O assistente detecta o Zabbix local, valida o token, sugere as redes a partir dos IPs já cadastrados e dos IPs da máquina, grava `config.yaml` e `.env` e conduz `check`, `setup`, `scan` e `apply`. Num Zabbix que já tem hosts, oferece também `audit`, `organize`, templates extras e serviços. Toda alteração pede confirmação e o padrão é "não". O resto deste guia explica as mesmas etapas, para quem quer fazer manualmente.

**Servidor novo (Linux):** se nenhum Zabbix responder na máquina, o assistente oferece instalar um. Ele instala o Docker pelo script oficial (get.docker.com, pede a senha do sudo) se faltar, grava `deploy/.env` com senhas aleatórias, sobe o Zabbix 8 (e o Grafana, se você quiser) com o `deploy/docker-compose.yml`, cria o token de API do Admin e troca a senha padrão do Admin. Depois segue direto para as redes e o scan, sem você precisar abrir a interface do Zabbix.

---

## Antes de começar (todos os cenários)

**1. Máquina que vai rodar a ferramenta.** Linux, Windows ou macOS, com acesso a todas as redes que serão varridas.

```bash
# Linux / macOS
git clone https://github.com/GustavoMS0/zabbix-autodiscovery
cd zabbix-autodiscovery
./zabbix-autodiscovery.sh init        # cria o ambiente Python, o config.yaml e o .env
```

```powershell
# Windows (precisa do uv: winget install astral-sh.uv, ou de um Python 3.10+)
git clone https://github.com/GustavoMS0/zabbix-autodiscovery
cd zabbix-autodiscovery
.\zabbix-autodiscovery.ps1 init
```

Nos exemplos abaixo, `zabbix-autodiscovery` significa `./zabbix-autodiscovery.sh` (Linux) ou `.\zabbix-autodiscovery.ps1` (Windows).

**2. Nos equipamentos.**
- Switches, APs, firewalls, impressoras e nobreaks: **SNMP habilitado**, liberando o IP do Zabbix e o da máquina do scan. Prefira uma comunidade própria ou SNMPv3, em vez de `public`.
- Servidores: **Zabbix Agent 2** com `Server=` e `ServerActive=` apontando para o Zabbix. O Agent 2 também é necessário para monitorar certificados SSL.
- Firewalls entre as redes: liberar ICMP, UDP 161 e TCP 10050 a partir do Zabbix e da máquina do scan.

**3. Editar o `config.yaml`** (o mínimo):

```yaml
zabbix:
  url: http://IP-DO-ZABBIX:8080
scan:
  networks:
    - {network: 192.168.0.0/24, site: Matriz}
    - {network: 192.168.10.0/24, site: Filial-01}
```

Os segredos ficam no **`.env`**, ao lado do `config.yaml`:

```
ZABBIX_TOKEN=<token da API>
SNMP_COMMUNITY=<sua comunidade SNMP>
```

Os nomes de grupo das regras (`Network/Switches`, `Servers/Windows`…) são livres: troque pelo padrão da sua empresa (ex.: `Rede/Switches`) antes do primeiro `setup`.

---

## Cenário A: nova implantação COM Grafana

**1. Subir Zabbix + Grafana com Docker** (num servidor Linux com Docker Compose):

```bash
cd deploy
cp .env.example .env
# edite o .env: troque TODAS as senhas (POSTGRES_PASSWORD, GRAFANA_ADMIN_PASSWORD, ZABBIX_GRAFANA_PASSWORD)
docker compose --profile zabbix --profile grafana up -d
```

| Serviço | Endereço | Primeiro login |
|---|---|---|
| Zabbix | `http://SERVIDOR:8080` | `Admin` / `zabbix` (troque a senha) |
| Grafana | `http://SERVIDOR:3000` | `admin` / valor de `GRAFANA_ADMIN_PASSWORD` |

**2. Criar o token da API** no Zabbix: *Usuários → API tokens → Criar*, com o usuário Admin (papel Super admin). Coloque o token em `ZABBIX_TOKEN` no `.env` da ferramenta.

**3. Usuário do Grafana.** No `config.yaml`, mantenha a seção `grafana_user`. No `.env` **da ferramenta**, use o mesmo usuário e senha do `deploy/.env`:

```
ZABBIX_GRAFANA_USER=grafana
ZABBIX_GRAFANA_PASSWORD=<igual ao deploy/.env>
```

**4. Preparar, descobrir e cadastrar:**

```bash
zabbix-autodiscovery check                         # só leitura: valida token e permissões
zabbix-autodiscovery setup                         # grupos, templates, dashboards e usuário do Grafana
zabbix-autodiscovery scan -o inventario.csv        # só lê a rede
#   revise o CSV no Excel (separador ;): coluna "action" = add | review | ignore
zabbix-autodiscovery apply -i inventario.csv --dry-run
zabbix-autodiscovery apply -i inventario.csv
zabbix-autodiscovery setup --rebuild-dashboards    # dashboards com os hosts recém-cadastrados
zabbix-autodiscovery maps                          # um mapa por filial
```

**5. Dashboards do Grafana.** Os dashboards que já vêm na pasta `deploy/grafana/dashboards` usam os nomes de grupo do exemplo. Se você trocou os nomes de grupo no `config.yaml`, gere-os de novo e reinicie o Grafana:

```bash
zabbix-autodiscovery grafana-dashboards -o deploy/grafana/dashboards
cd deploy && docker compose restart grafana
```

No Grafana, os dashboards ficam na pasta **Zabbix AutoDiscovery**.

---

## Cenário B: nova implantação SEM Grafana

Igual ao cenário A, com três diferenças:

1. Suba só o Zabbix:
   ```bash
   cd deploy && cp .env.example .env     # troque as senhas
   docker compose --profile zabbix up -d
   ```
   Também serve um Zabbix instalado por pacote, sem Docker.
2. No `config.yaml`, **apague a seção `grafana_user`**.
3. Pule o passo 5. Os dashboards ficam no próprio Zabbix, em *Dashboards*, com o prefixo **AutoDiscovery -**: visão geral, switches, firewalls, APs, impressoras, servidores, nobreaks, hardware de servidor, mapas, certificados e domínios.

---

## Cenário C: Zabbix já existente

A ferramenta **não altera o que já existe**:
- hosts já monitorados (mesmo IP ou DNS) são pulados;
- um nome já usado com outro IP é tratado como possível duplicata e pulado;
- macros, grupos, usuários e dashboards existentes são mantidos.

Tudo o que ela cria leva o prefixo `AutoDiscovery -` ou a tag `origin=autodiscovery`.

**1. Token.** Crie um token de API com um usuário **Super admin**. No Zabbix 8, o papel precisa ter "Acesso à API" habilitado. Aponte `zabbix.url` para o seu Zabbix.

**2. Diagnóstico (nada é alterado):**

```bash
zabbix-autodiscovery check      # permissões, templates disponíveis, o que seria criado
zabbix-autodiscovery audit      # IPs duplicados, máquinas clonadas, agentes, itens com erro
```

**3. Descobrir o que ainda não é monitorado:**

```bash
zabbix-autodiscovery scan -o inventario.csv
# ou por partes: scan --site Matriz -o matriz.csv   |   scan --network 192.168.10.0/24 -o pr.csv
zabbix-autodiscovery apply -i inventario.csv --dry-run    # confira a lista
zabbix-autodiscovery setup                                # grupos, templates e dashboards (idempotente)
zabbix-autodiscovery apply -i inventario.csv
```

**4. Organizar os hosts que já existiam** (opcional, recomendado):

```bash
zabbix-autodiscovery organize --dry-run           # mostra grupo de tipo/filial e tags que seriam acrescentados
zabbix-autodiscovery organize                     # só acrescenta; não remove nada
zabbix-autodiscovery update-templates --all       # ocupação de portas, suprimentos de impressora
zabbix-autodiscovery services -i inventario.csv   # tags e checagens de serviços (bancos, AD, clusters)
zabbix-autodiscovery setup --rebuild-dashboards
zabbix-autodiscovery maps
```

**5. Grafana (opcional):**
- **Já tem Grafana:** gere os JSON com `zabbix-autodiscovery grafana-dashboards -o dashboards/` e importe em *Dashboards → New → Import*. Cada dashboard tem um seletor de fonte de dados, então funciona com o datasource Zabbix que você já tem.
- **Quer um Grafana novo apontando para esse Zabbix:** em `deploy/.env`, defina `ZABBIX_API_URL=http://SEU-ZABBIX/api_jsonrpc.php` e as credenciais do Grafana. Configure `grafana_user` no `config.yaml`, rode `zabbix-autodiscovery setup` (cria o usuário somente leitura) e suba só o Grafana: `docker compose --profile grafana up -d`.

---

## Depois da implantação: rotina sugerida

| Frequência | O que fazer |
|---|---|
| Mensal (ou após mudanças na rede) | `scan -o novo.csv` → `diff -old anterior.csv -new novo.csv` (equipamentos novos, sumidos ou alterados) → `apply` dos novos |
| Depois de cadastrar hosts | `setup --rebuild-dashboards` e `maps --rebuild` |
| Ao instalar o agente num servidor | `agent-sync` (troca para os templates de agente e remove o alerta de "agente ausente") |
| Periodicamente | `audit` (duplicidades, agentes com nome errado, itens sem suporte) |
| Novos sites ou domínios para vigiar | Acrescente na seção `web` do `config.yaml` e rode `web` |

**No CSV**, linhas marcadas como `review` dependem de você. A coluna `note` explica o motivo, por exemplo "o equipamento não respondeu SNMP".

---

## Problemas comuns

| Sintoma | Causa provável | Solução |
|---|---|---|
| `API token expired` | Token vencido | Crie outro token e atualize o `.env` |
| `check` avisa sobre o papel | Usuário sem Super admin ou papel sem acesso à API (Zabbix 8) | Use um Super admin ou habilite a API no papel |
| Servidor aparece como `review` "agent installed, scanner refused" | O IP da máquina do scan não está no `Server=` do agente | Rode o scan do servidor Zabbix ou inclua o IP no `Server=` |
| Equipamento de rede em `review` com "no SNMP answer" | SNMP desligado ou ACL bloqueando | Habilite o SNMP e refaça o scan, ou cadastre só com ICMP ajustando o CSV |
| Hosts não aparecem no scan | Firewall bloqueando a máquina do scan | Rode do servidor/proxy Zabbix ou libere as portas |
| Gráficos do Grafana vazios | Nomes de grupo diferentes dos usados nos dashboards | `grafana-dashboards -o deploy/grafana/dashboards` e reinicie o Grafana |
| Certificado com "Unsupported item key" | O host indicado em `agent2_host` usa o agente clássico | Instale o Zabbix Agent 2 nesse host |

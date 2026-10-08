"""Interactive step-by-step assistant: zabbix-autodiscovery wizard.

Guides a first deployment (or a run against an existing Zabbix): connection and token, networks, SNMP,
Grafana, config files, then check -> setup -> scan -> apply -> organize -> dashboards/maps.
Nothing is changed in Zabbix without an explicit "yes", and the default answer to every change is "no".
"""
import argparse
import getpass
import ipaddress
import locale
import os
import re
import socket
import sys
from collections import Counter
from importlib import resources
from pathlib import Path

TEXT = {
    "pt": {
        "title": "zabbix-autodiscovery - assistente de implantação",
        "intro": "Vou guiar você etapa por etapa. Nada é alterado no Zabbix sem a sua confirmação (o padrão é sempre 'não').",
        "no_tty": "O assistente precisa de um terminal interativo.",
        "step": "Etapa",
        "reuse": "Já existe um config.yaml aqui. Reaproveitar (s) ou criar um novo (n)?",
        "url": "URL do Zabbix (frontend)",
        "url_bad": "Não consegui falar com a API do Zabbix nesse endereço",
        "url_ok": "Zabbix {version} encontrado",
        "token_help": "Crie um token em Usuários > API tokens, com um usuário Super admin (no Zabbix 8 o papel precisa ter acesso à API).",
        "token": "Token da API (não aparece na tela)",
        "token_bad": "Token recusado",
        "token_ok": "Token do usuário '{user}' (tipo {rtype})",
        "not_super": "Atenção: o setup precisa de um Super admin. Você poderá só consultar e simular.",
        "existing": "Este Zabbix já tem {n} hosts: vou tratar como ambiente EXISTENTE (nada do que existe será alterado).",
        "new": "Este Zabbix está praticamente vazio: vou tratar como implantação NOVA.",
        "nets_found": "Redes sugeridas (hosts já monitorados no Zabbix e rede desta máquina):",
        "nets_use": "Usar estas redes? (s = sim / n = digitar outras)",
        "nets_enter": "Digite uma rede por linha (ex.: 192.168.0.0/24 ou 10.0.0.10-10.0.0.50). Linha vazia termina.",
        "net": "Rede",
        "site": "Nome da filial/site para {net} (Enter = sem nome)",
        "exclude": "Faixas que NÃO devem ser varridas, ex. DHCP de estações (separadas por vírgula, Enter = nenhuma)",
        "snmp": "Comunidade SNMP dos equipamentos (Enter = public)",
        "snmp_public": "Dica: 'public' é a primeira comunidade que qualquer scanner tenta; prefira uma própria ou SNMPv3.",
        "pt_groups": "Usar nomes de grupos em português (Rede/Switches, Servidores/Windows, Filiais/<site>)?",
        "grafana": "Vai usar o Grafana com o Zabbix?",
        "grafana_user": "Usuário somente-leitura do Zabbix para o Grafana",
        "grafana_pass": "Senha desse usuário (a mesma do deploy/.env do Grafana)",
        "saved": "Arquivos gravados: {files}",
        "check": "Validação (somente leitura)",
        "setup_q": "Criar no Zabbix os grupos, templates 'AutoDiscovery' e dashboards (setup)?",
        "scan_q": "Varrer as redes agora? (só lê a rede; pode levar alguns minutos)",
        "scan_file": "Inventário salvo em {file}. Linhas 'review' precisam da sua decisão no CSV (coluna 'note' explica).",
        "dry": "Simulação do cadastro (nada é alterado)",
        "apply_q": "Cadastrar no Zabbix os {n} hosts marcados como 'add'?",
        "none_to_add": "Nenhum host novo para cadastrar.",
        "edit_csv": "Quer revisar o CSV antes? Edite {file} agora e pressione Enter para continuar.",
        "audit": "Diagnóstico do ambiente (somente leitura)",
        "organize_q": "Organizar os hosts que JÁ existiam (só acrescenta grupos de tipo/filial e tags)?",
        "addons_q": "Vincular templates extras (portas de switch, suprimentos de impressora) aos hosts antigos?",
        "services_q": "Acrescentar tags e checagens de serviços (bancos, AD, clusters) aos hosts existentes?",
        "dash_q": "Atualizar os dashboards com os hosts atuais (setup --rebuild-dashboards)?",
        "maps_q": "Criar/atualizar um mapa por filial?",
        "done": "Concluído. Próximos passos sugeridos:",
        "next": ["Abra os dashboards 'AutoDiscovery -' no Zabbix.",
                 "Mensalmente: scan + diff para achar equipamentos novos.",
                 "Ao instalar o agente num servidor: agent-sync.",
                 "Guia completo: docs/GUIA-DE-IMPLANTACAO.md"],
        "inst": "Instalação do Zabbix",
        "inst_q": "Nenhum Zabbix respondeu nesta máquina. Instalar um Zabbix 8 novo aqui, com Docker?",
        "inst_no_compose_file": "Não achei deploy/docker-compose.yml ao lado do config.yaml; rode o assistente na pasta do projeto.",
        "docker_missing": "O Docker não está instalado.",
        "docker_q": "Instalar o Docker agora com o script oficial (get.docker.com)? Vai pedir a senha do sudo.",
        "docker_manual": "Instale o Docker e o plugin Docker Compose (https://docs.docker.com/engine/install/) e rode o assistente de novo.",
        "docker_failed": "O Docker não ficou disponível depois da instalação.",
        "compose_missing": "O plugin 'docker compose' não está instalado (ex.: apt install docker-compose-plugin).",
        "inst_grafana": "Instalar também o Grafana (porta 3000), já ligado a este Zabbix?",
        "env_reuse": "Usando o deploy/.env que já existe (as senhas dele são mantidas).",
        "env_written": "Senhas aleatórias gravadas em {file} (somente o seu usuário lê).",
        "compose_up": "Baixando as imagens e iniciando os containers (pode levar alguns minutos)...",
        "wait_api": "Aguardando o Zabbix criar o banco e responder",
        "wait_timeout": "O Zabbix não respondeu a tempo. Veja: docker compose logs zabbix-server (na pasta deploy).",
        "admin_new": "Nova senha do usuário Admin do Zabbix (Enter = gerar uma aleatória)",
        "admin_confirm": "Repita a senha",
        "admin_mismatch": "As senhas não conferem.",
        "admin_current": "A senha padrão do Admin não funcionou. Senha atual do Admin (Enter = informar um token manualmente)",
        "inst_done": "Zabbix pronto em {url} (usuário Admin). Token de API criado e salvo no .env.",
        "admin_generated": "Senha do Admin: {password}  <- anote agora, ela não fica gravada em nenhum arquivo",
        "grafana_ready": "Grafana em http://<este-servidor>:{port} (usuário admin, senha em GRAFANA_ADMIN_PASSWORD no deploy/.env).",
        "yes": "s", "no": "n", "skipped": "pulado",
    },
    "en": {
        "title": "zabbix-autodiscovery - deployment assistant",
        "intro": "I will guide you step by step. Nothing changes in Zabbix without your confirmation (the default is always 'no').",
        "no_tty": "The wizard needs an interactive terminal.",
        "step": "Step",
        "reuse": "A config.yaml already exists here. Reuse it (y) or create a new one (n)?",
        "url": "Zabbix URL (frontend)",
        "url_bad": "Could not reach the Zabbix API at this address",
        "url_ok": "Found Zabbix {version}",
        "token_help": "Create a token in Users > API tokens, for a Super admin user (on Zabbix 8 the role needs API access).",
        "token": "API token (hidden)",
        "token_bad": "Token refused",
        "token_ok": "Token of user '{user}' (type {rtype})",
        "not_super": "Warning: setup needs a Super admin. You will only be able to read and simulate.",
        "existing": "This Zabbix already has {n} hosts: treating it as an EXISTING environment (nothing that exists will be changed).",
        "new": "This Zabbix is almost empty: treating it as a NEW deployment.",
        "nets_found": "Suggested networks (hosts already monitored by Zabbix and this machine's network):",
        "nets_use": "Use these networks? (y = yes / n = type others)",
        "nets_enter": "Type one network per line (e.g. 192.168.0.0/24 or 10.0.0.10-10.0.0.50). Empty line ends.",
        "net": "Network",
        "site": "Site name for {net} (Enter = none)",
        "exclude": "Ranges that must NOT be scanned, e.g. workstation DHCP (comma separated, Enter = none)",
        "snmp": "SNMP community of the devices (Enter = public)",
        "snmp_public": "Tip: 'public' is the first community any scanner tries; prefer your own or SNMPv3.",
        "pt_groups": "Use Portuguese group names (Rede/Switches, Servidores/Windows, Filiais/<site>)?",
        "grafana": "Will you use Grafana with Zabbix?",
        "grafana_user": "Read-only Zabbix user for Grafana",
        "grafana_pass": "Password of that user (same as Grafana's deploy/.env)",
        "saved": "Files written: {files}",
        "check": "Validation (read-only)",
        "setup_q": "Create the host groups, 'AutoDiscovery' templates and dashboards in Zabbix (setup)?",
        "scan_q": "Scan the networks now? (read-only; may take a few minutes)",
        "scan_file": "Inventory saved to {file}. 'review' rows need your decision in the CSV (the 'note' column explains).",
        "dry": "Onboarding simulation (nothing changes)",
        "apply_q": "Create the {n} hosts marked 'add' in Zabbix?",
        "none_to_add": "No new hosts to create.",
        "edit_csv": "Review the CSV first? Edit {file} now and press Enter to continue.",
        "audit": "Environment diagnosis (read-only)",
        "organize_q": "Organize the hosts that ALREADY existed (only adds type/site groups and tags)?",
        "addons_q": "Link add-on templates (switch ports, printer supplies) to existing hosts?",
        "services_q": "Add service tags and checks (databases, AD, clusters) to existing hosts?",
        "dash_q": "Refresh the dashboards with the current hosts (setup --rebuild-dashboards)?",
        "maps_q": "Create/refresh one map per site?",
        "done": "Done. Suggested next steps:",
        "next": ["Open the 'AutoDiscovery -' dashboards in Zabbix.",
                 "Monthly: scan + diff to find new devices.",
                 "When an agent is installed on a server: agent-sync.",
                 "Full guide: docs/DEPLOYMENT-GUIDE.md"],
        "inst": "Zabbix installation",
        "inst_q": "No Zabbix answered on this machine. Install a new Zabbix 8 here with Docker?",
        "inst_no_compose_file": "deploy/docker-compose.yml was not found next to config.yaml; run the wizard from the project folder.",
        "docker_missing": "Docker is not installed.",
        "docker_q": "Install Docker now with the official script (get.docker.com)? It will ask for your sudo password.",
        "docker_manual": "Install Docker and the Docker Compose plugin (https://docs.docker.com/engine/install/) and run the wizard again.",
        "docker_failed": "Docker is still not available after the installation.",
        "compose_missing": "The 'docker compose' plugin is not installed (e.g. apt install docker-compose-plugin).",
        "inst_grafana": "Also install Grafana (port 3000), already connected to this Zabbix?",
        "env_reuse": "Using the existing deploy/.env (its passwords are kept).",
        "env_written": "Random passwords written to {file} (readable by your user only).",
        "compose_up": "Pulling the images and starting the containers (this may take a few minutes)...",
        "wait_api": "Waiting for Zabbix to create its database and answer",
        "wait_timeout": "Zabbix did not answer in time. See: docker compose logs zabbix-server (in the deploy folder).",
        "admin_new": "New password for the Zabbix Admin user (Enter = generate a random one)",
        "admin_confirm": "Repeat the password",
        "admin_mismatch": "The passwords do not match.",
        "admin_current": "The default Admin password did not work. Current Admin password (Enter = type a token instead)",
        "inst_done": "Zabbix ready at {url} (user Admin). API token created and saved in .env.",
        "admin_generated": "Admin password: {password}  <- write it down now, it is not stored in any file",
        "grafana_ready": "Grafana at http://<this-server>:{port} (user admin, password in GRAFANA_ADMIN_PASSWORD in deploy/.env).",
        "yes": "y", "no": "n", "skipped": "skipped",
    },
}

PT_GROUPS = {
    "Network/Firewalls": "Rede/Firewalls", "Network/Access Points": "Rede/Access Points",
    "Network/Printers": "Rede/Impressoras", "Network/Switches": "Rede/Switches", "Network/Routers": "Rede/Roteadores",
    "Network/Other": "Rede/Outros", "Infrastructure/UPS": "Infra/Nobreaks", "Infrastructure/PDU": "Infra/PDU",
    "Infrastructure/Storage": "Infra/Storage", "Infrastructure/Server Hardware": "Infra/Hardware Servidores",
    "Servers/Windows": "Servidores/Windows", "Servers/Linux": "Servidores/Linux",
    "Servers/Hypervisors": "Servidores/Hypervisors", "Security/CCTV": "Seguranca/CFTV",
    "Telephony/VoIP": "Telefonia/VoIP", "Web/Certificates": "Web/Certificados", "Web/Domains": "Web/Dominios",
}
LOCAL_URLS = ["http://127.0.0.1:8080", "http://127.0.0.1/zabbix", "http://127.0.0.1"]


# ---------------------------------------------------------------- pure helpers (tested)

def default_lang():
    lang = os.environ.get("LANG") or (locale.getlocale()[0] or "")
    return "pt" if lang.lower().startswith("pt") else "en"


def suggest_networks(ips, minimum=1):
    """Private IPv4 addresses -> [(network '/24', count)] sorted by count, most populated first."""
    counts = Counter()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.version == 4 and addr.is_private and not addr.is_loopback:
            counts[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1
    return [(n, c) for n, c in sorted(counts.items(), key=lambda x: (-x[1], x[0])) if c >= minimum]


def local_ips():
    ips = set()
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))           # no packet is sent: only picks the outgoing interface
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    return sorted(ips)


def valid_target(text):
    text = text.strip()
    try:
        if "-" in text:
            a, b = (ipaddress.ip_address(p.strip()) for p in text.split("-", 1))
            return a.version == b.version and int(a) <= int(b)
        if "/" in text:
            ipaddress.ip_network(text, strict=False)
            return True
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def render_config(example, url, networks, exclude=(), grafana=True, pt_groups=False):
    """Fill the example config (keeping its comments and rules) with the wizard answers.

    networks: [(network, site)]."""
    text = re.sub(r"(?m)^  url: \S+", lambda _: f"  url: {url}", example, count=1)
    start, end = text.index("  networks:\n"), text.index("  exclude:")
    lines = ["  networks:"] + [f"    - {{network: {n}, site: {s}}}" if s else f"    - {n}" for n, s in networks]
    text = text[:start] + "\n".join(lines) + "\n" + text[end:]
    ex_start = text.index("  exclude:")
    ex_end = text.index("  ports:", ex_start)
    ex_lines = (["  exclude:"] + [f"    - {e}" for e in exclude]) if exclude else ["  exclude: []"]
    text = text[:ex_start] + "\n".join(ex_lines) + "\n" + text[ex_end:]
    if not grafana:
        g_start = text.index("# Read-only Zabbix user for the Grafana")
        g_end = text.index("scan:", g_start)
        text = text[:g_start] + text[g_end:]
    if pt_groups:
        for en, pt in PT_GROUPS.items():
            text = text.replace(f"group: {en}\n", f"group: {pt}\n").replace(f"group: {en} ", f"group: {pt} ")
        text = text.replace('site_group: "Sites/{site}"', 'site_group: "Filiais/{site}"')
    return text


def render_env(token, community, grafana_user="", grafana_password=""):
    lines = ["# zabbix-autodiscovery secrets (never commit or share this file)",
             f"ZABBIX_TOKEN={token}", f"SNMP_COMMUNITY={community}"]
    if grafana_user:
        lines += [f"ZABBIX_GRAFANA_USER={grafana_user}", f"ZABBIX_GRAFANA_PASSWORD={grafana_password}"]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- interaction

class Wizard:
    def __init__(self, lang, config, ask=input, secret=getpass.getpass, out=print):
        self.t, self.config, self.ask_fn, self.secret_fn, self.out = TEXT[lang], Path(config), ask, secret, out
        self.lang, self.n = lang, 0

    def step(self, title):
        self.n += 1
        self.out(f"\n=== {self.t['step']} {self.n}: {title} ===")

    def ask(self, prompt, default=""):
        answer = self.ask_fn(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
        return answer or default

    def yes(self, prompt, default=False):
        y, n = self.t["yes"], self.t["no"]
        hint = f"{y.upper()}/{n}" if default else f"{y}/{n.upper()}"
        answer = self.ask_fn(f"{prompt} ({hint}): ").strip().lower()
        return default if not answer else answer.startswith((y, "y", "s"))

    # -- steps

    def connect(self):
        from .zabbix_api import ZabbixAPI, ZabbixError
        self.step(self.t["url"])
        default = next((u for u in LOCAL_URLS if self._probe(u)), "")
        while True:
            url = self.ask(self.t["url"], default)
            version = self._probe(url)
            if version:
                self.out(f"  ok: {self.t['url_ok'].format(version=version)}")
                break
            self.out(f"  ! {self.t['url_bad']}: {url}")
        self.out(f"  {self.t['token_help']}")
        while True:
            token = self.secret_fn(f"{self.t['token']}: ").strip()
            try:
                api = ZabbixAPI(url, token=token)
                user = api.call("user.checkAuthentication", {"token": token}, auth=False)
                role = api.call("role.get", {"roleids": user.get("roleid"), "output": ["type"]})
                rtype = {"1": "User", "2": "Admin", "3": "Super admin"}.get(role[0]["type"] if role else "", "?")
                self.out(f"  ok: {self.t['token_ok'].format(user=user.get('username'), rtype=rtype)}")
                if rtype != "Super admin":
                    self.out(f"  ! {self.t['not_super']}")
                return url, token, api
            except (ZabbixError, OSError, ValueError, KeyError) as exc:
                self.out(f"  ! {self.t['token_bad']}: {str(exc)[:120]}")

    @staticmethod
    def _probe(url):
        import requests
        try:
            u = url.rstrip("/") + ("" if url.endswith(".php") else "/api_jsonrpc.php")
            r = requests.post(u, json={"jsonrpc": "2.0", "method": "apiinfo.version", "params": {}, "id": 1},
                              timeout=5)
            return r.json().get("result")
        except Exception:
            return None

    def offer_install(self):
        """Only on Linux, and only when no Zabbix answers on this machine."""
        if not sys.platform.startswith("linux") or any(self._probe(u) for u in LOCAL_URLS):
            return False
        return self.yes(self.t["inst_q"], default=False)

    def install_zabbix(self):
        """Docker (if asked) -> deploy/.env -> docker compose up -> token + new Admin password.
        Returns {url, token, api, grafana, grafana_user, grafana_password}, or None to fall back to connect()."""
        import subprocess
        try:
            return self._install_zabbix()
        except subprocess.CalledProcessError as exc:
            self.out(f"  ! {' '.join(map(str, exc.cmd))} -> exit {exc.returncode}")
            return None

    def _install_zabbix(self):
        from . import bootstrap
        from .zabbix_api import ZabbixAPI, ZabbixError
        self.step(self.t["inst"])
        deploy = self.config.resolve().parent / "deploy"
        if not (deploy / "docker-compose.yml").exists():
            self.out(f"  ! {self.t['inst_no_compose_file']}")
            return None
        prefix = bootstrap.docker_prefix()
        if prefix is None:
            self.out(f"  {self.t['docker_missing']}")
            if not self.yes(self.t["docker_q"]):
                self.out(f"  {self.t['docker_manual']}")
                return None
            bootstrap.install_docker()
            prefix = bootstrap.docker_prefix()
            if prefix is None:
                self.out(f"  ! {self.t['docker_failed']}")
                return None
        if not bootstrap.has_compose(prefix):
            self.out(f"  ! {self.t['compose_missing']}")
            return None
        grafana = self.yes(self.t["inst_grafana"])
        env_file = deploy / ".env"
        if env_file.exists():
            self.out(f"  {self.t['env_reuse']}")
        else:
            example = (deploy / ".env.example").read_text("utf-8")
            env_file.write_text(bootstrap.render_deploy_env(example, bootstrap.local_timezone()), "utf-8")
            env_file.chmod(0o600)
            self.out(f"  {self.t['env_written'].format(file=env_file)}")
        env = bootstrap.read_env(env_file.read_text("utf-8"))
        self.out(f"  {self.t['compose_up']}")
        bootstrap.compose_up(prefix, deploy, grafana)
        self.out(f"  {self.t['wait_api']}", end="", flush=True)
        url = bootstrap.ZABBIX_URL
        version = bootstrap.wait_for_api(url, self._probe, out=self.out)
        self.out("")
        if not version:
            self.out(f"  ! {self.t['wait_timeout']}")
            return None
        self.out(f"  ok: {self.t['url_ok'].format(version=version)}")

        while True:
            new = self.secret_fn(f"{self.t['admin_new']}: ").strip()
            if not new or self.secret_fn(f"{self.t['admin_confirm']}: ").strip() == new:
                break
            self.out(f"  ! {self.t['admin_mismatch']}")
        generated = not new
        new = new or bootstrap.new_password()
        current = bootstrap.DEFAULT_ADMIN_PASSWORD
        while True:
            try:
                token = bootstrap.first_access(url, current, new)
                break
            except ZabbixError as exc:
                self.out(f"  ! {str(exc)[:120]}")
                current = self.secret_fn(f"{self.t['admin_current']}: ").strip()
                if not current:
                    return None
        self.out(f"  ok: {self.t['inst_done'].format(url=url)}")
        if generated:
            self.out(f"  {self.t['admin_generated'].format(password=new)}")
        if grafana:
            self.out(f"  {self.t['grafana_ready'].format(port=bootstrap.GRAFANA_PORT)}")
        return {"url": url, "token": token, "api": ZabbixAPI(url, token=token), "grafana": grafana,
                "grafana_user": env.get("ZABBIX_GRAFANA_USER", "grafana"),
                "grafana_password": env.get("ZABBIX_GRAFANA_PASSWORD", "")}

    def networks(self, api):
        self.step(self.t["net"])
        known = [i["ip"] for i in api.call("hostinterface.get", {"output": ["ip"]}) if i["ip"]]
        hosts = api.call("host.get", {"countOutput": True})
        self.out(f"  {self.t['existing'].format(n=hosts) if int(hosts) > 5 else self.t['new']}")
        suggested = suggest_networks(known + local_ips())
        chosen = []
        if suggested:
            self.out(f"  {self.t['nets_found']}")
            for net, count in suggested[:12]:
                self.out(f"    - {net}  ({count})")
            if self.yes(self.t["nets_use"], default=True):
                chosen = [n for n, _ in suggested[:12]]
        if not chosen:
            self.out(f"  {self.t['nets_enter']}")
            while True:
                net = self.ask(f"  {self.t['net']}")
                if not net:
                    break
                if valid_target(net):
                    chosen.append(net)
                else:
                    self.out("  ! ?")
        networks = [(n, re.sub(r"[^\w.-]", "-", self.ask(f"  {self.t['site'].format(net=n)}"))) for n in chosen]
        exclude = [e.strip() for e in self.ask(self.t["exclude"]).split(",") if e.strip() and valid_target(e)]
        return networks, exclude, int(hosts) > 5

    def run(self):
        from . import cli
        self.out(f"\n{self.t['title']}\n{self.t['intro']}")
        if self.config.exists() and self.yes(self.t["reuse"], default=True):
            cfg = cli.load_config(self.config)
            api = cli.connect(cfg)
            existing = int(api.call("host.get", {"countOutput": True})) > 5
        else:
            installed = self.install_zabbix() if self.offer_install() else None
            url, token, api = (installed["url"], installed["token"], installed["api"]) if installed \
                else self.connect()
            networks, exclude, existing = self.networks(api)
            self.step("SNMP")
            community = self.ask(self.t["snmp"], "public")
            if community == "public":
                self.out(f"  {self.t['snmp_public']}")
            pt_groups = self.lang == "pt" and self.yes(self.t["pt_groups"], default=True)
            self.step("Grafana")
            guser = gpass = ""
            if installed:
                grafana, guser, gpass = installed["grafana"], installed["grafana_user"], installed["grafana_password"]
            else:
                grafana = self.yes(self.t["grafana"], default=False)
            if grafana and not installed:
                guser = self.ask(self.t["grafana_user"], "grafana")
                gpass = self.secret_fn(f"{self.t['grafana_pass']}: ")
            example = resources.files("zabbix_autodiscovery").joinpath("data/config.example.yaml").read_text("utf-8")
            self.config.write_text(render_config(example, url, networks, exclude, grafana, pt_groups), "utf-8")
            env = self.config.resolve().parent / ".env"
            env.write_text(render_env(token, community, guser, gpass), "utf-8")
            if os.name == "posix":
                env.chmod(0o600)
            self.out(f"  {self.t['saved'].format(files=f'{self.config}, {env}')}")
            cfg = cli.load_config(self.config)
            api = cli.connect(cfg)
        return self.operate(cli, cfg, api, existing)

    def operate(self, cli, cfg, api, existing):
        from . import organize, provision
        ns = argparse.Namespace
        self.step(self.t["check"])
        cli.cmd_check(cfg, ns(config=str(self.config)))
        self.step("setup")
        if self.yes(self.t["setup_q"]):
            provision.setup(api, cfg)
        else:
            self.out(f"  {self.t['skipped']}")
        csv_file = str(self.config.resolve().parent / "inventory.csv")
        self.step("scan")
        if not self.yes(self.t["scan_q"], default=True):
            return 0
        cli.cmd_scan(cfg, ns(output=csv_file, delimiter=";", network=None, site=None))
        self.out(f"  {self.t['scan_file'].format(file=csv_file)}")
        self.ask(self.t["edit_csv"].format(file=csv_file))
        self.step(self.t["dry"])
        rows = [r for r in cli.read_inventory(csv_file) if r.get("action") == "add"]
        if rows:
            apply_ns = ns(input=csv_file, dry_run=True, allow_duplicate_names=False)
            cli.cmd_apply(cfg, apply_ns)
            if self.yes(self.t["apply_q"].format(n=len(rows))):
                cli.cmd_apply(cfg, ns(input=csv_file, dry_run=False, allow_duplicate_names=False))
        else:
            self.out(f"  {self.t['none_to_add']}")
        if existing:
            self.step(self.t["audit"])
            organize.audit(api, cfg)
            organize.organize(api, cfg, dry_run=True)
            if self.yes(self.t["organize_q"]):
                organize.organize(api, cfg)
            if self.yes(self.t["addons_q"]):
                cli.cmd_update_templates(cfg, ns(dry_run=False, all=True))
            if self.yes(self.t["services_q"]):
                cli.cmd_services(cfg, ns(input=csv_file, dry_run=False))
        self.step("dashboards")
        if self.yes(self.t["dash_q"], default=False):
            provision.setup_zabbix_dashboards(api, cfg, rebuild=True)
        if cfg.get("_sites") and self.yes(self.t["maps_q"], default=False):
            cli.cmd_maps(cfg, ns(config=str(self.config), rebuild=True, dry_run=False))
        self.out(f"\n{self.t['done']}")
        for line in self.t["next"]:
            self.out(f"  - {line}")
        return 0


def main(args):
    lang = args.lang or default_lang()
    if not sys.stdin.isatty() and not args.force_tty:
        raise SystemExit(TEXT[lang]["no_tty"])
    from .config import ConfigError
    from .zabbix_api import ZabbixError
    try:
        return Wizard(lang, args.config).run()
    except (KeyboardInterrupt, EOFError):
        raise SystemExit("\n") from None
    except (ZabbixError, ConfigError) as exc:
        raise SystemExit(f"\n! {exc}") from None

"""Interactive Operations Menu (TUI) for zabbix-autodiscovery.

Provides an intuitive console control center for day-to-day operations:
- Network scanning and CSV inventory generation
- Zabbix connectivity validation & health check
- Environment audit (unsupported items, missing groups, duplicates)
- Onboarding / Apply (with safe dry-run default)
- Topology maps (native Zabbix maps; zoom/pan via the Zabbix UI module)
- Native NOC Dashboards synchronization
- Multi-platform inventory export (Ansible, NetBox, JSON)
- Web & SSL certificate monitoring
"""
import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from . import __version__
from .config import ConfigError, load_config

BANNER = r"""
  ______     _     _     _             _   _ _____   _____
 |___  /    | |   | |   (_)           | \ | |  _  | /  __ \
    / / __ _| |__ | |__  ___  __      |  \| | | | | | /  \/
   / / / _` | '_ \| '_ \| \ \/ / ____ | . ` | | | | | |
 ./ /_| (_| | |_) | |_) | |>  < |____| | |\ \ \_/ / | \__/\
 \_____/\__,_|_.__/|_.__/|_/_/\_\     \_| \_/\___/   \____/
          A U T O - D I S C O V E R Y   M E N U
"""


def clear_screen():
    # Keep output visible across scrolls, print clean separator
    pass


def prompt_choice(prompt, default="1"):
    try:
        val = input(f"{prompt} [{default}]: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return "0"


def prompt_string(prompt, default=""):
    try:
        hint = f" [{default}]" if default else ""
        val = input(f"{prompt}{hint}: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return default


def prompt_yes_no(prompt, default=True):
    try:
        hint = " [S/n]" if default else " [s/N]"
        val = input(f"{prompt}{hint}: ").strip().lower()
        if not val:
            return default
        return val.startswith(("s", "y", "sim", "yes"))
    except (KeyboardInterrupt, EOFError):
        return default


def pause():
    try:
        input("\n[Pressione ENTER para voltar ao menu principal]")
    except (KeyboardInterrupt, EOFError):
        pass


def show_header(cfg, cfg_path):
    print("=" * 72)
    print(BANNER.strip())
    print("=" * 72)
    if cfg:
        z_url = cfg.get("zabbix", {}).get("url", "N/A")
        nets = cfg.get("scan", {}).get("networks", [])
        net_str = f"{len(nets)} redes configuradas" if len(nets) > 1 else (nets[0] if nets else "nenhuma")
        print(f" Conexão : {z_url}")
        print(f" Redes   : {net_str}")
        print(f" Config  : {cfg_path}  (v{__version__})")
    else:
        print(f" Config  : {cfg_path} (não carregado ou inexistente)")
    print("=" * 72)


def run_scan(cfg, args_base):
    from .cli import cmd_scan
    print("\n--- [1] Varredura de Rede (Scan) ---")
    nets = cfg.get("scan", {}).get("networks", [])
    print(f"Redes no config.yaml: {', '.join(nets) if nets else 'nenhuma'}")

    mode = prompt_choice(
        "Tipo de Varredura (1: Inventário Completo [Ping+SNMP+TCP+rDNS+Web], 2: Rápido ICMP [IcmpSendEcho - apenas IPs ativos])",
        "1"
    )
    is_ping_only = (mode == "2")

    choice = prompt_choice("Escanear (1: Todas as redes do config, 2: Rede específica, 3: Filial específica)", "1")
    net_val = None
    site_val = None
    if choice == "2":
        net_val = prompt_string("Digite o CIDR da rede (ex: 192.168.0.0/24)")
        if not net_val:
            print("Operação cancelada.")
            return
    elif choice == "3":
        site_val = prompt_string("Digite o nome da filial")
        if not site_val:
            print("Operação cancelada.")
            return

    default_out = "ips_ativos.txt" if is_ping_only else "inventory.csv"
    out_file = prompt_string("Arquivo de saída", default_out)
    args = argparse.Namespace(config=args_base.config, network=net_val, site=site_val, output=out_file, delimiter=";", ping_only=is_ping_only)
    try:
        cmd_scan(cfg, args)
    except Exception as exc:
        print(f"\nErro durante scan: {exc}")


def run_check(cfg, args_base):
    from .cli import cmd_check
    print("\n--- [2] Diagnóstico e Teste de Conexão (Check) ---")
    try:
        cmd_check(cfg, args_base)
    except Exception as exc:
        print(f"\nErro no check: {exc}")


def run_audit(cfg, args_base):
    from .cli import cmd_audit
    print("\n--- [3] Auditoria do Zabbix (Audit) ---")
    try:
        cmd_audit(cfg, args_base)
    except Exception as exc:
        print(f"\nErro na auditoria: {exc}")


def run_apply(cfg, args_base):
    from .cli import cmd_apply
    print("\n--- [4] Cadastrar Hosts no Zabbix (Apply) ---")
    in_file = prompt_string("Arquivo CSV de inventário", "inventory.csv")
    if not Path(in_file).exists():
        print(f"Aviso: Arquivo '{in_file}' não encontrado. Execute o Scan primeiro.")
        return

    mode = prompt_choice("Modo de execução (1: Simulação / Dry-Run [seguro], 2: Aplicar no Zabbix em produção)", "1")
    dry_run = (mode != "2")
    allow_dup = prompt_yes_no("Permitir nomes duplicados adicionando sufixo de IP?", default=False)

    args = argparse.Namespace(config=args_base.config, input=in_file, dry_run=dry_run, allow_duplicate_names=allow_dup)
    try:
        cmd_apply(cfg, args)
    except Exception as exc:
        print(f"\nErro no apply: {exc}")


def run_maps(cfg, args_base):
    from .cli import cmd_maps
    print("\n--- [5] Reconstruir Mapas de Topologia (Maps) ---")
    mode = prompt_choice("Modo (1: Reconstruir mapas limpos no Zabbix, 2: Simulação / Dry-run)", "1")
    dry_run = (mode == "2")
    args = argparse.Namespace(config=args_base.config, rebuild=True, dry_run=dry_run)
    try:
        cmd_maps(cfg, args)
    except Exception as exc:
        print(f"\nErro na geração de mapas: {exc}")


def run_dashboards(cfg, args_base):
    from .cli import cmd_setup
    print("\n--- [6] Atualizar Dashboards NOC no Zabbix ---")
    confirm = prompt_yes_no("Reconstruir e sincronizar todos os dashboards no Zabbix com novos hosts?", default=True)
    if not confirm:
        return
    args = argparse.Namespace(config=args_base.config, native_discovery=False, force=False,
                              no_dashboards=False, rebuild_dashboards=True)
    try:
        cmd_setup(cfg, args)
    except Exception as exc:
        print(f"\nErro ao atualizar dashboards: {exc}")


def run_organize(cfg, args_base):
    from .cli import cmd_organize
    print("\n--- [7] Organizar Grupos e Tags de Hosts Antigos ---")
    mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar alterações no Zabbix)", "1")
    dry_run = (mode != "2")
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run, remove_groups="")
    try:
        cmd_organize(cfg, args)
    except Exception as exc:
        print(f"\nErro ao organizar hosts: {exc}")


def run_export(cfg, args_base):
    from .cli import cmd_export
    print("\n--- [8] Exportar Inventário (Ansible / NetBox / JSON) ---")
    fmt_choice = prompt_choice("Formato (1: Ansible YAML, 2: NetBox CSV, 3: JSON puro)", "1")
    fmt_map = {"1": "ansible", "2": "netbox", "3": "json"}
    fmt = fmt_map.get(fmt_choice, "ansible")

    src_choice = prompt_choice("Origem dos dados (1: Hosts ativos do Zabbix, 2: Arquivo CSV de scan)", "1")
    from_zabbix = (src_choice != "2")
    in_file = "inventory.csv"
    if not from_zabbix:
        in_file = prompt_string("Arquivo CSV de inventário", "inventory.csv")

    default_ext = "yml" if fmt == "ansible" else ("csv" if fmt == "netbox" else "json")
    default_out = f"export_{fmt}.{default_ext}"
    out_file = prompt_string(f"Salvar em arquivo (Enter para '{default_out}', ou '-' para tela)", default_out)
    if out_file == "-":
        out_file = None

    args = argparse.Namespace(config=args_base.config, format=fmt, input=in_file,
                              output=out_file, from_zabbix=from_zabbix)
    try:
        cmd_export(cfg, args)
    except Exception as exc:
        print(f"\nErro ao exportar: {exc}")


def add_site_to_config(config_path, site):
    """Add a site to web.certificates.sites in config.yaml preserving existing formatting."""
    path = Path(config_path)
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    if re.search(rf'-\s+["\']?{re.escape(site)}["\']?', text):
        return "already_present"
    m = re.search(r'(\bcertificates:\s*\n.*?\bsites:\s*\n)', text, re.DOTALL)
    if not m:
        m = re.search(r'(\bsites:\s*\n)', text)
    if m:
        idx = m.end()
        rest = text[idx:].splitlines()
        indent = "      "
        if rest and rest[0].strip().startswith("-"):
            indent = rest[0][:rest[0].index("-")]
        new_text = text[:idx] + f"{indent}- {site}\n" + text[idx:]
        path.write_text(new_text, encoding="utf-8")
        return "added"
    m_empty = re.search(r'(\bsites:\s*)\[\s*\]', text)
    if m_empty:
        new_text = text[:m_empty.start()] + f"sites:\n      - {site}\n" + text[m_empty.end():]
        path.write_text(new_text, encoding="utf-8")
        return "added"
    if "web:" in text:
        m_web = re.search(r'(\bweb:\s*\n)', text)
        block = f"  certificates:\n    group: Web/Certificados\n    sites:\n      - {site}\n"
        path.write_text(text[:m_web.end()] + block + text[m_web.end():], encoding="utf-8")
        return "added"
    block = f"\nweb:\n  certificates:\n    group: Web/Certificados\n    sites:\n      - {site}\n"
    path.write_text(text.rstrip() + block, encoding="utf-8")
    return "added"


def add_domain_to_config(config_path, domain):
    """Add a domain to web.domains.list in config.yaml preserving existing formatting."""
    path = Path(config_path)
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    if re.search(rf'-\s+["\']?{re.escape(domain)}["\']?', text):
        return "already_present"
    m = re.search(r'(\bdomains:\s*\n.*?\blist:\s*\n)', text, re.DOTALL)
    if not m:
        m = re.search(r'(\blist:\s*\n)', text)
    if m:
        idx = m.end()
        rest = text[idx:].splitlines()
        indent = "      "
        if rest and rest[0].strip().startswith("-"):
            indent = rest[0][:rest[0].index("-")]
        new_text = text[:idx] + f"{indent}- {domain}\n" + text[idx:]
        path.write_text(new_text, encoding="utf-8")
        return "added"
    m_empty = re.search(r'(\blist:\s*)\[\s*\]', text)
    if m_empty:
        new_text = text[:m_empty.start()] + f"list:\n      - {domain}\n" + text[m_empty.end():]
        path.write_text(new_text, encoding="utf-8")
        return "added"
    if "web:" in text:
        m_web = re.search(r'(\bweb:\s*\n)', text)
        block = f"  domains:\n    group: Web/Dominios\n    list:\n      - {domain}\n"
        path.write_text(text[:m_web.end()] + block + text[m_web.end():], encoding="utf-8")
        return "added"
    block = f"\nweb:\n  domains:\n    group: Web/Dominios\n    list:\n      - {domain}\n"
    path.write_text(text.rstrip() + block, encoding="utf-8")
    return "added"


def run_web(cfg, args_base):
    from . import web
    from .cli import cmd_web, connect

    while True:
        try:
            cfg = load_config(args_base.config)
        except Exception:
            pass

        web_cfg = cfg.get("web") or {}
        certs_cfg = web_cfg.get("certificates") or {}
        domains_cfg = web_cfg.get("domains") or {}
        sites = certs_cfg.get("sites") or []
        domains = domains_cfg.get("list") or []

        print("\n" + "=" * 72)
        print("--- [9] Monitoramento Web, Certificados SSL e Domínios ---")
        print("=" * 72)
        print(f"  Certificados SSL configurados: {len(sites)} site(s)")
        print(f"  Domínios (RDAP/WHOIS) configurados: {len(domains)} domínio(s)")
        print("-" * 72)
        print(" [1] 📋 Listar certificados e domínios cadastrados")
        print(" [2] ➕ Cadastrar novo Certificado SSL (URL / Site)")
        print(" [3] ➕ Cadastrar novo Domínio (Expiração RDAP / WHOIS)")
        print(" [4] 🚀 Sincronizar todos no Zabbix (Aplicar / Simular)")
        print(" [5] 📂 Importar certificados descobertos do CSV de inventário")
        print(" [0] ⬅️  Voltar ao menu principal")
        print("=" * 72)

        sub_choice = prompt_choice("Escolha uma opção (0-5)", "1")

        if sub_choice == "0":
            return
        elif sub_choice == "1":
            print("\n-- Certificados SSL Cadastrados no config.yaml --")
            if sites:
                for s in sites:
                    try:
                        h, p = web.parse_site(s)
                        print(f"  * {s:<35} -> Host: {h} (Porta TCP {p})")
                    except Exception:
                        print(f"  * {s}")
            else:
                print("  (nenhum certificado configurado)")

            print(f"\n-- Domínios Cadastrados ({len(domains)}) --")
            if domains:
                for d in domains:
                    print(f"  * {d}")
            else:
                print("  (nenhum domínio configurado)")
            pause()

        elif sub_choice == "2":
            print("\n-- Cadastrar Novo Certificado SSL --")
            raw_site = prompt_string("Digite a URL ou Hostname (ex: https://sistema.empresa.com.br ou portal:8443)")
            if not raw_site:
                print("Operação cancelada.")
                continue
            try:
                hostname, port = web.parse_site(raw_site)
            except ValueError as exc:
                print(f"Erro no formato do site: {exc}")
                pause()
                continue

            print(f"\nSite validado: Host={hostname}, Porta={port}")
            save_cfg = prompt_yes_no(f"Salvar '{raw_site}' no {args_base.config}?", default=True)
            if save_cfg:
                status = add_site_to_config(args_base.config, raw_site)
                if status == "already_present":
                    print(f"  i O site '{raw_site}' já constava no {args_base.config}.")
                elif status == "added":
                    print(f"  + Site salvo no {args_base.config} com sucesso!")

            apply_now = prompt_yes_no("Criar o monitoramento no Zabbix agora?", default=True)
            if apply_now:
                try:
                    cfg_updated = load_config(args_base.config)
                    api = connect(cfg_updated)
                    stats = web.provision(api, cfg_updated, extra_sites=[(hostname, port, "")], dry_run=False)
                    print(f"\nConcluído no Zabbix: {stats}")
                except Exception as exc:
                    print(f"\nErro ao provisionar no Zabbix: {exc}")
            pause()

        elif sub_choice == "3":
            print("\n-- Cadastrar Novo Domínio --")
            raw_domain = prompt_string("Digite o domínio (ex: novodominio.com.br)")
            if not raw_domain:
                print("Operação cancelada.")
                continue
            try:
                clean_d = web.clean_domain(raw_domain)
            except ValueError as exc:
                print(f"Erro no formato do domínio: {exc}")
                pause()
                continue

            print(f"\nDomínio validado: {clean_d}")
            save_cfg = prompt_yes_no(f"Salvar '{clean_d}' no {args_base.config}?", default=True)
            if save_cfg:
                status = add_domain_to_config(args_base.config, clean_d)
                if status == "already_present":
                    print(f"  i O domínio '{clean_d}' já constava no {args_base.config}.")
                elif status == "added":
                    print(f"  + Domínio salvo no {args_base.config} com sucesso!")

            apply_now = prompt_yes_no("Criar o monitoramento no Zabbix agora?", default=True)
            if apply_now:
                try:
                    cfg_updated = load_config(args_base.config)
                    if not save_cfg:
                        w_dom = cfg_updated.setdefault("web", {}).setdefault("domains", {})
                        w_dom.setdefault("list", []).append(clean_d)
                    api = connect(cfg_updated)
                    stats = web.provision(api, cfg_updated, dry_run=False)
                    print(f"\nConcluído no Zabbix: {stats}")
                except Exception as exc:
                    print(f"\nErro ao provisionar no Zabbix: {exc}")
            pause()

        elif sub_choice == "4":
            mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar no Zabbix)", "1")
            dry_run = (mode != "2")
            args = argparse.Namespace(config=args_base.config, dry_run=dry_run, input=None)
            try:
                cmd_web(cfg, args)
            except Exception as exc:
                print(f"\nErro no monitoramento web: {exc}")
            pause()

        elif sub_choice == "5":
            in_file = prompt_string("Arquivo CSV de inventário", "inventory.csv")
            if not Path(in_file).exists():
                print(f"Aviso: Arquivo '{in_file}' não encontrado.")
                pause()
                continue
            mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar no Zabbix)", "1")
            dry_run = (mode != "2")
            args = argparse.Namespace(config=args_base.config, dry_run=dry_run, input=in_file)
            try:
                cmd_web(cfg, args)
            except Exception as exc:
                print(f"\nErro ao importar certificados: {exc}")
            pause()


def run_agent_sync(cfg, args_base):
    from .cli import cmd_agent_sync
    print("\n--- [10] Sincronizar Servidores com Novo Agente ---")
    mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar no Zabbix)", "1")
    dry_run = (mode != "2")
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run)
    try:
        cmd_agent_sync(cfg, args)
    except Exception as exc:
        print(f"\nErro no sync de agentes: {exc}")


def run_wizard(cfg, args_base):
    from .wizard import main as wizard_main
    print("\n--- [11] Assistente Guiado de Implantação (Wizard) ---")
    args = argparse.Namespace(config=args_base.config, lang="pt", force_tty=False)
    try:
        wizard_main(args)
    except Exception as exc:
        print(f"\nErro no assistente: {exc}")


def run_dependencies(cfg, args_base):
    from .cli import cmd_dependencies
    print("\n--- [12] Dependências de Triggers (Root Cause Analysis) ---")
    mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar no Zabbix)", "1")
    dry_run = (mode != "2")
    confirmed = False
    if not dry_run:
        print("Dependências SUPRIMEM alertas dos hosts dependentes quando o pai está em problema.")
        confirmed = prompt_yes_no("Revisou a simulação e confirma a criação no Zabbix?", default=False)
        if not confirmed:
            print("Nada foi alterado.")
            return
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run, yes=confirmed)
    try:
        cmd_dependencies(cfg, args)
    except Exception as exc:
        print(f"\nErro ao vincular dependências: {exc}")


def run_sla(cfg, args_base):
    from .cli import cmd_sla
    print("\n--- [13] Criar Serviços de Negócio & SLA 99.5% ---")
    mode = prompt_choice("Modo (1: Criar no Zabbix, 2: Simulação / Dry-run)", "1")
    dry_run = (mode == "2")
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run)
    try:
        cmd_sla(cfg, args)
    except Exception as exc:
        print(f"\nErro ao criar SLA: {exc}")


def run_clean_unsupported(cfg, args_base):
    from .cli import cmd_clean_unsupported
    print("\n--- [14] Limpar Itens Não Suportados do Zabbix Server ---")
    mode = prompt_choice("Modo (1: Desativar no Zabbix, 2: Simulação / Dry-run)", "1")
    dry_run = (mode == "2")
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run)
    try:
        cmd_clean_unsupported(cfg, args)
    except Exception as exc:
        print(f"\nErro ao limpar itens: {exc}")


def run_grafana(cfg, args_base):
    from . import dashboards, provision
    from .cli import connect

    print("\n" + "=" * 72)
    print("--- [15] Instalação e Integração do Grafana com Zabbix Existente ---")
    print("=" * 72)
    print(" [1] 🚀 Configurar Usuário no Zabbix e Gerar deploy/.env (Docker)")
    print(" [2] 🐧 Gerar Script de Instalação Nativa no Linux (Ubuntu/Debian sem Docker)")
    print(" [3] 📊 Regenerar Arquivos JSON dos 13 Dashboards do Grafana")
    print(" [0] ⬅️  Voltar ao menu principal")
    print("=" * 72)

    sub_choice = prompt_choice("Escolha uma opção (0-3)", "1")
    if sub_choice == "0":
        return

    if sub_choice == "1":
        print("\n-- Configurar Integração Grafana + Zabbix (Docker) --")
        zbx_url = cfg.get("zabbix", {}).get("url", "http://192.168.0.15:8080")
        api_url = zbx_url if zbx_url.endswith(".php") else zbx_url.rstrip("/") + "/api_jsonrpc.php"

        target_url = prompt_string("URL da API do Zabbix", api_url)
        username = prompt_string("Nome do usuário do Grafana no Zabbix", "grafana")
        password = prompt_string("Senha para o usuário do Grafana no Zabbix", "GrafanaZabbix@2026")
        admin_pass = prompt_string("Senha do usuário 'admin' do Grafana UI", "admin@123")

        # 1. Criar / atualizar usuário no Zabbix via API
        print("\nConectando ao Zabbix para configurar permissões de leitura...")
        try:
            api = connect(cfg)
            gcfg = {"grafana_user": {"username": username, "password": password}}
            provision.setup_grafana_user(api, gcfg, log=print)
        except Exception as exc:
            print(f"  ! Aviso ao criar usuário no Zabbix: {exc}")

        # 2. Atualizar deploy/.env
        deploy_dir = Path(args_base.config).resolve().parent / "deploy"
        env_file = deploy_dir / ".env"
        example_file = deploy_dir / ".env.example"

        env_text = ""
        if env_file.exists():
            env_text = env_file.read_text(encoding="utf-8")
        elif example_file.exists():
            env_text = example_file.read_text(encoding="utf-8")

        def _set_env(text, k, v):
            if re.search(rf"(?m)^{k}=.*$", text):
                return re.sub(rf"(?m)^{k}=.*$", f"{k}={v}", text)
            return text.rstrip() + f"\n{k}={v}\n"

        env_text = _set_env(env_text, "ZABBIX_API_URL", target_url)
        env_text = _set_env(env_text, "ZABBIX_GRAFANA_USER", username)
        env_text = _set_env(env_text, "ZABBIX_GRAFANA_PASSWORD", password)
        env_text = _set_env(env_text, "GRAFANA_ADMIN_PASSWORD", admin_pass)
        deploy_dir.mkdir(parents=True, exist_ok=True)
        env_file.write_text(env_text, encoding="utf-8")
        print(f"[+] Arquivo {env_file} atualizado com as credenciais.")

        # 3. Atualizar config.yaml
        cfg_path = Path(args_base.config)
        if cfg_path.exists():
            cfg_text = cfg_path.read_text(encoding="utf-8")
            if "grafana_user:" not in cfg_text:
                block = f"\ngrafana_user:\n  username: {username}\n  password: {password}\n"
                cfg_path.write_text(cfg_text.rstrip() + block, encoding="utf-8")
                print(f"[+] Seção grafana_user adicionada ao {args_base.config}.")

        # 4. Oferecer rodar docker compose se Docker estiver instalado
        has_docker = shutil.which("docker") is not None
        if has_docker:
            prompt_docker = "\nDocker detectado. Deseja iniciar o Grafana agora com 'docker compose'?"
            up_now = prompt_yes_no(prompt_docker, default=True)
            if up_now:
                try:
                    subprocess.run(["docker", "compose", "--profile", "grafana", "up", "-d"],
                                   cwd=str(deploy_dir), check=True)
                    print("\n[+] Grafana iniciado com sucesso na porta 3000!")
                    print("    URL    : http://localhost:3000 (ou pelo IP do servidor)")
                    print(f"    Usuário: admin | Senha: {admin_pass}")
                    print("    Dashboards pré-carregados na pasta 'Zabbix AutoDiscovery'")
                except Exception as exc:
                    print(f"[!] Erro ao iniciar container Docker: {exc}")
        else:
            host_target = target_url.split("/")[2].split(":")[0]
            print("\n" + "=" * 72)
            print("  Configuração concluída! Para subir o Grafana no servidor:")
            print("========================================================================")
            print(f"  1. No servidor ({host_target}):")
            print("     cd deploy && docker compose --profile grafana up -d")
            print(f"  2. Acesse no navegador: http://{host_target}:3000")
            print(f"     Usuário: admin | Senha: {admin_pass}")
            print("========================================================================")
        pause()

    elif sub_choice == "2":
        print("\n-- Instalação Nativa no Linux (Ubuntu / Debian sem Docker) --")
        script_path = Path(args_base.config).resolve().parent / "deploy" / "install-grafana.sh"
        print(f"\nO script automatizado está disponível em: {script_path}")
        print("\nPara executar no servidor Linux via SSH:")
        print("  cd zabbix-autodiscovery")
        print("  chmod +x deploy/install-grafana.sh")
        print("  sudo ./deploy/install-grafana.sh native")
        pause()

    elif sub_choice == "3":
        print("\n-- Regenerar Dashboards do Grafana --")
        out_dir = Path(args_base.config).resolve().parent / "deploy" / "grafana" / "dashboards"
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in out_dir.glob("autodiscovery-*.json"):      # tipos sem hosts não deixam JSON antigo para trás
            old.unlink()
        count = 0
        # Sem hosts no grupo = sem dashboard (só quando o Zabbix responde; offline gera todos)
        from .cli import connect_optional
        for spec in dashboards.specs_to_build(cfg, connect_optional(cfg)):
            path = out_dir / f"autodiscovery-{spec['key']}.json"
            path.write_text(json.dumps(dashboards.grafana_dashboard(spec, cfg, "zabbix"),
                                       ensure_ascii=False, indent=2), encoding="utf-8")
            count += 1
        from .topology import build_topology_dashboard
        topo_path = out_dir / "autodiscovery-topology.json"
        topo_path.write_text(json.dumps(build_topology_dashboard("zabbix"),
                                       ensure_ascii=False, indent=2), encoding="utf-8")
        count += 1
        print(f"[+] {count} dashboards JSON gerados/atualizados em {out_dir}")
        pause()


def interactive_menu(config_path="config.yaml"):
    args_base = argparse.Namespace(config=config_path)

    while True:
        cfg = None
        try:
            cfg = load_config(config_path)
        except ConfigError as exc:
            print(f"\nAviso de configuração: {exc}")
        except FileNotFoundError:
            print(f"\nAviso: {config_path} não encontrado no diretório atual.")

        show_header(cfg, config_path)
        print(" [1]  📡 Varredura de Rede (Scan)         - Descobre equipamentos e gera CSV")
        print(" [2]  🔍 Diagnóstico e Teste (Check)      - Valida conexão, token e templates")
        print(" [3]  📋 Auditoria do Ambiente (Audit)    - Relatório de integridade e erros")
        print(" [4]  🚀 Cadastrar Hosts (Apply)          - Envia hosts para o Zabbix (Simulação/Real)")
        print(" [5]  🗺️  Reconstruir Mapas de Topologia   - Mapas hierárquicos estilizados por filial")
        print(" [6]  📊 Atualizar Dashboards NOC         - Sincroniza métricas e painéis nativos")
        print(" [7]  🏷️  Organizar Grupos e Tags          - Padroniza hosts existentes por tipo/filial")
        print(" [8]  📦 Exportar Inventário              - Gera inventário Ansible, NetBox ou JSON")
        print(" [9]  🔐 Monitoramento Web & SSL          - Monitora certificados SSL e domínios")
        print(" [10] 🔄 Sincronizar Agentes (Sync)       - Atualiza servidores com agente recém-instalado")
        print(" [11] 🧙 Assistente Passo a Passo (Wizard)- Executa o assistente guiado completo")
        print(" [12] 🔗 Dependências de Triggers (NOC)   - Evita tempestade de alertas vinculando topologia")
        print(" [13] 📈 Criar Serviços & SLA 99.5%       - Árvore de serviços e metas de disponibilidade")
        print(" [14] 🧹 Limpar Itens Não Suportados      - Desativa coletores inativos e itens órfãos")
        print(" [15] 📊 Instalar / Configurar Grafana    - Integra Grafana com Zabbix existente (Docker/Nativo)")
        print(" [0]  ❌ Sair")
        print("=" * 72)

        choice = prompt_choice("Escolha uma opção (0-15)", default="1")

        if choice == "0":
            print("\nEncerrando. Até logo!")
            return 0
        elif choice == "1":
            if cfg:
                run_scan(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "2":
            if cfg:
                run_check(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "3":
            if cfg:
                run_audit(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "4":
            if cfg:
                run_apply(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "5":
            if cfg:
                run_maps(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "6":
            if cfg:
                run_dashboards(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "7":
            if cfg:
                run_organize(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "8":
            if cfg:
                run_export(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "9":
            if cfg:
                run_web(cfg, args_base)
                continue
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "10":
            if cfg:
                run_agent_sync(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "11":
            run_wizard(cfg, args_base)
        elif choice == "12":
            if cfg:
                run_dependencies(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "13":
            if cfg:
                run_sla(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "14":
            if cfg:
                run_clean_unsupported(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        elif choice == "15":
            if cfg:
                run_grafana(cfg, args_base)
                continue
            else:
                print("Configure o config.yaml primeiro.")
        else:
            print("Opção inválida.")

        pause()


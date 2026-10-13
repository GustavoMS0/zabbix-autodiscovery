"""Interactive Operations Menu (TUI) for zabbix-autodiscovery.

Provides an intuitive console control center for day-to-day operations:
- Network scanning and CSV inventory generation
- Zabbix connectivity validation & health check
- Environment audit (unsupported items, missing groups, duplicates)
- Onboarding / Apply (with safe dry-run default)
- Topology map generation and hierarchical layout
- Native NOC Dashboards synchronization
- Multi-platform inventory export (Ansible, NetBox, JSON)
- Web & SSL certificate monitoring
"""
import argparse
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

    out_file = prompt_string("Arquivo CSV de saída", "inventory.csv")
    args = argparse.Namespace(config=args_base.config, network=net_val, site=site_val, output=out_file, delimiter=";")
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


def run_web(cfg, args_base):
    from .cli import cmd_web
    print("\n--- [9] Monitoramento Web & Certificados SSL ---")
    mode = prompt_choice("Modo (1: Simulação / Dry-run, 2: Aplicar no Zabbix)", "1")
    dry_run = (mode != "2")
    use_inv = prompt_yes_no("Adicionar certificados descobertos no inventory.csv?", default=False)
    in_file = "inventory.csv" if use_inv else None

    args = argparse.Namespace(config=args_base.config, dry_run=dry_run, input=in_file)
    try:
        cmd_web(cfg, args)
    except Exception as exc:
        print(f"\nErro no monitoramento web: {exc}")


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
    args = argparse.Namespace(config=args_base.config, dry_run=dry_run)
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


def run_interactive_map(cfg, args_base):
    from .cli import cmd_interactive_map
    print("\n--- [15] Mapa Interativo Web (Zoom, Pan, Busca e Status NOC) ---")
    out_file = prompt_string("Arquivo HTML de saída", "topology.html")
    site_val = prompt_string("Filtrar por filial específica (ENTER para todas)", "")
    open_now = prompt_yes_no("Abrir no navegador imediatamente?", default=True)

    args = argparse.Namespace(
        config=args_base.config,
        output=out_file,
        site=site_val if site_val else None,
        serve=False,
        port=8088,
        open=open_now,
    )
    try:
        cmd_interactive_map(cfg, args)
    except Exception as exc:
        print(f"\nErro ao gerar mapa interativo: {exc}")


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
        print(" [15] 🌐 Mapa Interativo Web (NOC)       - Canvas com Zoom, Pan, Busca e Status ao Vivo")
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
                run_interactive_map(cfg, args_base)
            else:
                print("Configure o config.yaml primeiro.")
        else:
            print("Opção inválida.")

        pause()


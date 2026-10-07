"""Configuration loading: YAML + ${VAR} expansion from the environment or a local .env file."""
import ipaddress
import os
import re
from pathlib import Path

import yaml

RULE_KEYS = ("name", "category", "match")
ACTIONS = ("add", "review", "ignore")


class ConfigError(Exception):
    pass


def load_env_file(path):
    """Load KEY=value lines from a .env file without overriding the real environment."""
    path = Path(path)
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def expand_vars(text):
    return re.sub(r"\$\{(\w+)\}", lambda m: os.environ.get(m.group(1), ""), text)


def load_config(path):
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path} (create one with: zabbix-autodiscovery init)")
    load_env_file(path.resolve().parent / ".env")
    cfg = yaml.safe_load(expand_vars(path.read_text(encoding="utf-8"))) or {}
    validate(cfg)
    normalize_sites(cfg)
    return cfg


def validate(cfg):
    for section in ("zabbix", "scan"):
        if section not in cfg:
            raise ConfigError(f"missing '{section}' section")
    if not cfg["scan"].get("networks"):
        raise ConfigError("scan.networks is empty")
    for rule in cfg.get("rules", []):
        for key in RULE_KEYS:
            if key not in rule:
                raise ConfigError(f"rule without '{key}': {rule}")
        if rule.get("action", "review") not in ACTIONS:
            raise ConfigError(f"rule '{rule['name']}': action must be one of {', '.join(ACTIONS)}")


def normalize_sites(cfg):
    """scan.networks accepts plain strings or {network, site, proxy}.

    Sites are stored in cfg["_sites"]; scan.networks keeps only the networks,
    which is what the scanner and the native discovery rule use.
    """
    sites, networks = [], []
    for item in cfg["scan"]["networks"]:
        if isinstance(item, dict):
            if "network" not in item:
                raise ConfigError(f"scan.networks: entry without 'network': {item}")
            sites.append({"network": str(item["network"]), "site": str(item.get("site") or ""),
                          "proxy": item.get("proxy")})
            networks.append(str(item["network"]))
        else:
            networks.append(str(item))
    cfg["scan"]["networks"] = networks
    cfg["_sites"] = sites


def in_network(network, ip):
    """True if ip belongs to a CIDR, an 'a-b' range or a single address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:          # host prototype interfaces carry macros ({#...}) instead of an IP
        return False
    network = str(network).strip()
    if "/" in network:
        return addr in ipaddress.ip_network(network, strict=False)
    if "-" in network:
        start, end = (ipaddress.ip_address(p.strip()) for p in network.split("-", 1))
        return start <= addr <= end
    return addr == ipaddress.ip_address(network)


def in_networks(networks, ip):
    return any(in_network(n, ip) for n in networks)


def site_for(cfg, ip):
    return next((s for s in cfg.get("_sites", []) if in_network(s["network"], ip)), {})


def credentials_by_name(cfg):
    return {c["name"]: c for c in cfg.get("snmp_credentials", [])}


def default_community(cfg):
    for c in cfg.get("snmp_credentials", []):
        if str(c.get("version", "2c")) in ("2", "2c") and c.get("community"):
            return c["community"]
    return None


def category_groups(cfg):
    """category -> host group, from the rules (first rule wins)."""
    groups = {}
    for rule in cfg.get("rules", []):
        if rule.get("group") and rule.get("action") in ("add", "review"):
            groups.setdefault(rule["category"], rule["group"])
    return groups

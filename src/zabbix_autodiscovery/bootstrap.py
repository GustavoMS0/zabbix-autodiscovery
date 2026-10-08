"""New Zabbix (and optional Grafana) on this Linux machine, with the Docker Compose shipped in deploy/.

Used by the wizard when no Zabbix answers locally: installs Docker if asked, writes deploy/.env with random
passwords, starts the containers, waits for the API, creates an API token for Admin and changes the default
Admin password.
"""
import os
import re
import secrets
import shutil
import subprocess
import time
from pathlib import Path

from .zabbix_api import ZabbixAPI, ZabbixError

DOCKER_INSTALL_URL = "https://get.docker.com"
ZABBIX_URL = "http://127.0.0.1:8080"
GRAFANA_PORT = 3000
DEFAULT_ADMIN_PASSWORD = "zabbix"
PASSWORD_KEYS = ("POSTGRES_PASSWORD", "GRAFANA_ADMIN_PASSWORD", "ZABBIX_GRAFANA_PASSWORD")


def new_password():
    return secrets.token_urlsafe(18)


def read_env(text):
    env = {}
    for line in text.splitlines():
        m = re.match(r"\s*([A-Z_][A-Z0-9_]*)=(.*)$", line)
        if m:
            env[m.group(1)] = m.group(2).strip()
    return env


def render_deploy_env(example, tz="UTC", passwords=None):
    """deploy/.env.example -> .env with the time zone and a random value for every password."""
    values = {"TZ": tz, **{k: new_password() for k in PASSWORD_KEYS}, **(passwords or {})}
    for key, value in values.items():
        example = re.sub(rf"(?m)^{key}=.*$", lambda _, k=key, v=value: f"{k}={v}", example)
    return example


def local_timezone():
    if os.environ.get("TZ", "").count("/") == 1:
        return os.environ["TZ"]
    try:
        tz = Path("/etc/timezone").read_text().strip()
        if tz:
            return tz
    except OSError:
        pass
    try:
        target = os.readlink("/etc/localtime")
        if "zoneinfo/" in target:
            return target.split("zoneinfo/", 1)[1]
    except OSError:
        pass
    return "UTC"


def _is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _quiet(run, cmd):
    return run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def docker_prefix(run=subprocess.run, which=shutil.which):
    """None if Docker is not installed, [] if the current user can use it, ["sudo"] if it needs sudo."""
    if not which("docker"):
        return None
    if _quiet(run, ["docker", "info"]):
        return []
    return ["sudo"] if which("sudo") and not _is_root() else []


def has_compose(prefix, run=subprocess.run):
    return _quiet(run, [*prefix, "docker", "compose", "version"])


def install_docker(run=subprocess.run):
    """Docker's official convenience script (Debian, Ubuntu, RHEL, CentOS, Fedora...). Asks for sudo."""
    sudo = [] if _is_root() else ["sudo"]
    run([*sudo, "sh", "-c", f"curl -fsSL {DOCKER_INSTALL_URL} | sh"], check=True)
    run([*sudo, "systemctl", "enable", "--now", "docker"])
    user = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if sudo and user:
        run([*sudo, "usermod", "-aG", "docker", user])        # takes effect at the next login


def compose_up(prefix, deploy_dir, grafana, run=subprocess.run):
    profiles = ["--profile", "zabbix"] + (["--profile", "grafana"] if grafana else [])
    run([*prefix, "docker", "compose", *profiles, "up", "-d"], cwd=str(deploy_dir), check=True)


def wait_for_api(url, probe, timeout=900, interval=5, sleep=time.sleep, clock=time.monotonic, out=print):
    """The first start creates the database schema, which takes a few minutes."""
    deadline = clock() + timeout
    while clock() < deadline:
        version = probe(url)
        if version:
            return version
        out(".", end="", flush=True)
        sleep(interval)
    return None


def first_access(url, admin_password, new_admin_password=None, api_factory=ZabbixAPI):
    """Log in as Admin, create an API token, point the bundled agent host to its container and change
    the Admin password. Returns the token."""
    api = api_factory(url, user="Admin", password=admin_password)
    userid = api.call("user.get", {"filter": {"username": "Admin"}, "output": ["userid"]})[0]["userid"]
    name = f"zabbix-autodiscovery {time.strftime('%Y-%m-%d %H%M%S')}"
    tokenid = api.call("token.create", {"name": name, "userid": userid})["tokenids"][0]
    token = api.call("token.generate", [tokenid])[0]["token"]
    try:    # the default "Zabbix server" host points to 127.0.0.1, but the agent runs in its own container
        for host in api.call("host.get", {"filter": {"host": ["Zabbix server"]}, "output": ["hostid"],
                                          "selectInterfaces": ["interfaceid", "ip", "type"]}):
            for iface in host["interfaces"]:
                if iface["type"] == "1" and iface["ip"] == "127.0.0.1":
                    api.call("hostinterface.update", {"interfaceid": iface["interfaceid"], "useip": 0,
                                                      "dns": "zabbix-agent"})
    except ZabbixError:
        pass
    if new_admin_password and new_admin_password != admin_password:
        api.call("user.update", {"userid": userid, "current_passwd": admin_password,
                                 "passwd": new_admin_password})
    return token

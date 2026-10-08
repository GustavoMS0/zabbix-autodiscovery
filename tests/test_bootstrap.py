import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from zabbix_autodiscovery import bootstrap, wizard
from zabbix_autodiscovery.wizard import Wizard
from zabbix_autodiscovery.zabbix_api import ZabbixError

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def scripted(*answers):
    queue = list(answers)
    return lambda prompt="": queue.pop(0)


def quiet(*a, **k):
    pass


def test_render_deploy_env_replaces_every_password():
    example = (DEPLOY / ".env.example").read_text("utf-8")
    env = bootstrap.read_env(bootstrap.render_deploy_env(example, tz="America/Sao_Paulo"))
    assert env["TZ"] == "America/Sao_Paulo"
    passwords = [env[k] for k in bootstrap.PASSWORD_KEYS]
    assert "change-me" not in passwords and len(set(passwords)) == 3 and all(len(p) >= 20 for p in passwords)
    assert env["ZABBIX_TAG"] == bootstrap.read_env(example)["ZABBIX_TAG"]
    assert env["ZABBIX_API_URL"] == "http://zabbix-web:8080/api_jsonrpc.php"


def test_docker_prefix():
    ok = lambda cmd, **k: SimpleNamespace(returncode=0)      # noqa: E731
    fail = lambda cmd, **k: SimpleNamespace(returncode=1)    # noqa: E731
    assert bootstrap.docker_prefix(run=ok, which=lambda name: None) is None
    assert bootstrap.docker_prefix(run=ok, which=lambda name: "/usr/bin/" + name) == []
    if not bootstrap._is_root():
        assert bootstrap.docker_prefix(run=fail, which=lambda name: "/usr/bin/" + name) == ["sudo"]


def test_compose_up_profiles(tmp_path):
    calls = []
    bootstrap.compose_up(["sudo"], tmp_path, grafana=True, run=lambda cmd, **k: calls.append((cmd, k)))
    cmd, kwargs = calls[0]
    assert cmd == ["sudo", "docker", "compose", "--profile", "zabbix", "--profile", "grafana", "up", "-d"]
    assert kwargs == {"cwd": str(tmp_path), "check": True}


def test_wait_for_api():
    answers = iter([None, None, "8.0.0"])
    now = [0]
    sleep = lambda s: now.__setitem__(0, now[0] + s)          # noqa: E731
    assert bootstrap.wait_for_api("u", lambda u: next(answers), sleep=sleep, clock=lambda: now[0], out=quiet) == "8.0.0"
    assert bootstrap.wait_for_api("u", lambda u: None, timeout=20, sleep=sleep, clock=lambda: now[0], out=quiet) is None


class FakeZabbix:
    def __init__(self, url, user=None, password=None, token=None):
        if password not in (None, "right"):
            raise ZabbixError("user.login: Incorrect user name or password")
        self.calls = []
        FakeZabbix.last = self

    def call(self, method, params, auth=True):
        self.calls.append((method, params))
        return {
            "user.get": [{"userid": "1"}],
            "token.create": {"tokenids": ["7"]},
            "token.generate": [{"tokenid": "7", "token": "abc123"}],
            "host.get": [{"hostid": "10084", "interfaces": [{"interfaceid": "1", "ip": "127.0.0.1", "type": "1"}]}],
        }.get(method, {})


def test_first_access_creates_token_then_changes_password():
    assert bootstrap.first_access("u", "right", "new-pass", api_factory=FakeZabbix) == "abc123"
    methods = [m for m, _ in FakeZabbix.last.calls]
    assert methods == ["user.get", "token.create", "token.generate", "host.get", "hostinterface.update", "user.update"]
    assert FakeZabbix.last.calls[4][1] == {"interfaceid": "1", "useip": 0, "dns": "zabbix-agent"}
    assert FakeZabbix.last.calls[5][1] == {"userid": "1", "current_passwd": "right", "passwd": "new-pass"}
    with pytest.raises(ZabbixError):
        bootstrap.first_access("u", "wrong", "x", api_factory=FakeZabbix)


@pytest.fixture
def project(tmp_path, monkeypatch):
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "docker-compose.yml").write_text("services: {}\n")
    (deploy / ".env.example").write_text((DEPLOY / ".env.example").read_text("utf-8"))
    calls = []
    monkeypatch.setattr(bootstrap, "docker_prefix", lambda: [])
    monkeypatch.setattr(bootstrap, "has_compose", lambda prefix: True)
    monkeypatch.setattr(bootstrap, "compose_up", lambda prefix, d, grafana: calls.append(("up", grafana)))
    monkeypatch.setattr(bootstrap, "wait_for_api", lambda url, probe, out: "8.0.0")
    monkeypatch.setattr(bootstrap, "local_timezone", lambda: "UTC")
    monkeypatch.setattr("zabbix_autodiscovery.zabbix_api.ZabbixAPI", lambda url, token: ("api", token))
    return tmp_path, calls


def test_install_zabbix_happy_path(project, monkeypatch):
    tmp_path, calls = project
    seen = {}
    monkeypatch.setattr(bootstrap, "first_access", lambda url, cur, new: seen.update(cur=cur, new=new) or "tok")
    lines = []
    w = Wizard("en", tmp_path / "config.yaml", ask=scripted("y"), secret=scripted(""),
               out=lambda *a, **k: lines.append(a))
    result = w.install_zabbix()
    env = bootstrap.read_env((tmp_path / "deploy" / ".env").read_text())
    assert calls == [("up", True)]
    assert seen["cur"] == "zabbix" and len(seen["new"]) >= 20
    assert result["token"] == "tok" and result["api"] == ("api", "tok") and result["grafana"] is True
    assert result["grafana_password"] == env["ZABBIX_GRAFANA_PASSWORD"] != "change-me"
    assert any(seen["new"] in str(a) for a in lines)              # generated Admin password is shown once


def test_install_zabbix_asks_current_admin_password_and_can_give_up(project, monkeypatch):
    tmp_path, _ = project
    tried = []

    def first_access(url, cur, new):
        tried.append(cur)
        raise ZabbixError("Incorrect user name or password")
    monkeypatch.setattr(bootstrap, "first_access", first_access)
    w = Wizard("en", tmp_path / "config.yaml", ask=scripted(""),
               secret=scripted("mypass1", "mypass1", "old", ""), out=quiet)
    assert w.install_zabbix() is None
    assert tried == ["zabbix", "old"]


def test_install_zabbix_docker_missing_and_declined(project, monkeypatch):
    tmp_path, calls = project
    monkeypatch.setattr(bootstrap, "docker_prefix", lambda: None)
    monkeypatch.setattr(bootstrap, "install_docker", lambda: pytest.fail("must not install"))
    w = Wizard("en", tmp_path / "config.yaml", ask=scripted(""), out=quiet)
    assert w.install_zabbix() is None and calls == []


def test_install_zabbix_command_failure_falls_back(project, monkeypatch):
    tmp_path, _ = project

    def boom(prefix, d, grafana):
        raise subprocess.CalledProcessError(1, ["docker", "compose", "up"])
    monkeypatch.setattr(bootstrap, "compose_up", boom)
    w = Wizard("en", tmp_path / "config.yaml", ask=scripted(""), out=quiet)
    assert w.install_zabbix() is None


def test_offer_install_only_on_linux_without_local_zabbix(tmp_path, monkeypatch):
    w = Wizard("en", tmp_path / "config.yaml", ask=scripted("y", "y"), out=quiet)
    monkeypatch.setattr(Wizard, "_probe", staticmethod(lambda url: None))
    monkeypatch.setattr(wizard.sys, "platform", "win32")
    assert w.offer_install() is False
    monkeypatch.setattr(wizard.sys, "platform", "linux")
    assert w.offer_install() is True
    monkeypatch.setattr(Wizard, "_probe", staticmethod(lambda url: "8.0.0"))
    assert w.offer_install() is False

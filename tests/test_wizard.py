from importlib import resources

import yaml

from zabbix_autodiscovery import cli, organize, provision, wizard
from zabbix_autodiscovery.config import load_config
from zabbix_autodiscovery.wizard import Wizard, render_config, render_env, suggest_networks, valid_target

EXAMPLE = resources.files("zabbix_autodiscovery").joinpath("data/config.example.yaml").read_text("utf-8")


def scripted(*answers):
    queue = list(answers)
    return lambda prompt="": queue.pop(0)


class FakeAPI:
    def __init__(self, ips=(), hosts=0):
        self.ips, self.hosts = list(ips), hosts

    def call(self, method, params=None, auth=True):
        if method == "hostinterface.get":
            return [{"ip": ip} for ip in self.ips]
        if method == "host.get":
            return str(self.hosts)
        raise AssertionError(f"unexpected call {method}")


def test_suggest_networks_counts_private_ipv4_only():
    ips = ["10.1.2.3", "10.1.2.9", "192.168.5.1", "8.8.8.8", "127.0.0.1", "fe80::1", "", "bogus"]
    assert suggest_networks(ips) == [("10.1.2.0/24", 2), ("192.168.5.0/24", 1)]
    assert suggest_networks(ips, minimum=2) == [("10.1.2.0/24", 2)]


def test_valid_target():
    for ok in ["10.0.0.0/24", "10.0.0.5", "10.0.0.1-10.0.0.9", " 192.168.1.0/25 "]:
        assert valid_target(ok)
    for bad in ["", "abc", "10.0.0.9-10.0.0.1", "10.0.0.300", "10.0.0.1-fe80::1"]:
        assert not valid_target(bad)


def test_render_config_fills_answers_and_stays_valid_yaml():
    text = render_config(EXAMPLE, "http://zbx.example:8080", [("10.0.0.0/24", "HQ"), ("10.0.1.0/24", "")],
                         exclude=["10.0.0.100-10.0.0.199"], grafana=False)
    cfg = yaml.safe_load(text)
    assert cfg["zabbix"]["url"] == "http://zbx.example:8080"
    assert cfg["scan"]["networks"] == [{"network": "10.0.0.0/24", "site": "HQ"}, "10.0.1.0/24"]
    assert cfg["scan"]["exclude"] == ["10.0.0.100-10.0.0.199"]
    assert "grafana_user" not in cfg
    assert cfg["rules"] == yaml.safe_load(EXAMPLE)["rules"]          # rules and comments are kept
    assert "#" in text


def test_render_config_empty_exclude_grafana_and_portuguese_groups():
    cfg = yaml.safe_load(render_config(EXAMPLE, "http://z", [("10.0.0.0/24", "Matriz")], pt_groups=True))
    assert cfg["scan"]["exclude"] == []
    assert "grafana_user" in cfg
    assert cfg["site_group"] == "Filiais/{site}"
    groups = {r.get("group") for r in cfg["rules"]}
    assert "Rede/Switches" in groups and "Network/Switches" not in groups


def test_render_env():
    env = render_env("tok", "comm")
    assert "ZABBIX_TOKEN=tok\n" in env and "SNMP_COMMUNITY=comm\n" in env and "GRAFANA" not in env
    assert "ZABBIX_GRAFANA_PASSWORD=pw\n" in render_env("tok", "comm", "grafana", "pw")


def test_yes_defaults_and_languages(tmp_path):
    w = Wizard("pt", tmp_path / "c.yaml", ask=scripted("", "", "s", "n", "yes"), out=lambda *a: None)
    assert w.yes("?") is False                   # changes default to "no"
    assert w.yes("?", default=True) is True
    assert w.yes("?") is True
    assert w.yes("?", default=True) is False
    assert w.yes("?") is True                    # English answers work in Portuguese too


def test_networks_uses_suggestions_sites_and_exclusions(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "local_ips", lambda: ["10.9.9.9"])
    api = FakeAPI(ips=["10.0.0.1", "10.0.0.2", ""], hosts=20)
    w = Wizard("en", tmp_path / "c.yaml", ask=scripted("", "HQ", "Branch 1", "10.0.0.200-10.0.0.250, junk"),
               out=lambda *a: None)
    networks, exclude, existing = w.networks(api)
    assert networks == [("10.0.0.0/24", "HQ"), ("10.9.9.0/24", "Branch-1")]
    assert exclude == ["10.0.0.200-10.0.0.250"]
    assert existing is True


def test_networks_typed_manually(tmp_path, monkeypatch):
    monkeypatch.setattr(wizard, "local_ips", lambda: [])
    w = Wizard("en", tmp_path / "c.yaml", ask=scripted("bad", "172.16.0.0/24", "", "", ""), out=lambda *a: None)
    networks, exclude, existing = w.networks(FakeAPI(hosts=0))
    assert networks == [("172.16.0.0/24", "")] and exclude == [] and existing is False


def test_run_writes_config_and_env(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    seen = {}
    monkeypatch.setattr(Wizard, "offer_install", lambda self: False)      # would ask on a Linux runner
    monkeypatch.setattr(Wizard, "connect", lambda self: ("http://zbx.example", "secret-token", FakeAPI()))
    monkeypatch.setattr(Wizard, "networks", lambda self, api: ([("10.0.0.0/24", "HQ")], [], False))
    monkeypatch.setattr(cli, "connect", lambda cfg: "api")
    monkeypatch.setattr(Wizard, "operate", lambda self, c, cfg, api, existing: seen.update(cfg=cfg) or 0)
    w = Wizard("en", config, ask=scripted("mycomm", ""), secret=scripted(), out=lambda *a: None)
    assert w.run() == 0
    assert (tmp_path / ".env").read_text("utf-8").count("secret-token") == 1
    assert "secret-token" not in config.read_text("utf-8")
    cfg = load_config(config)
    assert cfg["zabbix"]["url"] == "http://zbx.example"
    assert "grafana_user" not in cfg
    assert seen["cfg"]["_sites"][0]["site"] == "HQ"


def test_operate_declining_changes_writes_nothing(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    calls = []
    record = lambda name: lambda *a, **k: calls.append((name, a[-1] if a else None, k))  # noqa: E731
    for name in ["cmd_check", "cmd_scan", "cmd_apply", "cmd_update_templates", "cmd_services", "cmd_maps"]:
        monkeypatch.setattr(cli, name, record(name))
    monkeypatch.setattr(cli, "read_inventory", lambda path: [{"action": "add"}, {"action": "review"}])
    monkeypatch.setattr(provision, "setup", record("setup"))
    monkeypatch.setattr(provision, "setup_zabbix_dashboards", record("dashboards"))
    monkeypatch.setattr(organize, "audit", record("audit"))
    monkeypatch.setattr(organize, "organize", record("organize"))
    # setup? no | scan? yes | edit pause | apply? no | organize? no | addons? no | services? no | dashboards? no
    answers = scripted("", "", "", "", "", "", "", "")
    w = Wizard("en", config, ask=answers, out=lambda *a: None)
    assert w.operate(cli, {"_sites": []}, "api", existing=True) == 0
    names = [c[0] for c in calls]
    assert names == ["cmd_check", "cmd_scan", "cmd_apply", "audit", "organize"]
    assert calls[2][1].dry_run is True                     # only the dry-run apply
    assert calls[4][2] == {"dry_run": True}                # only the organize preview

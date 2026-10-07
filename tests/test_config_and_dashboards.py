import json

import pytest

from zabbix_autodiscovery import dashboards, provision
from zabbix_autodiscovery.cli import build_parser
from zabbix_autodiscovery.config import ConfigError, category_groups, in_network, load_config, site_for


def test_sites_are_normalized(example_config):
    assert example_config["scan"]["networks"] == ["192.168.0.0/24", "192.168.10.0/24", "192.168.20.0/24"]
    assert site_for(example_config, "192.168.10.9") == {
        "network": "192.168.10.0/24", "site": "Branch-01", "proxy": "proxy-branch-01"}


def test_env_file_is_loaded(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTODISCOVERY_TEST_TOKEN", raising=False)
    (tmp_path / ".env").write_text("AUTODISCOVERY_TEST_TOKEN=abc\n")
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z, token: '${AUTODISCOVERY_TEST_TOKEN}'}\nscan: {networks: [10.0.0.0/30]}\n")
    assert load_config(tmp_path / "config.yaml")["zabbix"]["token"] == "abc"


def test_invalid_action_is_rejected(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "zabbix: {url: http://z}\nscan: {networks: [10.0.0.0/30]}\n"
        "rules: [{name: r, category: c, match: {snmp: true}, action: maybe}]\n")
    with pytest.raises(ConfigError):
        load_config(tmp_path / "config.yaml")


def test_in_network():
    assert in_network("10.0.0.0/24", "10.0.0.7")
    assert in_network("10.0.1.1-10.0.1.9", "10.0.1.5")
    assert not in_network("10.0.1.1-10.0.1.9", "10.0.0.7")
    assert not in_network("10.0.0.0/24", "{#MACRO}")


def test_zabbix_iprange():
    assert provision.zabbix_iprange("192.168.0.100-192.168.0.199") == "192.168.0.100-199"
    with pytest.raises(ValueError):
        provision.zabbix_iprange("10.0.0.1-10.0.1.1")


def test_resolve_templates():
    ids, missing = provision.resolve_templates("A|B,C,D", {"B": "2", "C": "3"})
    assert ids == ["2", "3"] and missing == ["D"]


def test_grafana_dashboards_follow_config_groups(example_config):
    group = category_groups(example_config)["switch"]
    spec = next(s for s in dashboards.SPECS if s["key"] == "switches")
    dash = dashboards.grafana_dashboard(spec, example_config)
    assert dash["uid"] == "autodiscovery-switches"
    assert group.replace("/", "\\/") in dash["templating"]["list"][1]["allValue"]
    panels_text = json.dumps(dash["panels"])
    assert "${datasource}" in panels_text and '"uid": "zabbix"' not in panels_text
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
    assert all(p["gridPos"]["x"] + p["gridPos"]["w"] <= 24 for p in dash["panels"])


@pytest.mark.parametrize("version, width", [((8, 0), 72), ((6, 4), 24)])
def test_zabbix_widgets_fit_the_grid(version, width):
    for spec in dashboards.SPECS:
        widgets = dashboards.zabbix_widgets(spec, ["1", "2"], version)
        assert widgets and widgets[0]["type"] == "problems"
        assert all(w["x"] + w["width"] <= width for w in widgets)
        if version < (7, 0):
            assert all(w["type"] != "honeycomb" for w in widgets)


def test_init_writes_config_and_env(tmp_path, monkeypatch):
    from zabbix_autodiscovery.cli import cmd_init

    monkeypatch.chdir(tmp_path)
    cmd_init(build_parser().parse_args(["init"]))
    assert (tmp_path / "config.yaml").exists() and (tmp_path / ".env").exists()
    with pytest.raises(SystemExit):
        cmd_init(build_parser().parse_args(["init"]))


def test_cmd_diff(tmp_path, capsys):
    from zabbix_autodiscovery.cli import cmd_diff

    old_csv = tmp_path / "old.csv"
    new_csv = tmp_path / "new.csv"

    old_csv.write_text("ip;category;hostname;vendor;ports;sysname;rule\n"
                       "192.168.0.1;switch;SW01;Cisco;22,80;SW01;cisco\n"
                       "192.168.0.2;printer;PRN01;HP;9100;PRN01;printer\n", encoding="utf-8")
    new_csv.write_text("ip;category;hostname;vendor;ports;sysname;rule\n"
                       "192.168.0.1;switch;SW01;Cisco;22,80,443;SW01;cisco\n"
                       "192.168.0.3;firewall;FW01;Fortinet;443;FW01;fortigate\n", encoding="utf-8")

    class Args:
        old_file = str(old_csv)
        new_file = str(new_csv)

    cmd_diff(None, Args())
    captured = capsys.readouterr().out
    assert "New devices:          1" in captured
    assert "Removed devices:      1" in captured
    assert "Changed devices:      1" in captured
    assert "192.168.0.3" in captured
    assert "192.168.0.2" in captured
    assert "ports: '22,80' -> '22,80,443'" in captured


def test_zabbix_api_retry(monkeypatch):
    import requests

    from zabbix_autodiscovery.zabbix_api import ZabbixAPI

    attempts = 0

    class DummyResponse:
        def __init__(self, status_code, body):
            self.status_code = status_code
            self._body = body

        def json(self):
            return self._body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(f"{self.status_code}")

    def fake_post(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return DummyResponse(502, {})
        return DummyResponse(200, {"result": "7.0.0"})

    monkeypatch.setattr(requests.Session, "post", fake_post)
    monkeypatch.setattr("time.sleep", lambda _: None)
    api = ZabbixAPI("http://dummy", token="test")
    assert api.version_str == "7.0.0"
    assert attempts == 2


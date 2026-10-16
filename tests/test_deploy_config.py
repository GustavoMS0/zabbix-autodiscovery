"""Static checks on the deploy/ files (Grafana provisioning, installer, compose)."""

from pathlib import Path

import yaml

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def test_datasource_trends_disabled():
    # plugin 6.9.1 + Zabbix 8.0: trend.get rejects "sortfield", so trends must stay off
    doc = yaml.safe_load((DEPLOY / "grafana/provisioning/datasources/zabbix.yml").read_text(encoding="utf-8"))
    assert doc["datasources"][0]["jsonData"]["trends"] is False


def test_installer_native_datasource_trends_disabled_and_cleans_old_dashboards():
    script = (DEPLOY / "install-grafana.sh").read_text(encoding="utf-8")
    assert "trends: true" not in script
    assert "trends: false" in script
    # stale autodiscovery-*.json must be removed before copying the new ones
    rm = script.index("rm -f /var/lib/grafana/dashboards/autodiscovery-*.json")
    cp = script.index('cp -r "$SCRIPT_DIR/grafana/dashboards/"')
    assert rm < cp


def test_compose_zabbix_web_memory_limit():
    doc = yaml.safe_load((DEPLOY / "docker-compose.yml").read_text(encoding="utf-8"))
    web = doc["services"]["zabbix-web"]
    assert web["image"].startswith("zabbix/zabbix-web-")
    assert web["environment"]["ZBX_MEMORYLIMIT"] == "512M"

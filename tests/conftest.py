from importlib import resources
from pathlib import Path

import pytest

from zabbix_autodiscovery.config import load_config


@pytest.fixture
def example_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SNMP_COMMUNITY", "secret-community")
    monkeypatch.setenv("ZABBIX_TOKEN", "x")
    src = resources.files("zabbix_autodiscovery").joinpath("data/config.example.yaml")
    path = Path(tmp_path) / "config.yaml"
    path.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return load_config(path)

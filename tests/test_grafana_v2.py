import json
import re

import pytest

from zabbix_autodiscovery import cli
from zabbix_autodiscovery.grafana_v2 import CATEGORY_MODULES, build_all
from zabbix_autodiscovery.grafana_v2 import style as S

TV_UIDS = {"autodiscovery-overview-v2", "autodiscovery-topology-canvas-v2", "autodiscovery-topology-echarts-v2"}
# Zabbix query types that read history (metrics / text): those go through history.get or trend.get
HISTORY_QUERY_TYPES = {"0", "1", "2"}


@pytest.fixture
def v2_set(example_config):
    return build_all(example_config, api=None, log=lambda *_: None)


def _walk(panels):
    for p in panels:
        yield p
        yield from _walk(p.get("panels", []))


def test_offline_builds_tv_and_every_category(v2_set):
    uids = {d["uid"] for d in v2_set.values()}
    assert TV_UIDS <= uids
    assert {S.uid(k) for k in CATEGORY_MODULES} <= uids
    assert all(name == f"{d['uid']}.json" for name, d in v2_set.items())


def test_empty_category_is_skipped(example_config):
    firewall_groups = set(S.categories(example_config)[0]["groups"])

    class Api:      # only the firewall group has hosts
        def call(self, method, params):
            if method == "hostgroup.get":
                self.names = params["filter"]["name"]
                return [{"groupid": i, "name": n} for i, n in enumerate(self.names)]
            return 1 if self.names[params["groupids"][0]] in firewall_groups else 0

    uids = {d["uid"] for d in build_all(example_config, api=Api(), log=lambda *_: None).values()}
    assert uids == TV_UIDS | {"autodiscovery-firewalls-v2"}


def test_identity(v2_set):
    for d in v2_set.values():
        assert d["uid"].startswith("autodiscovery-") and d["uid"].endswith("-v2")
        assert d["title"].startswith("AutoDiscovery v2 - ")
        assert {"autodiscovery", "autodiscovery-v2"} <= set(d["tags"])


def test_panel_ids_unique_and_grid_within_24_columns(v2_set):
    for d in v2_set.values():
        panels = list(_walk(d["panels"]))
        ids = [p["id"] for p in panels]
        assert len(ids) == len(set(ids)), d["uid"]
        for p in panels:
            g = p["gridPos"]
            assert g["x"] >= 0 and g["w"] > 0 and g["x"] + g["w"] <= 24, (d["uid"], p.get("title"), g)


def test_tv_dashboards_fit_one_1080p_screen(v2_set):
    for d in v2_set.values():
        if d["uid"] not in TV_UIDS:
            continue
        assert d["refresh"] == "1m" and d["timepicker"].get("hidden")
        bottom = max(p["gridPos"]["y"] + p["gridPos"]["h"] for p in d["panels"])
        assert bottom <= S.TV_HEIGHT, (d["uid"], bottom)
        assert not any(p["type"] == "row" for p in d["panels"]), d["uid"]


def test_history_targets_never_use_trends(v2_set):
    n = 0
    for d in v2_set.values():
        for p in _walk(d["panels"]):
            for t in p.get("targets", []):
                if t.get("datasource", {}).get("type") == S.DS_TYPE and t.get("queryType") in HISTORY_QUERY_TYPES:
                    assert t["options"]["useTrends"] == "false", (d["uid"], p.get("title"))
                    n += 1
    assert n > 50


def test_echarts_code_uses_context_not_global_data(v2_set):
    found = 0
    for d in v2_set.values():
        for p in _walk(d["panels"]):
            if p["type"] == "volkovlabs-echarts-panel":
                code = re.sub(r"//.*", "", p["options"]["getOption"])     # comments may say "data"
                found += 1
                assert "context.panel.data" in code
                # a bare `data` identifier (not a property like .data or context_data) is the v6 global
                assert not re.search(r"(?<![\w.$])data\b(?!\s*:)", code), d["uid"]
    assert found


def test_links_point_to_existing_v2_dashboards(v2_set):
    uids = {d["uid"] for d in v2_set.values()}
    for d in v2_set.values():
        text = json.dumps(d)
        for target in re.findall(r"/d/([\w-]+)", text):
            assert target in uids, (d["uid"], target)
        for link in d["links"]:
            assert link["tags"] == ["autodiscovery-v2"]


def test_cli_v2_writes_own_directory(example_config, tmp_path):
    out = tmp_path / "v2"
    out.mkdir()
    (out / "autodiscovery-stale-v2.json").write_text("{}")
    cli.cmd_grafana_dashboards(example_config, cli.build_parser().parse_args(
        ["grafana-dashboards", "--v2", "-o", str(out), "--include-empty"]))
    names = {p.name for p in out.glob("*.json")}
    assert "autodiscovery-stale-v2.json" not in names
    assert "autodiscovery-overview-v2.json" in names and len(names) == 10
    assert json.loads((out / "autodiscovery-overview-v2.json").read_text(encoding="utf-8"))["uid"] \
        == "autodiscovery-overview-v2"


def test_v3_dashboards_and_cli(example_config, tmp_path):
    from zabbix_autodiscovery.grafana_v3 import build_all as build_all_v3
    v3_set = build_all_v3(example_config, api=None, log=lambda *_: None)
    uids = {d["uid"] for d in v3_set.values()}
    assert "autodiscovery-overview-v3" in uids
    assert "autodiscovery-topology-v3" in uids
    assert "autodiscovery-maps-v3" in uids
    assert len(uids) == 10
    for d in v3_set.values():
        assert d["uid"].startswith("autodiscovery-") and d["uid"].endswith("-v3")
        assert d["title"].startswith("AutoDiscovery v3 - ")
        assert {"autodiscovery", "autodiscovery-v3"} <= set(d["tags"])
        text = json.dumps(d)
        for target in re.findall(r"/d/([\w-]+)", text):
            assert target in uids, (d["uid"], target)

    out = tmp_path / "v3"
    out.mkdir()
    cli.cmd_grafana_dashboards(example_config, cli.build_parser().parse_args(
        ["grafana-dashboards", "--v3", "-o", str(out), "--include-empty"]))
    names = {p.name for p in out.glob("*.json")}
    assert "autodiscovery-topology-v3.json" in names and "autodiscovery-maps-v3.json" in names and len(names) == 10


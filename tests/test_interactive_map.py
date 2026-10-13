from unittest.mock import MagicMock, patch

from zabbix_autodiscovery.interactive_map import (
    build_topology_dataset,
    export_interactive_map,
    generate_interactive_html,
)


def test_build_topology_dataset_and_html(tmp_path):
    api = MagicMock()

    # Mock trigger.get returning 1 active problem on host 101
    def fake_call(method, params):
        if method == "trigger.get":
            return [
                {
                    "triggerid": "1",
                    "description": "High latency",
                    "priority": "4",
                    "hosts": [{"hostid": "101"}],
                }
            ]
        if method == "item.get":
            return []
        return []

    api.call.side_effect = fake_call

    cfg = {
        "_sites": [{"site": "Matriz", "network": "192.168.0.0/24"}],
        "zabbix": {"url": "http://192.168.0.15:8080"},
    }

    sample_hosts = [
        {
            "hostid": "100",
            "name": "FW-01",
            "host": "FW-01",
            "tags": [{"tag": "type", "value": "firewall"}],
            "interfaces": [{"ip": "192.168.0.1"}],
        },
        {
            "hostid": "101",
            "name": "SW-01",
            "host": "SW-01",
            "tags": [{"tag": "type", "value": "switch"}],
            "interfaces": [{"ip": "192.168.0.2"}],
        },
    ]

    with patch("zabbix_autodiscovery.interactive_map.site_hosts_list", return_value=sample_hosts):
        dataset = build_topology_dataset(api, cfg)

        assert dataset["stats"]["total"] == 2
        assert dataset["stats"]["ok"] == 1
        assert dataset["stats"]["disaster"] == 1
        assert len(dataset["nodes"]) == 2
        assert len(dataset["edges"]) == 1

        html = generate_interactive_html(dataset, "http://192.168.0.15:8080")
        assert "AutoDiscovery" in html
        assert "vis-network" in html
        assert "FW-01" in html
        assert "SW-01" in html

        out_file = tmp_path / "test_map.html"
        saved = export_interactive_map(api, cfg, output_file=str(out_file), log=lambda *_: None)
        assert saved.exists()
        assert "SW-01" in saved.read_text(encoding="utf-8")


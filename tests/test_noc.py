from unittest.mock import MagicMock
from zabbix_autodiscovery.noc import clean_unsupported_items, link_trigger_dependencies, primary_down_trigger, setup_noc_services


def test_primary_down_trigger():
    api = MagicMock()
    api.call.return_value = [
        {"triggerid": "10", "description": "High memory usage", "priority": "3"},
        {"triggerid": "20", "description": "Unavailable by ICMP ping", "priority": "4"},
    ]
    assert primary_down_trigger(api, "100") == "20"


def test_setup_noc_services():
    api = MagicMock()
    api.call.side_effect = lambda method, params: [] if "get" in method else {"serviceids": ["1"], "slaids": ["1"]}
    cfg = {"_sites": [{"site": "Matriz", "network": "192.168.0.0/24"}]}
    stats = setup_noc_services(api, cfg, dry_run=False, log=lambda *_: None)
    assert stats["created"] > 0


def test_clean_unsupported_items():
    api = MagicMock()
    # host.get returns Zabbix server
    # item.get returns 2 unsupported items
    def fake_call(method, params):
        if method == "host.get":
            return [{"hostid": "1", "name": "Zabbix server"}]
        if method == "item.get":
            return [{"itemid": "101", "name": "ipmi"}, {"itemid": "102", "name": "vmware"}]
        return {}

    api.call.side_effect = fake_call
    stats = clean_unsupported_items(api, dry_run=False, log=lambda *_: None)
    assert stats["cleaned"] == 2


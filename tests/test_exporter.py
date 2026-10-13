import json
import yaml
from zabbix_autodiscovery import exporter


SAMPLE_ROWS = [
    {
        "visible_name": "FW-BA",
        "hostname": "fw-ba.corp",
        "ip": "192.168.10.1",
        "category": "firewall",
        "site": "BA",
        "vendor": "Fortinet",
        "tags": "type=firewall,site=BA,vendor=Fortinet",
    },
    {
        "visible_name": "SW-CORE",
        "hostname": "sw-core",
        "ip": "192.168.10.2",
        "category": "switch",
        "site": "BA",
        "vendor": "Cisco",
        "tags": "type=switch,site=BA",
    },
    {
        "visible_name": "SRV-APP",
        "hostname": "srv-app",
        "ip": "192.168.10.10",
        "category": "server-windows",
        "site": "BA",
        "vendor": "Microsoft",
        "tags": "type=server-windows,site=BA",
    },
]


def test_devices_from_inventory():
    devices = exporter.devices_from_inventory(SAMPLE_ROWS)
    assert len(devices) == 3
    assert devices[0]["name"] == "FW-BA"
    assert devices[0]["ip"] == "192.168.10.1"
    assert devices[0]["category"] == "firewall"
    assert devices[0]["site"] == "BA"
    assert devices[0]["vendor"] == "Fortinet"
    assert devices[0]["tags"]["vendor"] == "Fortinet"


def test_export_ansible():
    devices = exporter.devices_from_inventory(SAMPLE_ROWS)
    ansible_yaml = exporter.export_ansible(devices)
    inv = yaml.safe_load(ansible_yaml)

    assert "all" in inv
    categories = inv["all"]["children"]["categories"]["children"]
    sites = inv["all"]["children"]["sites"]["children"]

    assert "firewall" in categories
    assert "FW-BA" in categories["firewall"]["hosts"]
    assert categories["firewall"]["hosts"]["FW-BA"]["ansible_host"] == "192.168.10.1"
    assert categories["firewall"]["hosts"]["FW-BA"]["vendor"] == "Fortinet"

    assert "switch" in categories
    assert "SW-CORE" in categories["switch"]["hosts"]

    assert "ba" in sites
    assert "FW-BA" in sites["ba"]["hosts"]


def test_export_netbox():
    devices = exporter.devices_from_inventory(SAMPLE_ROWS)
    netbox_json = exporter.export_netbox(devices)
    data = json.loads(netbox_json)

    assert len(data) == 3
    fw = next(d for d in data if d["name"] == "FW-BA")
    assert fw["primary_ip4"] == "192.168.10.1"
    assert fw["role"]["name"] == "Firewall"
    assert fw["site"]["name"] == "BA"
    assert fw["device_type"]["manufacturer"]["name"] == "Fortinet"


def test_export_json():
    devices = exporter.devices_from_inventory(SAMPLE_ROWS)
    res_json = exporter.export_json(devices)
    data = json.loads(res_json)
    assert len(data) == 3
    assert data[1]["name"] == "SW-CORE"
    assert data[1]["category"] == "switch"

import pytest

from zabbix_autodiscovery.classifier import classify, host_name, oid_matches, vendor
from zabbix_autodiscovery.scanner import Device

WIN = "1.3.6.1.4.1.311.1.1.3.1."
WIN_BUILD_26100 = "Hardware: x86 - Software: Windows Version 6.3 (Build 26100 Multiprocessor Free)"


@pytest.mark.parametrize("dev, category, action", [
    (Device("10.0.0.1", True, sysdescr="Cisco IOS", sysobjectid="1.3.6.1.4.1.9.1.1208"), "switch", "add"),
    (Device("10.0.0.2", True, sysdescr="FortiGate-60F", sysobjectid="1.3.6.1.4.1.12356.101.1.1"), "firewall", "add"),
    (Device("10.0.0.3", True, sysobjectid="1.3.6.1.4.1.11.2.3.9.1", ports=[9100]), "printer", "add"),
    (Device("10.0.0.4", True, sysdescr="U6-Pro 6.6.55", sysobjectid="1.3.6.1.4.1.8072.3.2.10"), "ap", "add"),
    (Device("10.0.0.5", True, ports=[9100]), "printer", "add"),
    (Device("10.0.0.6", True, sysobjectid="1.3.6.1.4.1.674.10892.5"), "server-hardware", "add"),
    (Device("10.0.0.7", True, sysobjectid="1.3.6.1.4.1.26381", sysdescr="SNMP Utility"), "ups", "add"),
    (Device("10.0.0.8", True, sysdescr="RouterOS CCR2004", sysobjectid="1.3.6.1.4.1.14988.1"), "router", "add"),
    # workstations are ignored without any host-name rule
    (Device("10.0.0.20", True, ports=[135, 445, 3389], dns="ANY-NAME-01"), "workstation", "ignore"),
    (Device("10.0.0.21", True, sysdescr=WIN_BUILD_26100, sysobjectid=WIN + "1"), "workstation", "ignore"),
    (Device("10.0.0.22", True, ports=[445, 10050], agent_uname="Windows PC 10.0.22631 Microsoft Windows 11 Pro"),
     "workstation", "ignore"),
    # Windows 11 and Server 2025 share build 26100; Microsoft's sysObjectID tells them apart
    (Device("10.0.0.30", True, sysdescr=WIN_BUILD_26100, sysobjectid=WIN + "2"), "server-windows", "add"),
    (Device("10.0.0.31", True, ports=[445, 10050],
            agent_uname="Windows SRV 10.0.20348 Microsoft Windows Server 2022 Standard x64"), "server-windows", "add"),
    (Device("10.0.0.32", True, ports=[22, 10050], agent_uname="Linux web01 5.15.0 x86_64"), "server-linux", "add"),
    (Device("10.0.0.33", True, ports=[53, 88, 135, 389, 445]), "server-windows", "add"),
    (Device("10.0.0.34", True, ports=[135, 445, 3389, 5985]), "server-windows", "review"),
    (Device("10.0.0.35", True, ports=[22, 80]), "server-linux", "review"),
    (Device("10.0.0.36", True, ports=[445, 10050]), "server-windows", "review"),
    (Device("10.0.0.40", True, sysobjectid="1.3.6.1.4.1.99999.1", sysdescr="something"), "network-generic", "review"),
    (Device("10.0.0.41", True, ports=[80]), "unknown", "ignore"),
])
def test_rules(example_config, dev, category, action):
    row = classify(dev, example_config)
    assert (row["category"], row["action"]) == (category, action)


def test_agent_missing_tag(example_config):
    row = classify(Device("10.0.0.33", True, ports=[88, 389, 445]), example_config)
    assert row["tags"] == "agent=missing"
    assert "AutoDiscovery - Zabbix agent missing" in row["templates"]


def test_site_column(example_config):
    assert classify(Device("192.168.10.5", True, ports=[9100]), example_config)["site"] == "Branch-01"
    assert classify(Device("192.168.20.5", True, ports=[9100]), example_config)["site"] == ""


def test_oid_prefix_is_dot_aware():
    assert oid_matches("1.3.6.1.4.1.9.1.1", "1.3.6.1.4.1.9")
    assert not oid_matches("1.3.6.1.4.1.99.1", "1.3.6.1.4.1.9")


def test_vendor():
    assert vendor("1.3.6.1.4.1.41112.1.6") == "Ubiquiti"
    assert vendor("1.3.6.1.4.1.424242.1") == "enterprise 424242"


@pytest.mark.parametrize("dev, expected", [
    (Device("1.1.1.1", ports=[10050], agent_hostname="srv-app01.corp.local", system_hostname="SRV-APP01"),
     ("srv-app01.corp.local", "SRV-APP01", "agent")),
    (Device("1.1.1.2", ports=[10050], agent_hostname="web01", system_hostname="web01"), ("web01", "", "agent")),
    (Device("1.1.1.3", sysname="SW-CORE-01.corp.local", sysdescr="Cisco IOS"), ("SW-CORE-01", "", "snmp")),
    (Device("1.1.1.4", sysname="AP RECEPÇÃO", sysdescr="U7-Pro"), ("AP RECEPCAO", "", "snmp")),
    (Device("1.1.1.5", sysname="UAP-AC-Pro", sysdescr="UAP-AC-Pro 6.6", dns="ap1.corp.local", dns_confirmed=True),
     ("ap1", "", "dns")),
    (Device("1.1.1.6", sysname="localhost", sysdescr="Linux", dns="old.corp.local"),
     ("x-1.1.1.6", "old (1.1.1.6)", "ip")),
    (Device("1.1.1.7", ports=[445], netbios="DC01"), ("DC01", "", "netbios")),
    (Device("1.1.1.8", dns="NPI123ABC"), ("NPI123ABC", "", "netbios")),
    (Device("1.1.1.9", ports=[9100]), ("x-1.1.1.9", "", "ip")),
])
def test_host_name(dev, expected):
    assert host_name(dev, "x") == expected

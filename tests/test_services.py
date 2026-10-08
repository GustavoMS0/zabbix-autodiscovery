import asyncio
import re

from zabbix_autodiscovery import services
from zabbix_autodiscovery.cli import service_template_names

MYSQL_GREETING = b"\x4a\x00\x00\x00\x0a8.0.36\x00" + b"\x00" * 40
PG_ACCEPTS_SSL = b"S"
REDIS_PONG = b"+PONG\r\n"
SSH_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"


def _with_servers(replies, coro_factory):
    """replies: {fake_service_port: (first_message_or_None, answer_to_request_or_None)}."""
    async def run():
        servers, mapping = [], {}
        for real_port, (greeting, answer) in replies.items():
            async def handler(reader, writer, greeting=greeting, answer=answer):
                if greeting:
                    writer.write(greeting)
                    await writer.drain()
                if answer is not None:
                    await reader.read(64)
                    writer.write(answer)
                    await writer.drain()
                await asyncio.sleep(0.05)
                writer.close()
            srv = await asyncio.start_server(handler, "127.0.0.1", 0)
            servers.append(srv)
            mapping[real_port] = srv.sockets[0].getsockname()[1]
        try:
            return await coro_factory(mapping)
        finally:
            for srv in servers:
                srv.close()
    return asyncio.run(run())


def test_protocol_confirmation(monkeypatch):
    """Probes run against fake servers listening on random ports mapped to the real service ports."""
    replies = {3306: (MYSQL_GREETING, None), 5432: (None, PG_ACCEPTS_SSL),
               6379: (None, REDIS_PONG), 22: (SSH_BANNER, None)}

    async def detect(mapping):
        original = services._exchange

        async def mapped(ip, port, payload, timeout):
            return await original(ip, mapping.get(port, port), payload, timeout)

        monkeypatch.setattr(services, "_exchange", mapped)
        return await services.detect("127.0.0.1", list(replies) + [1433, 3343], 2)

    found = _with_servers(replies, detect)
    assert {"mysql", "postgresql", "redis", "ssh", "mssql", "windows-cluster"} <= set(found)


def test_unrelated_program_on_a_database_port_is_not_reported(monkeypatch):
    replies = {3306: (b"HTTP/1.1 400 Bad Request\r\n\r\n", None), 6379: (None, b"hello\r\n")}

    async def detect(mapping):
        original = services._exchange

        async def mapped(ip, port, payload, timeout):
            return await original(ip, mapping.get(port, port), payload, timeout)

        monkeypatch.setattr(services, "_exchange", mapped)
        return await services.detect("127.0.0.1", list(replies), 2)

    assert _with_servers(replies, detect) == []


def test_domain_controller_and_proxmox_rules():
    found = asyncio.run(services.detect("192.0.2.1", [], 0.1))
    assert found == []
    # AD needs Kerberos + LDAP + SMB together (no network needed: port-only services)
    found = asyncio.run(services.detect("192.0.2.1", [88, 389, 445], 0.1))
    assert {"active-directory", "kerberos", "ldap", "smb"} <= set(found)
    found = asyncio.run(services.detect("192.0.2.1", [8006], 0.1, web_servers="pve-api-daemon/3.0"))
    assert "proxmox" in found


def test_catalog_is_consistent():
    names = [c[0] for c in services.CATALOG]
    assert len(names) == len(set(names))
    groups = {c[2] for c in services.CATALOG}
    assert {"database", "cluster", "directory", "mail", "virtualization"} <= groups
    assert 1433 in services.service_ports() and 3343 in services.service_ports()


def test_checked_services_and_template_names(example_config):
    found = ["mssql", "smb", "rdp", "windows-cluster", "active-directory"]
    assert services.checked_services(found, example_config) == ["mssql", "windows-cluster"]
    assert services.checked_services(found, {"service_checks": ["file"]}) == ["smb"]
    assert services.checked_services(found, {"service_checks": False}) == []
    assert services.template_name("smtp", 25) == "AutoDiscovery - Service SMTP"
    assert services.template_name("smtp", 587) == "AutoDiscovery - Service SMTP (TCP 587)"
    assert services.check_port("smtp", [587, 443]) == 587
    row = {"services": "smtp,ssh", "ports": "22,587"}
    assert service_template_names(example_config, row) == ["AutoDiscovery - Service SMTP (TCP 587)"]


def test_service_template_checks_the_right_port():
    from tests.test_templates_maps import FakeAPI

    api = FakeAPI()
    services.ensure_service_template(api, "smtp", 587, log=lambda *_: None)
    item = api.created("item.create")[0]
    trigger = api.created("trigger.create")[0]
    assert item["key_"] == "net.tcp.service.perf[tcp,,587]"
    assert re.search(r"/AutoDiscovery - Service SMTP \(TCP 587\)/net\.tcp\.service\.perf\[tcp,,587\]",
                     trigger["expression"])

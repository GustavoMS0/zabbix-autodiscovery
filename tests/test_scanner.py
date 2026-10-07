import asyncio
import struct
from ipaddress import ip_address

from zabbix_autodiscovery import scanner


def test_expand_targets():
    ips = scanner.expand_targets(["10.0.0.1-10.0.0.3", "10.0.1.0/30", "10.0.2.9"])
    assert ips == [ip_address(x) for x in
                   ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.1.1", "10.0.1.2", "10.0.2.9")]


def _entry(name, suffix, flags):
    return name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", flags)


def test_parse_nbstat_picks_unique_computer_name():
    assert len(scanner._NBSTAT_QUERY) == 50
    body = bytes([2]) + _entry("WORKGROUP", 0, 0x8400) + _entry("SRV-FS01", 0, 0x0400)
    reply = (b"\x13\x37\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00" + scanner._NBSTAT_QUERY[12:46]
             + b"\x00\x21\x00\x01" + b"\x00" * 4 + struct.pack(">H", len(body)) + body)
    assert scanner.parse_nbstat(reply) == "SRV-FS01"
    assert scanner.parse_nbstat(b"garbage") == ""


def test_snmp_community_message(monkeypatch):
    """The hand-built v2c GET must decode with pysnmp and carry our three OIDs."""
    from pyasn1.codec.ber import decoder

    sent = {}

    async def fake_udp(ip, port, payload, timeout):
        sent["payload"] = payload
        return None

    monkeypatch.setattr(scanner, "udp_request", fake_udp)
    prober = scanner.SnmpProber([{"name": "t", "version": "2c", "community": "public"}], 0.1, 0)
    assert asyncio.run(prober.probe("192.0.2.1")) is None

    pmod = prober.api.PROTOCOL_MODULES[prober.api.SNMP_VERSION_2C]
    msg, _ = decoder.decode(sent["payload"], asn1Spec=pmod.Message())
    assert str(pmod.apiMessage.get_community(msg)) == "public"
    oids = [str(o) for o, _ in pmod.apiPDU.get_varbinds(pmod.apiMessage.get_pdu(msg))]
    assert oids == [scanner.SYS_DESCR, scanner.SYS_OBJECTID, scanner.SYS_NAME]


def test_refused_port_stops_credential_loop(monkeypatch):
    calls = []

    async def refused(ip, port, payload, timeout):
        calls.append(ip)
        return scanner.REFUSED

    monkeypatch.setattr(scanner, "udp_request", refused)
    creds = [{"name": "a", "version": "2c", "community": "a"}, {"name": "b", "version": "1", "community": "b"}]
    assert asyncio.run(scanner.SnmpProber(creds, 0.1, 1).probe("192.0.2.1")) is None
    assert len(calls) == 1


def test_merge_second_pass():
    first = scanner.Device("10.0.0.1", ports=[80])
    second = scanner.Device("10.0.0.1", ports=[443], sysobjectid="1.3.6.1.4.1.9.1", sysname="sw")
    scanner.merge(first, second)
    assert first.ports == [80, 443] and first.sysname == "sw"

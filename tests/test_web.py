import asyncio
import datetime as dt
import ssl

import pytest

from zabbix_autodiscovery import scanner, web
from zabbix_autodiscovery.classifier import certificate_columns, classify, web_servers
from zabbix_autodiscovery.scanner import Device


def _self_signed(tmp_path, cn="intranet.example.com", days=45):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("www." + cn)]), False)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "c.pem", tmp_path / "k.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert, cert_path, key_path


def test_parse_certificate(tmp_path):
    from cryptography.hazmat.primitives import serialization

    cert, _, _ = _self_signed(tmp_path)
    info = scanner.parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert info["cn"] == "intranet.example.com"
    assert info["names"] == ["intranet.example.com", "www.intranet.example.com"]
    assert info["self_signed"] is True
    assert info["not_after"] == (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=45)).strftime("%Y-%m-%d")
    assert scanner.parse_certificate(b"not a certificate") is None


def test_http_probe_reads_server_header_and_certificate(tmp_path):
    _, cert_path, key_path = _self_signed(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)

    async def handler(reader, writer):
        await reader.read(1024)
        writer.write(b"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()

    async def run():
        server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await scanner.http_probe("127.0.0.1", port, True, 3)

    result = asyncio.run(run())
    assert result["server"] == "Microsoft-IIS/10.0"
    assert result["cert"]["cn"] == "intranet.example.com"


def test_inventory_columns_and_iis_rule(example_config):
    cert = {"cn": "app.example.com", "names": ["app.example.com"], "issuer": "Let's Encrypt",
            "not_after": "2027-01-31", "self_signed": False}
    dev = Device("10.0.0.50", True, ports=[443, 445],
                 web=[{"port": 443, "tls": True, "server": "Microsoft-IIS/10.0", "cert": cert}])
    assert web_servers(dev) == "443=Microsoft-IIS/10.0"
    assert certificate_columns(dev) == {"cert_names": "app.example.com", "cert_expires": "2027-01-31",
                                        "cert_issuer": "Let's Encrypt", "cert_self_signed": "no"}
    row = classify(dev, example_config)
    assert (row["category"], row["action"]) == ("server-windows", "review")


@pytest.mark.parametrize("text, expected", [
    ("https://www.example.com/", ("www.example.com", 443)),
    ("https://Example.com:8443/login", ("example.com", 8443)),
    ("mail.example.com:443", ("mail.example.com", 443)),
    ("example.com.br", ("example.com.br", 443)),
])
def test_parse_site(text, expected):
    assert web.parse_site(text) == expected


def test_clean_domain():
    assert web.clean_domain(" Example.COM.br. ") == "example.com.br"
    with pytest.raises(ValueError):
        web.clean_domain("not a domain")


def test_sites_from_inventory_skips_self_signed():
    rows = [
        {"ip": "10.0.0.1", "cert_names": "*.example.com,portal.example.com", "cert_self_signed": "no",
         "web_servers": "80=nginx; 8443=nginx"},
        {"ip": "10.0.0.2", "cert_names": "idrac-xyz", "cert_self_signed": "yes", "web_servers": "443=?"},
        {"ip": "10.0.0.3", "cert_names": "", "cert_self_signed": "", "web_servers": ""},
    ]
    assert web.sites_from_inventory(rows) == [("portal.example.com", 8443, "10.0.0.1")]


def test_rdap_javascript_logic():
    """The Zabbix preprocessing JavaScript, evaluated with the same logic in Python."""
    assert "eventAction === 'expiration'" in web.RDAP_EXPIRES_JS
    assert "Date.parse(events[i].eventDate)" in web.RDAP_EXPIRES_JS
    assert web.DAYS_JS.format(expr="X") == "return Math.floor((X - Date.now() / 1000) / 86400);"


def test_web_example_config(example_config):
    sites = example_config["web"]["certificates"]["sites"]
    assert [web.parse_site(s) for s in sites] == [("www.example.com", 443), ("mail.example.com", 443)]
    assert all(web.clean_domain(d) for d in example_config["web"]["domains"]["list"])


def test_rdap_url_uses_longest_matching_suffix():
    bootstrap = {"br": "https://rdap.registro.br/", "com": "https://rdap.verisign.com/com/v1/"}
    assert web.rdap_url("example.com.br", bootstrap) == "https://rdap.registro.br/domain/"
    assert web.rdap_url("example.ind.br", bootstrap) == "https://rdap.registro.br/domain/"
    assert web.rdap_url("example.com", bootstrap) == "https://rdap.verisign.com/com/v1/domain/"
    assert web.rdap_url("example.xyz", bootstrap) == web.RDAP_FALLBACK
    assert web.USER_AGENT.startswith("zabbix-autodiscovery/")

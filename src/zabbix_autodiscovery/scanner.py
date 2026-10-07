"""Network scanner: ping, TCP ports, SNMP, Zabbix agent, NetBIOS and forward-confirmed reverse DNS."""
import asyncio
import ipaddress
import platform
import socket
import struct
from dataclasses import dataclass, field

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECTID = "1.3.6.1.2.1.1.2.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
AGENT_PORT = 10050
WINDOWS = platform.system() == "Windows"


@dataclass
class Device:
    ip: str
    alive: bool = False
    dns: str = ""
    sysname: str = ""
    sysdescr: str = ""
    sysobjectid: str = ""
    snmp_cred: str = ""
    ports: list = field(default_factory=list)
    agent_hostname: str = ""
    agent_uname: str = ""
    system_hostname: str = ""
    netbios: str = ""
    dns_confirmed: bool = False

    @property
    def snmp(self):
        return bool(self.sysobjectid or self.sysdescr)

    @property
    def agent(self):
        return bool(self.agent_uname or self.agent_hostname)

    @property
    def responded(self):
        return self.alive or self.snmp or bool(self.ports)


def expand_targets(items):
    """Accept CIDR, single IP or 'start-end' range."""
    ips = []
    for item in items or []:
        item = str(item).strip()
        if "-" in item:
            start, end = (ipaddress.ip_address(p.strip()) for p in item.split("-", 1))
            ips.extend(ipaddress.ip_address(i) for i in range(int(start), int(end) + 1))
        elif "/" in item:
            net = ipaddress.ip_network(item, strict=False)
            ips.extend(net.hosts() if net.num_addresses > 2 else net)
        else:
            ips.append(ipaddress.ip_address(item))
    return ips


def _snmp_str(value):
    if value.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return ""
    if hasattr(value, "asOctets"):
        raw = value.asOctets()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1")      # older devices send accented text as Latin-1
        return " ".join(text.replace("\x00", " ").split())
    return value.prettyPrint()


REFUSED = object()      # host answered "ICMP port unreachable": nothing listening


class _UdpOnce(asyncio.DatagramProtocol):
    def __init__(self, payload):
        self.payload = payload
        self.future = asyncio.get_running_loop().create_future()

    def connection_made(self, transport):
        transport.sendto(self.payload)

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_result(REFUSED)

    def connection_lost(self, exc):
        if not self.future.done():
            self.future.set_result(REFUSED if exc else None)


async def udp_request(ip, port, payload, timeout):
    """Send one datagram on a dedicated socket and wait for the reply.
    Returns bytes, None (timeout) or REFUSED (ICMP port unreachable)."""
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            lambda: _UdpOnce(payload), remote_addr=(ip, port))
    except OSError:
        return None
    try:
        return await asyncio.wait_for(proto.future, timeout)
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        transport.close()


class SnmpProber:
    """SNMP GET of sysDescr/sysObjectID/sysName.

    v1/v2c use only pysnmp's message encoding and one UDP socket per request. This is light
    (an SnmpEngine costs ~0.4 s of CPU to build) and, on Windows, an "ICMP port unreachable" from a
    host without SNMP only breaks that one socket instead of a shared one. v3 needs the (USM) SnmpEngine.
    """

    def __init__(self, credentials, timeout, retries):
        try:
            from pyasn1.codec.ber import decoder, encoder
            from pysnmp.proto import api
        except ImportError as exc:
            raise SystemExit("pysnmp >= 7 not found: pip install zabbix-autodiscovery") from exc
        self.api, self.encoder, self.decoder = api, encoder, decoder
        self.hl = None
        self.engine = None
        self.timeout = timeout
        self.retries = retries
        self.credentials = [(c, self._auth_data(c)) for c in credentials]

    def _auth_data(self, cred):
        version = str(cred.get("version", "2c"))
        if version in ("1", "2", "2c"):
            return None
        if self.hl is None:
            from pysnmp.hlapi.v3arch import asyncio as hl
            self.hl = hl
        hl = self.hl
        auth_protocols = {
            "MD5": hl.usmHMACMD5AuthProtocol,
            "SHA": hl.usmHMACSHAAuthProtocol,
            "SHA256": hl.usmHMAC192SHA256AuthProtocol,
            "SHA512": hl.usmHMAC384SHA512AuthProtocol,
        }
        priv_protocols = {
            "DES": hl.usmDESPrivProtocol,
            "AES": hl.usmAesCfb128Protocol,
            "AES256": hl.usmAesCfb256Protocol,
        }
        kwargs = {}
        if cred.get("auth_pass"):
            kwargs["authKey"] = cred["auth_pass"]
            kwargs["authProtocol"] = auth_protocols[cred.get("auth_protocol", "SHA").upper()]
        if cred.get("priv_pass"):
            kwargs["privKey"] = cred["priv_pass"]
            kwargs["privProtocol"] = priv_protocols[cred.get("priv_protocol", "AES").upper()]
        return hl.UsmUserData(cred["user"], **kwargs)

    async def _get_community(self, ip, cred):
        api = self.api
        pmod = api.PROTOCOL_MODULES[api.SNMP_VERSION_1 if str(cred.get("version")) == "1"
                                    else api.SNMP_VERSION_2C]
        pdu = pmod.GetRequestPDU()
        pmod.apiPDU.set_defaults(pdu)
        pmod.apiPDU.set_varbinds(pdu, [(oid, pmod.Null("")) for oid in (SYS_DESCR, SYS_OBJECTID, SYS_NAME)])
        msg = pmod.Message()
        pmod.apiMessage.set_defaults(msg)
        pmod.apiMessage.set_community(msg, cred["community"])
        pmod.apiMessage.set_pdu(msg, pdu)
        payload = self.encoder.encode(msg)
        request_id = pmod.apiPDU.get_request_id(pdu)

        for _ in range(self.retries + 1):
            data = await udp_request(ip, 161, payload, self.timeout)
            if data is REFUSED:
                return REFUSED
            if not data:
                continue
            try:
                rsp, _ = self.decoder.decode(data, asn1Spec=pmod.Message())
                rpdu = pmod.apiMessage.get_pdu(rsp)
            except Exception:
                return None
            if pmod.apiPDU.get_request_id(rpdu) != request_id or pmod.apiPDU.get_error_status(rpdu):
                return None
            return [_snmp_str(value) for _, value in pmod.apiPDU.get_varbinds(rpdu)]
        return None

    async def _get_v3(self, ip, auth):
        hl = self.hl
        if self.engine is None:
            self.engine = hl.SnmpEngine()
        try:
            target = await hl.UdpTransportTarget.create((ip, 161), timeout=self.timeout, retries=self.retries)
            err_ind, err_status, _, var_binds = await hl.get_cmd(
                self.engine, auth, target, hl.ContextData(),
                *(hl.ObjectType(hl.ObjectIdentity(o)) for o in (SYS_DESCR, SYS_OBJECTID, SYS_NAME)),
                lookupMib=False)
        except Exception:
            return None
        if err_ind or err_status:
            return None
        return [_snmp_str(vb[1]) for vb in var_binds]

    async def probe(self, ip):
        """Return (credential_name, sysDescr, sysObjectID, sysName) or None."""
        for cred, auth in self.credentials:
            result = await (self._get_community(ip, cred) if auth is None else self._get_v3(ip, auth))
            if result is REFUSED:
                return None                  # port 161 closed: no point trying other credentials
            if result and any(result):
                descr, objid, name = result
                return cred["name"], descr, objid.lstrip("."), name
        return None


async def ping(ip, timeout):
    if WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 3)
    except Exception:
        return False
    # On Windows ping exits 0 even for "destination unreachable"; TTL= only shows on a real reply
    return proc.returncode == 0 and b"TTL=" in out.upper()


async def tcp_open(ip, port, timeout):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def agent_get(ip, key, timeout):
    """Passive Zabbix agent query (ZBXD protocol). The scanner IP must be listed in the agent's Server=."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, AGENT_PORT), timeout)
    except Exception:
        return ""
    try:
        data = key.encode()
        writer.write(b"ZBXD\x01" + struct.pack("<II", len(data), 0) + data)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(), timeout * 2)
    except Exception:
        return ""
    finally:
        writer.close()
    if resp[:4] != b"ZBXD" or len(resp) < 13:
        return ""
    length = struct.unpack("<I", resp[5:9])[0]
    value = resp[13:13 + length].decode("utf-8", "replace").strip()
    return "" if value.startswith("ZBX_NOTSUPPORTED") else value


async def reverse_dns(ip):
    """Return (name, confirmed). Confirmed = the name resolves back to the same IP,
    which discards stale PTR records."""
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyaddr, ip), 3)
    except Exception:
        return "", False
    try:
        infos = await asyncio.wait_for(loop.run_in_executor(None, socket.getaddrinfo, name, None), 3)
        confirmed = any(info[4][0] == ip for info in infos)
    except Exception:
        confirmed = False
    return name, confirmed


# NetBIOS node status query (same as "nbtstat -A"): encoded name "*" + type NBSTAT
_NBSTAT_QUERY = (b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01")


def parse_nbstat(data):
    """Extract the computer name (suffix 0x00, unique name) from an NBSTAT reply."""
    try:
        pos = 12
        pos += 2 if data[pos] & 0xC0 == 0xC0 else data[pos] + 2      # question name (or pointer)
        pos += 10                                                     # type, class, TTL, length
        count = data[pos]
        pos += 1
        for _ in range(count):
            entry = data[pos:pos + 18]
            pos += 18
            name, suffix = entry[:15].decode("ascii", "replace").strip(), entry[15]
            group = struct.unpack(">H", entry[16:18])[0] & 0x8000
            if suffix == 0x00 and not group and name:
                return name
    except (IndexError, struct.error):
        pass
    return ""


async def netbios_name(ip, timeout):
    data = await udp_request(ip, 137, _NBSTAT_QUERY, timeout)
    return parse_nbstat(data) if isinstance(data, bytes) else ""


async def scan_host(ip, ctx):
    async with ctx["sem"]:
        dev = Device(ip)
        timeout = ctx["timeout"]
        ports = ctx["ports"]
        ping_task = ping(ip, timeout) if ctx["ping"] else asyncio.sleep(0, False)
        results = await asyncio.gather(
            ping_task, ctx["snmp"].probe(ip), *(tcp_open(ip, p, timeout) for p in ports))
        dev.alive = bool(results[0])
        if results[1]:
            dev.snmp_cred, dev.sysdescr, dev.sysobjectid, dev.sysname = results[1]
        dev.ports = [p for p, is_open in zip(ports, results[2:], strict=True) if is_open]
        if AGENT_PORT in dev.ports:
            dev.agent_hostname = await agent_get(ip, "agent.hostname", timeout)
            dev.agent_uname = await agent_get(ip, "system.uname", timeout)
            dev.system_hostname = await agent_get(ip, "system.hostname", timeout)
        if dev.responded and not dev.agent and ctx.get("netbios", True):
            dev.netbios = await netbios_name(ip, timeout)
        if dev.responded and ctx["reverse_dns"]:
            dev.dns, dev.dns_confirmed = await reverse_dns(ip)
        return dev


async def scan(scan_cfg, credentials, progress=None):
    excluded = set(expand_targets(scan_cfg.get("exclude")))
    targets = [str(ip) for ip in expand_targets(scan_cfg["networks"]) if ip not in excluded]
    ports = sorted(set(int(p) for p in scan_cfg.get("ports", [])) | {AGENT_PORT})
    ctx = {
        "sem": asyncio.Semaphore(int(scan_cfg.get("concurrency", 50))),
        "timeout": float(scan_cfg.get("timeout", 1.5)),
        "ports": ports,
        "ping": scan_cfg.get("ping", True),
        "reverse_dns": scan_cfg.get("reverse_dns", True),
        "snmp": SnmpProber(credentials, float(scan_cfg.get("timeout", 1.5)),
                           int(scan_cfg.get("snmp_retries", 1))),
    }
    found = []
    tasks = [scan_host(ip, ctx) for ip in targets]
    for done, coro in enumerate(asyncio.as_completed(tasks), 1):
        dev = await coro
        if dev.responded:
            found.append(dev)
        if progress:
            progress(done, len(targets), len(found))

    # Second pass: with many hosts in parallel, short timeouts miss ports/SNMP.
    # Re-probe only responsive hosts, with less parallelism and twice the timeout, and merge.
    if found and scan_cfg.get("second_pass", True):
        timeout2 = ctx["timeout"] * 2
        ctx2 = dict(ctx, sem=asyncio.Semaphore(max(5, int(scan_cfg.get("concurrency", 50)) // 3)),
                    timeout=timeout2, ping=False, reverse_dns=False, netbios=False,
                    snmp=SnmpProber(credentials, timeout2, int(scan_cfg.get("snmp_retries", 1))))
        tasks = [scan_host(d.ip, ctx2) for d in found]
        by_ip = {d.ip: d for d in found}
        for done, coro in enumerate(asyncio.as_completed(tasks), 1):
            merge(by_ip[(again := await coro).ip], again)
            if progress:
                progress(done, len(found), len(found), "second pass")
    found.sort(key=lambda d: ipaddress.ip_address(d.ip))
    return found


def merge(dev, again):
    """Complete the first-pass result with what the second pass found."""
    dev.ports = sorted(set(dev.ports) | set(again.ports))
    if not dev.snmp and again.snmp:
        dev.snmp_cred, dev.sysdescr = again.snmp_cred, again.sysdescr
        dev.sysobjectid, dev.sysname = again.sysobjectid, again.sysname
    if not dev.agent and again.agent:
        dev.agent_hostname, dev.agent_uname = again.agent_hostname, again.agent_uname
        dev.system_hostname = again.system_hostname
        dev.netbios = ""

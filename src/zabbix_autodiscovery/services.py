"""Service detection for local networks: databases, clusters, directory, mail, virtualization...

Each catalog entry lists the TCP ports that identify a service. When the protocol talks first or answers a
tiny request, the scanner confirms it (MySQL greeting, PostgreSQL SSL handshake, Redis PING, SSH/SMTP/FTP
banners, Elasticsearch/Docker HTTP answers), so an unrelated program on the same port is not reported.

Detected services become a "services" column in the inventory and "service" tags in Zabbix. Services of
the groups listed in config "service_checks" also get a template that raises a problem when the port stops
answering (no credentials needed). Everything here targets local / on-premises networks.
"""
import asyncio

PREFIX = "AutoDiscovery - "             # same prefix as provision.PREFIX (not imported: scanner uses this module)
TEMPLATE_GROUP = "Templates/AutoDiscovery"

# probe: None = port is enough; otherwise (payload to send or None, predicate on the reply bytes)
HTTP_GET = b"GET / HTTP/1.0\r\nUser-Agent: zabbix-autodiscovery\r\n\r\n"
DOCKER_GET = b"GET /version HTTP/1.0\r\n\r\n"
PG_SSLREQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


def _mysql(reply):
    # protocol v10 greeting (len[3] seq[1] 0x0a version...), or an error packet (0xff) such as "host not allowed"
    return len(reply) > 5 and (reply[4] == 0x0A or reply[4] == 0xFF or b"mysql" in reply.lower()
                               or b"mariadb" in reply.lower())


CATALOG = [
    # name, label, group, any of these ports, optional (payload, predicate)
    ("mssql", "Microsoft SQL Server", "database", [1433], None),
    ("mysql", "MySQL / MariaDB", "database", [3306], (None, _mysql)),
    ("postgresql", "PostgreSQL", "database", [5432], (PG_SSLREQUEST, lambda r: r[:1] in (b"S", b"N"))),
    ("oracle", "Oracle Database", "database", [1521], None),
    ("mongodb", "MongoDB", "database", [27017], None),
    ("redis", "Redis", "database", [6379],
     (b"PING\r\n", lambda r: r.startswith((b"+PONG", b"-NOAUTH", b"-ERR", b"-DENIED")))),
    ("elasticsearch", "Elasticsearch / OpenSearch", "database", [9200],
     (HTTP_GET, lambda r: b"cluster_name" in r or b"You Know, for Search" in r or b"opensearch" in r.lower()
      or (b"401" in r[:20] and b"security" in r.lower()))),
    ("influxdb", "InfluxDB", "database", [8086], None),
    ("memcached", "Memcached", "database", [11211], (b"version\r\n", lambda r: r.startswith(b"VERSION"))),

    ("windows-cluster", "Windows Failover Cluster", "cluster", [3343], None),
    ("sql-alwayson", "SQL Server AlwaysOn / mirroring endpoint", "cluster", [5022], None),
    ("hyperv-migration", "Hyper-V live migration", "cluster", [6600], None),
    ("pacemaker", "Pacemaker / pcsd", "cluster", [2224], None),
    ("galera", "Galera cluster", "cluster", [4567], None),
    ("redis-cluster", "Redis cluster bus", "cluster", [16379], None),
    ("elasticsearch-cluster", "Elasticsearch transport", "cluster", [9300], None),
    ("rabbitmq-cluster", "RabbitMQ clustering", "cluster", [25672], None),
    ("kubernetes-api", "Kubernetes API server", "cluster", [6443], None),
    ("kubelet", "Kubernetes kubelet", "cluster", [10250], None),
    ("etcd", "etcd", "cluster", [2379, 2380], None),

    ("vmware-esxi", "VMware ESXi", "virtualization", [902], None),
    ("proxmox", "Proxmox VE", "virtualization", [8006], None),
    ("docker-api", "Docker API", "virtualization", [2375, 2376],
     (DOCKER_GET, lambda r: b"ApiVersion" in r or b"Client sent an HTTP request to an HTTPS server" in r)),

    ("active-directory", "Active Directory domain controller", "directory", [], None),   # see detect()
    ("ldap", "LDAP", "directory", [389, 636], None),
    ("kerberos", "Kerberos", "directory", [88], None),
    ("global-catalog", "AD Global Catalog", "directory", [3268, 3269], None),
    ("dns", "DNS", "directory", [53], None),

    ("smtp", "SMTP", "mail", [25, 587],
     (None, lambda r: r.startswith(b"220") and any(k in r.upper() for k in (b"SMTP", b"MAIL", b"POSTFIX", b"EXIM",
                                                                             b"EXCHANGE", b"ZIMBRA")))),
    ("imap", "IMAP", "mail", [143, 993], (None, lambda r: r.startswith(b"* OK"))),
    ("pop3", "POP3", "mail", [110, 995], (None, lambda r: r.startswith(b"+OK"))),

    ("rabbitmq", "RabbitMQ", "messaging", [5672, 15672], None),
    ("kafka", "Kafka", "messaging", [9092], None),
    ("mqtt", "MQTT broker", "messaging", [1883, 8883], None),

    ("veeam", "Veeam Backup", "backup", [9392, 9401, 10005, 10006], None),

    ("zabbix-server", "Zabbix server / proxy", "monitoring", [10051], None),
    ("prometheus", "Prometheus", "monitoring", [9090],
     (b"GET /-/healthy HTTP/1.0\r\n\r\n", lambda r: b"Prometheus" in r)),
    ("grafana", "Grafana", "monitoring", [3000],
     (b"GET /api/health HTTP/1.0\r\n\r\n", lambda r: b'"database"' in r and b"version" in r)),

    ("smb", "File sharing (SMB)", "file", [445], None),
    ("nfs", "NFS", "file", [2049], None),
    ("iscsi", "iSCSI target", "file", [3260], None),
    ("ftp", "FTP", "file", [21], (None, lambda r: r.startswith(b"220"))),

    ("ssh", "SSH", "remote-access", [22], (None, lambda r: r.startswith(b"SSH-"))),
    ("rdp", "Remote Desktop", "remote-access", [3389], None),
    ("winrm", "WinRM", "remote-access", [5985, 5986], None),
    ("vnc", "VNC", "remote-access", [5900], (None, lambda r: r.startswith(b"RFB"))),
    ("telnet", "Telnet", "remote-access", [23], None),

    ("rtsp", "RTSP video", "video", [554], None),
    ("sip", "SIP", "voip", [5060], None),
    ("printing", "Printing (JetDirect/LPD/IPP)", "printing", [9100, 515, 631], None),
]
BY_NAME = {c[0]: c for c in CATALOG}
# Groups whose services get a "port answering" template by default (config: service_checks)
DEFAULT_CHECK_GROUPS = ["database", "cluster", "directory", "mail", "messaging", "backup", "virtualization"]


def service_ports():
    return sorted({p for _, _, _, ports, _ in CATALOG for p in ports})


async def _exchange(ip, port, payload, timeout):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except Exception:
        return b""
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        return await asyncio.wait_for(reader.read(1024), timeout)
    except Exception:
        return b""
    finally:
        writer.close()


async def detect(ip, open_ports, timeout, web_servers=""):
    """Service names found on a host, from its open ports (+ protocol confirmation when available)."""
    ports = set(open_ports)
    found = []
    checks = []
    for name, _, _, svc_ports, probe in CATALOG:
        hit = sorted(ports & set(svc_ports))
        if not hit:
            continue
        if probe is None:
            found.append(name)
        else:
            checks.append((name, hit[0], probe))
    replies = await asyncio.gather(*(_exchange(ip, port, payload, timeout) for _, port, (payload, _) in checks))
    for (name, _, (_, ok)), reply in zip(checks, replies, strict=True):
        if reply and ok(reply):
            found.append(name)
    if {88, 389, 445} <= ports:
        found.append("active-directory")
    if "pve-api-daemon" in web_servers.lower() and "proxmox" not in found:
        found.append("proxmox")
    order = {c[0]: i for i, c in enumerate(CATALOG)}
    return sorted(set(found), key=lambda n: order.get(n, 999))


# ---------------------------------------------------------------- Zabbix side

def template_name(service, port=None):
    """One template per service and port: e.g. SMTP on 25 and SMTP on 587 are separate templates."""
    _, label, _, ports, _ = BY_NAME[service]
    suffix = f" (TCP {port})" if port and port != ports[0] else ""
    return f"{PREFIX}Service {label}{suffix}"


def check_port(service, open_ports=()):
    """Port monitored for a service: the first of its ports that was found open, else its first port."""
    ports = BY_NAME[service][3]
    return next((p for p in ports if p in set(open_ports)), ports[0])


def checked_services(services, cfg):
    groups = cfg.get("service_checks", DEFAULT_CHECK_GROUPS)
    if groups in (False, None):
        return []
    groups = set(groups or [])
    return [s for s in services if s in BY_NAME and BY_NAME[s][2] in groups and BY_NAME[s][3]]


def ensure_service_template(api, service, port=None, log=print):
    """Template with a TCP check on the service's main port; problem after 3 failed checks in a row.

    The port is part of the item key (not a macro): several service templates on one host never clash."""
    name, label, _, ports, _ = BY_NAME[service]
    port = port or ports[0]
    tname = template_name(service, port)
    found = api.call("template.get", {"output": ["templateid"], "filter": {"host": tname}})
    if found:
        return found[0]["templateid"]
    tid = api.call("template.create", {
        "host": tname, "groups": [{"groupid": api.ensure_templategroup(TEMPLATE_GROUP)}],
        "description": f"Created by zabbix-autodiscovery. {label}: checks that TCP {port} answers "
                       "(from the Zabbix server or proxy, no credentials).",
        "tags": [{"tag": "origin", "value": "autodiscovery"}],
    })["templateids"][0]
    key = f"net.tcp.service.perf[tcp,,{port}]"
    api.call("item.create", {
        "hostid": tid, "type": 3, "value_type": 0, "units": "s", "delay": "1m", "history": "30d",
        "name": f"Service {label}: TCP {port} response time", "key_": key,
        "description": "0 = the port did not answer.",
        "tags": [{"tag": "component", "value": "service"}, {"tag": "service", "value": name}],
    })
    api.call("trigger.create", {
        "description": f"{label} (TCP {port}) is not answering on {{HOST.NAME}}",
        "expression": f"max(/{tname}/{key},#3)=0", "priority": 3,
        "tags": [{"tag": "service", "value": name}, {"tag": "scope", "value": "availability"}],
    })
    log(f"- template '{tname}' created")
    return tid


def service_tags(services):
    return [{"tag": "service", "value": s} for s in services]


def parse(text):
    return [s for s in (text or "").replace(";", ",").split(",") if s.strip() and s.strip() in BY_NAME]

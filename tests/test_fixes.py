import asyncio

import pytest
import requests

from zabbix_autodiscovery import dashboards, scanner
from zabbix_autodiscovery.zabbix_api import ZabbixAPI, ZabbixError

# ---------------------------------------------------------------- dashboards

def _widgets(key, version, hostnames=()):
    spec = next(s for s in dashboards.SPECS if s["key"] == key)
    return dashboards.zabbix_widgets(spec, ["1"], version, hostnames)


def _fields(widget):
    return {f["name"]: f["value"] for f in widget["fields"]}


def test_svggraph_lists_hosts_and_has_no_invalid_fields():
    assert not [w for w in _widgets("switches", (8, 0)) if w["type"] == "svggraph"]      # no hosts yet: no graph
    graphs = [w for w in _widgets("switches", (8, 0), ["sw-b", "sw-a"]) if w["type"] == "svggraph"]
    assert graphs
    for g in graphs:
        f = _fields(g)
        assert f["ds.0.hosts.0"] == "sw-a" and f["ds.0.hosts.1"] == "sw-b" and f["ds.0.items.0"]
        assert "groupids.0" not in f and "graph_time" not in f


def test_svggraph_host_list_is_capped():
    hosts = [f"h{i:03}" for i in range(80)]
    g = next(w for w in _widgets("switches", (8, 0), hosts) if w["type"] == "svggraph")
    assert sum(1 for f in g["fields"] if f["name"].startswith("ds.0.hosts.")) == dashboards.MAX_GRAPH_HOSTS


def test_tophosts_order_on_zabbix_6_4():
    servers = {w["name"]: _fields(w) for w in _widgets("servers", (6, 4)) if w["type"] == "tophosts"}
    assert servers["CPU"]["order"] == 2                                    # highest usage first
    ups = {w["name"]: _fields(w) for w in _widgets("ups", (6, 4)) if w["type"] == "tophosts"}
    assert ups["Battery charge"]["order"] == 3                             # lowest charge first


# ---------------------------------------------------------------- API retries

class FakeResponse:
    def __init__(self, status=200, result="ok"):
        self.status_code, self._result = status, result

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))

    def json(self):
        return {"result": self._result}


def _api(responses):
    api = ZabbixAPI.__new__(ZabbixAPI)
    api.url, api._id, api._auth, api.BACKOFF = "http://z/api_jsonrpc.php", 0, None, 0
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs["json"]["method"])
        r = responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    api.session = type("S", (), {"post": staticmethod(post), "headers": {}})()
    return api, calls


def test_write_is_not_retried_after_read_timeout():
    api, calls = _api([requests.ReadTimeout("slow"), FakeResponse()])
    with pytest.raises(ZabbixError):
        api.call("host.create", {})
    assert calls == ["host.create"]


def test_write_is_retried_when_connection_failed():
    api, calls = _api([requests.ConnectionError("refused"), FakeResponse(result="1")])
    assert api.call("host.create", {}) == "1" and len(calls) == 2


def test_504_retried_for_reads_only():
    api, calls = _api([FakeResponse(504), FakeResponse(result=[])])
    assert api.call("host.get", {}) == [] and len(calls) == 2
    api, calls = _api([FakeResponse(504), FakeResponse()])
    with pytest.raises(requests.HTTPError):
        api.call("item.create", {})
    assert len(calls) == 1


def test_read_timeout_retried_for_reads():
    api, calls = _api([requests.ReadTimeout("slow"), FakeResponse(result=[])])
    assert api.call("item.get", {}) == [] and len(calls) == 2


# ---------------------------------------------------------------- SNMP error status

def test_snmp_error_status_is_not_retried(monkeypatch):
    prober = scanner.SnmpProber([{"name": "t", "version": "2c", "community": "public"}], 0.1, 3)
    pmod = prober.api.PROTOCOL_MODULES[prober.api.SNMP_VERSION_2C]
    sent = []

    async def answer_with_error(ip, port, payload, timeout):
        sent.append(payload)
        msg, _ = prober.decoder.decode(payload, asn1Spec=pmod.Message())
        pdu = pmod.apiMessage.get_pdu(msg)
        rsp_pdu = pmod.GetResponsePDU()
        pmod.apiPDU.set_defaults(rsp_pdu)
        pmod.apiPDU.set_request_id(rsp_pdu, pmod.apiPDU.get_request_id(pdu))
        pmod.apiPDU.set_error_status(rsp_pdu, 2)                           # noSuchName
        pmod.apiPDU.set_varbinds(rsp_pdu, [(o, pmod.Null("")) for o, _ in pmod.apiPDU.get_varbinds(pdu)])
        pmod.apiMessage.set_pdu(msg, rsp_pdu)
        return prober.encoder.encode(msg)

    monkeypatch.setattr(scanner, "udp_request", answer_with_error)
    assert asyncio.run(prober.probe("192.0.2.1")) is None
    assert len(sent) == 1

import asyncio

import pytest
import requests

from zabbix_autodiscovery import scanner
from zabbix_autodiscovery.zabbix_api import ZabbixAPI, ZabbixError

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

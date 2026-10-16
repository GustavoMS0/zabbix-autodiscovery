"""Servidores (Windows/Linux & Hypervisors) v3."""
import json

from ..grafana_v2 import servers as _v2
from . import style as S

KEY = _v2.KEY
TITLE = _v2.TITLE


def build(cfg, datasource_uid="zabbix"):
    d = _v2.build(cfg, datasource_uid=datasource_uid)
    txt = json.dumps(d).replace("-v2", "-v3").replace("AutoDiscovery v2 - ", S.PREFIX).replace("Dashboards v2", "Dashboards v3")
    return json.loads(txt)


"""Design system wrapper for AutoDiscovery v3 dashboards.

Inherits all validated palette tokens, thresholds, value maps, Zabbix target builders and layout helpers
from grafana_v2.style, while scoping UIDs, titles, tags and cross-dashboard links to v3 ("autodiscovery-v3").
"""

from ..grafana_v2 import style as _v2
from ..grafana_v2.style import *  # noqa: F401,F403
from ..grafana_v2.style import _col, _fn, _ref, _regex_escape  # noqa: F401

PREFIX = "AutoDiscovery v3 - "
TAG = "autodiscovery-v3"


def uid(key):
    return f"autodiscovery-{key}-v3"


def dashboard_url(key, keep_time=True, **vars_):
    """Relative URL of a v3 dashboard; vars_ become var-<name>=<value> (e.g. site="BA")."""
    params = ["${__url_time_range}"] if keep_time else []
    params += [f"var-{k}={v}" for k, v in vars_.items()]
    return f"/d/{uid(key)}" + ("?" + "&".join(params) if params else "")


def tv_links():
    """Header links shared by the TV dashboards (Visão Geral <-> Topologia da Rede)."""
    return [
        (f"{dashboard_url('overview', keep_time=False)}&kiosk", "Visão Geral"),
        (f"{dashboard_url('topology', keep_time=False)}&kiosk", "Topologia da Rede"),
    ]


def categories(cfg):
    """v3 category dashboards with their host groups: [{"key", "title", "uid", "groups", "group"}]."""
    out = []
    for c in _v2.categories(cfg):
        item = dict(c)
        item["uid"] = uid(c["key"])
        out.append(item)
    return out


def dashboard(key, title, panels, *, datasource_uid="zabbix", variables=(), refresh="5m", time_from="now-6h",
              range_cap="2d", description="", tv=False, extra_tags=()):
    """Complete v3 dashboard."""
    d = _v2.dashboard(
        key, title, panels,
        datasource_uid=datasource_uid,
        variables=variables,
        refresh=refresh,
        time_from=time_from,
        range_cap=range_cap,
        description=description,
        tv=tv,
        extra_tags=extra_tags,
    )
    d["uid"] = uid(key)
    d["title"] = f"{PREFIX}{title}"
    d["tags"] = ["autodiscovery", TAG, *extra_tags]
    if not tv:
        d["links"] = [{
            "title": "Dashboards v3",
            "type": "dashboards",
            "tags": [TAG],
            "asDropdown": True,
            "includeVars": False,
            "keepTime": True,
            "icon": "external link",
            "targetBlank": False,
        }]
    return d

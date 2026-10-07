# Contributing

Thanks for helping! Issues and pull requests can be written in English or Portuguese.

## Development setup

```bash
git clone https://github.com/GustavoMS0/zabbix-autodiscovery
cd zabbix-autodiscovery
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check src tests
pytest
```

## Adding or fixing a device rule

Rules live in [`src/zabbix_autodiscovery/data/config.example.yaml`](src/zabbix_autodiscovery/data/config.example.yaml). `zabbix-autodiscovery init` copies that file into new installations.

1. Run `zabbix-autodiscovery scan` and take the `sysobjectid`, `sysdescr`, `ports` and `agent_uname` columns of the device.
2. Prefer `sysobjectid_prefix` (the vendor's IANA enterprise number, e.g. `1.3.6.1.4.1.9` for Cisco). It is the most stable signal, and it is also the only one the native Zabbix discovery can use. Use `sysdescr_regex` when one vendor OID covers several device types.
3. Put the rule **before** generic rules: order matters and the first match wins.
4. List template alternatives with `|`, ending with a generic one (`Network Generic Device by SNMP`, `Generic by SNMP`), so the rule still works on Zabbix versions that lack the specific template.
5. Never match on host names. Classification must work with any naming convention.
6. Add a case to `tests/test_classifier.py`. If the vendor is new, add it to `VENDORS` in `classifier.py`.

## Dashboards

Dashboards are described once in `SPECS` (`src/zabbix_autodiscovery/dashboards.py`) and rendered both as native Zabbix dashboards and as Grafana JSON. After changing them, regenerate the bundled Grafana files (CI checks they are up to date):

```bash
zabbix-autodiscovery -c src/zabbix_autodiscovery/data/config.example.yaml grafana-dashboards -o deploy/grafana/dashboards
```

## Guidelines

- Anything that changes Zabbix must be idempotent, skip existing objects and use the `AutoDiscovery - ` prefix or the `origin=autodiscovery` tag.
- New read-only checks belong in `zabbix-autodiscovery check`.
- Keep the Zabbix 6.0 → 8.0 compatibility: branch on `api.version` when the API differs.
- Never put real IPs, host names, tokens or communities in code, tests, docs or issues.

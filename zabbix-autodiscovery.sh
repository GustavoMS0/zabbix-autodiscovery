#!/usr/bin/env sh
# Run zabbix-autodiscovery from a source checkout on Linux/macOS without installing it.
#   ./zabbix-autodiscovery.sh init && ./zabbix-autodiscovery.sh check
set -e
here="$(cd "$(dirname "$0")" && pwd)"
if [ ! -x "$here/.venv/bin/python3" ] || [ ! -f "$here/.venv/bin/zabbix-autodiscovery" ]; then
  rm -rf "$here/.venv"
  python3 -m venv "$here/.venv"
  "$here/.venv/bin/pip" install --quiet -e "$here"
fi
exec "$here/.venv/bin/python3" -m zabbix_autodiscovery.cli "$@"

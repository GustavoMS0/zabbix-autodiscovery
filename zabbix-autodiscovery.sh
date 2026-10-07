#!/usr/bin/env sh
# Run zabbix-autodiscovery from a source checkout on Linux/macOS without installing it.
#   ./zabbix-autodiscovery.sh init && ./zabbix-autodiscovery.sh check
set -e
here="$(cd "$(dirname "$0")" && pwd)"
if [ ! -d "$here/.venv" ]; then
  python3 -m venv "$here/.venv"
  "$here/.venv/bin/pip" install --quiet -e "$here"
fi
exec "$here/.venv/bin/zabbix-autodiscovery" "$@"

#!/usr/bin/env bash
# zabbix-autodiscovery installer / updater for Linux and macOS (e.g. on the Zabbix server itself).
#
#   curl -fsSL https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.sh | bash
#
# What it does: downloads the project into ~/zabbix-autodiscovery, creates a Python virtual environment,
# installs the package and starts the interactive wizard. Running it again updates the code and keeps
# config.yaml, .env and your CSV files. It never uses sudo.
#
# Options (environment variables):
#   ZAD_DIR=/opt/zabbix-autodiscovery   install folder (default: ~/zabbix-autodiscovery)
#   ZAD_REF=v0.2.0                      branch or tag (default: main)
#   ZAD_NO_WIZARD=1                     install/update only, do not start the wizard
set -euo pipefail

REPO="GustavoMS0/zabbix-autodiscovery"
REF="${ZAD_REF:-main}"
DIR="${ZAD_DIR:-$HOME/zabbix-autodiscovery}"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
ask() {                                   # questions read from the terminal, even when piped from curl
    local answer
    [ -r /dev/tty ] || return 1
    read -r -p "$1 [y/N] " answer </dev/tty || return 1
    [[ "$answer" =~ ^[yYsS] ]]
}

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

say "Downloading $REPO ($REF) into $DIR"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "https://github.com/$REPO/archive/$REF.tar.gz" | tar -xz -C "$tmp" --strip-components=1 \
    || die "download failed (check the internet access of this machine)"
mkdir -p "$DIR"
# config.yaml, .env, *.csv and .venv are not part of the repository, so an update never overwrites them
(cd "$tmp" && tar -cf - .) | (cd "$DIR" && tar -xf -)
chmod +x "$DIR/zabbix-autodiscovery.sh" 2>/dev/null || true
cd "$DIR"

# Python 3.10+ with venv, or uv (which can also provide Python)
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
        PY="$candidate"
        break
    fi
done
[ -x "$HOME/.local/bin/uv" ] && export PATH="$HOME/.local/bin:$PATH"

if [ ! -x .venv/bin/python ]; then
    say "Creating the Python environment (.venv)"
    if [ -z "$PY" ] || ! "$PY" -m venv .venv >/dev/null 2>&1; then
        rm -rf .venv
        if ! command -v uv >/dev/null 2>&1; then
            ask "Python 3.10+ with venv was not found. Install uv (https://astral.sh/uv, no sudo) to provide it?" \
                || die "install python3 (3.10+) and python3-venv (e.g. apt install python3-venv), then run again"
            curl -LsSf https://astral.sh/uv/install.sh | sh
            export PATH="$HOME/.local/bin:$PATH"
        fi
        uv venv -q --python 3.12 .venv
    fi
fi

say "Installing dependencies"
if command -v uv >/dev/null 2>&1; then
    uv pip install -q --python .venv/bin/python -e .
else
    .venv/bin/python -m pip install -q --upgrade pip
    .venv/bin/python -m pip install -q -e .
fi
say "Installed: $(.venv/bin/zabbix-autodiscovery --version)"

if [ -n "${ZAD_NO_WIZARD:-}" ]; then
    say "Done. Start the wizard with: cd $DIR && ./zabbix-autodiscovery.sh wizard"
    exit 0
fi
if [ -r /dev/tty ]; then
    say "Starting the wizard (Ctrl+C to quit; run it again later with: cd $DIR && ./zabbix-autodiscovery.sh wizard)"
    exec .venv/bin/zabbix-autodiscovery wizard </dev/tty
fi
say "No interactive terminal. Start the wizard with: cd $DIR && ./zabbix-autodiscovery.sh wizard"

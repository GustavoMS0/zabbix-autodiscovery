# Run zabbix-autodiscovery from a source checkout on Windows, without installing Python system-wide.
# Uses uv (https://docs.astral.sh/uv/): winget install astral-sh.uv
#   .\zabbix-autodiscovery.ps1 init
#   .\zabbix-autodiscovery.ps1 check
#   .\zabbix-autodiscovery.ps1 scan -o inventory.csv
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$deps = Join-Path $here '.deps'

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw 'uv not found. Install it with: winget install astral-sh.uv'
}
$py = uv python find 2>$null
if (-not $py) {
    uv python install 3.12
    $py = uv python find
}
if (-not (Test-Path (Join-Path $deps 'yaml'))) {
    Write-Host 'Installing dependencies into .deps ...'
    $env:UV_LINK_MODE = 'copy'      # OneDrive/network folders do not support hard links
    uv pip install --quiet --python $py --target $deps 'pysnmp>=7.1,<8' 'PyYAML>=6.0' 'requests>=2.31'
}

$env:PYTHONPATH = "$deps;$(Join-Path $here 'src')"
$env:PYTHONUTF8 = '1'
& $py -m zabbix_autodiscovery @args
exit $LASTEXITCODE

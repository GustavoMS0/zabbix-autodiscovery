# Run zabbix-autodiscovery from a source checkout on Windows.
# Prefers uv (https://docs.astral.sh/uv/): winget install astral-sh.uv
# Or falls back to system Python (3.10+).
#   .\zabbix-autodiscovery.ps1 init
#   .\zabbix-autodiscovery.ps1 check
#   .\zabbix-autodiscovery.ps1 scan -o inventory.csv
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$deps = Join-Path $here '.deps'

$hasUv = Get-Command uv -ErrorAction SilentlyContinue
if ($hasUv) {
    $py = uv python find 2>$null
    if (-not $py) {
        uv python install 3.12
        $py = uv python find
    }
    if (-not (Test-Path (Join-Path $deps 'cryptography'))) {
        Write-Host 'Installing dependencies into .deps via uv ...'
        $env:UV_LINK_MODE = 'copy'      # OneDrive/network folders do not support hard links
        uv pip install --quiet --python $py --target $deps 'pysnmp>=7.1,<8' 'PyYAML>=6.0' 'requests>=2.31' 'cryptography>=42'
    }
} else {
    # "python" may be the Microsoft Store alias, which exists but only prints an install hint:
    # use the first candidate that really reports a Python 3 version.
    $pyCmd = $null
    foreach ($candidate in 'py', 'python', 'python3') {
        if (-not (Get-Command $candidate -ErrorAction SilentlyContinue)) { continue }
        try { $version = & $candidate --version 2>&1 | Out-String } catch { continue }   # PS 5.1 + Stop
        if ($LASTEXITCODE -eq 0 -and $version -match 'Python 3\.(1[0-9]|[2-9][0-9])') { $pyCmd = $candidate; break }
    }
    if (-not $pyCmd) {
        throw 'Neither uv nor Python was found. Install uv (winget install astral-sh.uv) or Python 3.10+.'
    }
    $py = $pyCmd
    if (-not (Test-Path (Join-Path $deps 'cryptography'))) {
        Write-Host 'Installing dependencies into .deps via pip ...'
        & $py -m pip install --quiet --target $deps 'pysnmp>=7.1,<8' 'PyYAML>=6.0' 'requests>=2.31' 'cryptography>=42'
    }
}

$env:PYTHONPATH = "$deps;$(Join-Path $here 'src')"
$env:PYTHONUTF8 = '1'
& $py -m zabbix_autodiscovery @args
exit $LASTEXITCODE

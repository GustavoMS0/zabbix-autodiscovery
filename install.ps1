# zabbix-autodiscovery installer / updater for Windows.
#
#   irm https://raw.githubusercontent.com/GustavoMS0/zabbix-autodiscovery/main/install.ps1 | iex
#
# What it does: downloads the project into %USERPROFILE%\zabbix-autodiscovery, makes sure uv or Python 3.10+
# is available and starts the interactive wizard (it only needs the Zabbix URL and an API token).
# Running it again updates the code and keeps config.yaml, .env and your CSV files.
#
# Options (environment variables, set before running):
#   $env:ZAD_DIR = 'D:\zabbix-autodiscovery'   install folder
#   $env:ZAD_REF = 'v0.2.0'                    branch or tag (default: main)
#   $env:ZAD_NO_WIZARD = '1'                   install/update only
$ErrorActionPreference = 'Stop'
$Repo = 'GustavoMS0/zabbix-autodiscovery'
$Ref = if ($env:ZAD_REF) { $env:ZAD_REF } else { 'main' }
$Dir = if ($env:ZAD_DIR) { $env:ZAD_DIR } else { Join-Path $HOME 'zabbix-autodiscovery' }

function Say($text) { Write-Host "==> $text" -ForegroundColor Cyan }

function Test-RealPython {
    # "python" may be the Microsoft Store alias, which exists but only prints an install hint
    foreach ($candidate in 'py', 'python', 'python3') {
        if (-not (Get-Command $candidate -ErrorAction SilentlyContinue)) { continue }
        try { $version = & $candidate --version 2>&1 | Out-String } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $version -match 'Python 3\.(1[0-9]|[2-9][0-9])') { return $true }
    }
    return $false
}

Say "Downloading $Repo ($Ref) into $Dir"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("zad-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $zip = Join-Path $tmp 'source.zip'
    Invoke-WebRequest -Uri "https://github.com/$Repo/archive/$Ref.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath $tmp
    $src = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    # config.yaml, .env and *.csv are not part of the repository, so an update never overwrites them
    Copy-Item -Path (Join-Path $src.FullName '*') -Destination $Dir -Recurse -Force
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
Get-ChildItem -Path $Dir -Recurse -File | Unblock-File -ErrorAction SilentlyContinue

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    $localUv = Join-Path $HOME '.local\bin'
    if (Test-Path (Join-Path $localUv 'uv.exe')) { $env:Path = "$localUv;$env:Path" }
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue) -and -not (Test-RealPython)) {
    $answer = Read-Host 'Neither uv nor Python 3.10+ was found. Install uv now with winget? [y/N]'
    if ($answer -notmatch '^[yYsS]') { throw 'Install uv (winget install astral-sh.uv) or Python 3.10+ and run again.' }
    winget install --id astral-sh.uv -e --accept-source-agreements --accept-package-agreements
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'User') + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine')
}

$runner = Join-Path $Dir 'zabbix-autodiscovery.ps1'
$shell = (Get-Process -Id $PID).Path                       # same PowerShell (5.1 or 7) that runs this script
Set-Location $Dir
& $shell -NoProfile -ExecutionPolicy Bypass -File $runner --version
if ($env:ZAD_NO_WIZARD) {
    Say "Done. Start the wizard with: cd '$Dir'; .\zabbix-autodiscovery.ps1 wizard"
    return
}
Say "Starting the wizard (Ctrl+C to quit; run it again later with: .\zabbix-autodiscovery.ps1 wizard)"
& $shell -NoProfile -ExecutionPolicy Bypass -File $runner wizard

<#
.SYNOPSIS
  Sets Hostname= in the Zabbix agent (or agent 2) config to the computer's name and restarts the agent.

.DESCRIPTION
  Use it when "zabbix-autodiscovery audit" reports "Agent Hostname= different from the Zabbix host name",
  a common leftover of cloned VMs or copied config files. The Zabbix host's technical name must be equal
  to the value written here (by default the computer name).

  Local (as Administrator, on the server):
    .\fix-agent-hostname.ps1 -WhatIf
    .\fix-agent-hostname.ps1

  Remote WITHOUT WinRM (uses the C$ admin share, TCP 445, and the Service Control Manager, TCP 135):
    .\fix-agent-hostname.ps1 -ComputerName SRV01,SRV02 -WhatIf
    .\fix-agent-hostname.ps1 -ComputerName SRV01,SRV02

  A timestamped backup of each config is kept next to it.

.PARAMETER ComputerName
  Remote servers. Hostname= is set to each server's name (upper case) unless -Hostname is given.

.PARAMETER Hostname
  Value to write. Defaults to the computer name.

.PARAMETER ConfigPath
  Explicit config file (skips auto-detection; mainly for testing).

.PARAMETER WhatIf
  Only show what would change.
#>
param(
    [string[]]$ComputerName,
    [string]$Hostname,
    [string]$ConfigPath,
    [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'

$Agents = @(
    @{ Path = 'Zabbix Agent 2\zabbix_agent2.conf'; Service = 'Zabbix Agent 2' },
    @{ Path = 'Zabbix Agent\zabbix_agentd.conf';   Service = 'Zabbix Agent' }
)

function Find-Agent([string]$Computer) {
    if ($ConfigPath) { return @{ Conf = $ConfigPath; Service = 'Zabbix Agent 2' } }
    $base = if ($Computer) { "\\$Computer\C$\Program Files" } else { $env:ProgramFiles }
    foreach ($a in $Agents) {
        $conf = Join-Path $base $a.Path
        if (Test-Path -LiteralPath $conf) { return @{ Conf = $conf; Service = $a.Service } }
    }
    throw "Zabbix agent config not found under $base"
}

function Restart-Agent([string]$Computer, [string]$Service) {
    if (-not $Computer) {
        Restart-Service -Name $Service
        Start-Sleep -Seconds 3
        return (Get-Service -Name $Service).Status.ToString()
    }
    $target = "\\$Computer"
    & sc.exe $target stop "$Service" | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        if ((& sc.exe $target query "$Service") -match 'STOPPED') { break }
        Start-Sleep -Seconds 1
    }
    & sc.exe $target start "$Service" | Out-Null
    Start-Sleep -Seconds 3
    if ((& sc.exe $target query "$Service") -match 'RUNNING') { return 'Running' }
    return 'NotRunning'
}

function Set-AgentHostname([string]$Computer) {
    $label = if ($Computer) { $Computer } else { $env:COMPUTERNAME }
    $value = if ($Hostname) { $Hostname } elseif ($Computer) { $Computer.Split('.')[0].ToUpper() } else { $env:COMPUTERNAME }
    $agent = Find-Agent $Computer
    $lines = [System.IO.File]::ReadAllLines($agent.Conf)
    $current = $lines | Where-Object { $_ -match '^\s*Hostname\s*=' } | Select-Object -First 1

    Write-Host "[$label] config : $($agent.Conf)"
    Write-Host "[$label] before : $(if ($current) { $current.Trim() } else { '(no Hostname= line)' })"
    Write-Host "[$label] after  : Hostname=$value"
    if ($current -and $current.Trim() -eq "Hostname=$value") { Write-Host "[$label] already correct"; return }
    if ($WhatIf) { return }

    Copy-Item -LiteralPath $agent.Conf -Destination "$($agent.Conf).bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
    if ($current) {
        $lines = $lines | ForEach-Object { if ($_ -match '^\s*Hostname\s*=') { "Hostname=$value" } else { $_ } }
    } else {
        $lines = @($lines) + "Hostname=$value"
    }
    # UTF-8 without BOM: a BOM on the first line can break the agent's config parser
    [System.IO.File]::WriteAllLines($agent.Conf, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    if ($ConfigPath) { Write-Host "[$label] written (test mode, service not restarted)"; return }

    $status = Restart-Agent $Computer $agent.Service
    Write-Host "[$label] service '$($agent.Service)': $status"
    if ($status -ne 'Running') { Write-Warning "[$label] the agent did not start: restore the .bak file and check the agent log" }
}

if ($ComputerName) {
    foreach ($c in $ComputerName) {
        try { Set-AgentHostname $c } catch { Write-Warning "[$c] $($_.Exception.Message)" }
    }
} else {
    Set-AgentHostname $null
}

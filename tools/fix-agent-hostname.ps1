<#
.SYNOPSIS
  Sets Hostname= in the Zabbix agent (or agent 2) config to this computer's name and restarts the agent.

.DESCRIPTION
  Use it when "zabbix-autodiscovery audit" reports "Agent Hostname= different from the Zabbix host name",
  a common leftover of cloned VMs or copied config files. The Zabbix host's technical name must be equal
  to the value written here (by default the computer name).

  Run as Administrator on the server, or remotely:
    Invoke-Command -ComputerName SRV01,SRV02 -FilePath .\fix-agent-hostname.ps1

  A timestamped backup of the config is kept next to it.

.PARAMETER Hostname
  Value to write. Defaults to the computer name.

.PARAMETER WhatIf
  Only show what would change.
#>
param(
    [string]$Hostname = $env:COMPUTERNAME,
    [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'

$candidates = @(
    @{ Conf = "$env:ProgramFiles\Zabbix Agent 2\zabbix_agent2.conf"; Service = 'Zabbix Agent 2' },
    @{ Conf = "$env:ProgramFiles\Zabbix Agent\zabbix_agentd.conf";   Service = 'Zabbix Agent' }
)
$agent = $candidates | Where-Object { Test-Path $_.Conf } | Select-Object -First 1
if (-not $agent) { throw "Zabbix agent config not found under $env:ProgramFiles" }

$lines = [System.IO.File]::ReadAllLines($agent.Conf)
$current = ($lines | Where-Object { $_ -match '^\s*Hostname\s*=' } | Select-Object -First 1)
Write-Host "Config : $($agent.Conf)"
Write-Host "Before : $(if ($current) { $current.Trim() } else { '(no Hostname= line; agent uses HostnameItem or system.hostname)' })"
Write-Host "After  : Hostname=$Hostname"

if ($current -and $current.Trim() -eq "Hostname=$Hostname") {
    Write-Host 'Already correct, nothing to do.'
    return
}
if ($WhatIf) { return }

Copy-Item $agent.Conf "$($agent.Conf).bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
if ($current) {
    $lines = $lines | ForEach-Object { if ($_ -match '^\s*Hostname\s*=') { "Hostname=$Hostname" } else { $_ } }
} else {
    $lines = @($lines) + "Hostname=$Hostname"
}
# UTF-8 without BOM: a BOM on the first line can break the agent's config parser
[System.IO.File]::WriteAllLines($agent.Conf, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))

Restart-Service -Name $agent.Service
Start-Sleep -Seconds 3
$status = (Get-Service -Name $agent.Service).Status
Write-Host "Service '$($agent.Service)': $status"
if ($status -ne 'Running') { throw "The agent did not start. Restore the .bak file and check the agent log." }

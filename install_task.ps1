# Register the DDNS panel to start automatically.
#
# ASCII only: PowerShell 5.1 reads UTF-8 without BOM as GBK, which mangles
# any non-ASCII byte in this file.
#
# Two modes:
#   .\install_task.ps1                 -> per-user task, starts at logon
#   .\install_task.ps1 -System         -> machine-wide task, starts at boot
#                                         (must run from an elevated shell)
#   .\install_task.ps1 -Uninstall      -> remove the per-user task
#   .\install_task.ps1 -System -Uninstall

param(
    [switch]$System,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

$taskName = if ($System) { 'DDNS-Panel-System' } else { 'DDNS-Panel' }
$script   = 'D:\Projects\ddns-panel\run.ps1'
$runner   = 'powershell.exe'
$arg      = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $script

function Remove-Task {
    param([string]$name)
    Write-Host "removing task: $name"
    & schtasks.exe /delete /tn $name /f 2>&1 | Out-String | Write-Host
}

if ($Uninstall) {
    Remove-Task $taskName
    Write-Host 'done.'
    exit 0
}

if (-not (Test-Path $script)) {
    Write-Error "run.ps1 not found: $script"
    exit 1
}

if ($System) {
    $id  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr  = New-Object Security.Principal.WindowsPrincipal($id)
    $adm = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $pr.IsInRole($adm)) {
        Write-Error 'The -System task needs an elevated PowerShell. Right-click, Run as administrator.'
        exit 1
    }

    # SYSTEM starts with no profile and cannot read the encrypted master key
    # or write the SQLite db until it is granted access. Skip this and the
    # panel silently fails to decrypt every stored credential.
    Write-Host 'granting SYSTEM access to the data directory...'
    & icacls.exe 'D:\ddns-panel-data' /grant 'SYSTEM:(OI)(CI)(M)' 2>&1 | Out-String | Write-Host
    & icacls.exe 'D:\ddns-panel-data\master.key' /grant 'SYSTEM:(R)' 2>&1 | Out-String | Write-Host

    Write-Host "creating boot task: $taskName"
    & schtasks.exe /create /tn $taskName /tr "$runner $arg" /sc onstart /ru SYSTEM /rl highest /f 2>&1 | Out-String | Write-Host
} else {
    Write-Host "creating logon task: $taskName"
    & schtasks.exe /create /tn $taskName /tr "$runner $arg" /sc onlogon /rl limited /f 2>&1 | Out-String | Write-Host
}

Write-Host ''
Write-Host '--- task status ---'
& schtasks.exe /query /tn $taskName /fo list 2>&1 | Out-String | Write-Host
Write-Host 'Panel URL: http://127.0.0.1:8300'

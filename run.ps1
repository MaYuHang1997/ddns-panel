# Start the DDNS panel.
# Uses the uv-managed Python 3.12 interpreter because the system Python 3.13
# on this machine cannot install packages (pip resolution fails).
# ASCII only: PowerShell 5.1 reads unbommed UTF-8 as GBK.

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

# Runtime data (SQLite db + AES master key) lives outside this repo on purpose:
# it must never be committed or pushed. Override via env var if you relocate it.
if (-not $env:DDNS_DATA_DIR) {
  $env:DDNS_DATA_DIR = 'D:\ddns-panel-data'
}
Write-Host "data   : $env:DDNS_DATA_DIR"

$candidates = @(
  'C:\Users\myh\AppData\Roaming\uv\python\cpython-3.12.14-windows-x86_64-none\python.exe'
)

$python = $null
foreach ($c in $candidates) {
  if (Test-Path $c) { $python = $c; break }
}

if (-not $python) {
  # Fall back to any uv-managed interpreter that has fastapi installed.
  $found = Get-ChildItem -Path "$env:APPDATA\uv\python" -Filter python.exe -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($found) { $python = $found.FullName }
}

if (-not $python) {
  Write-Error 'Python interpreter not found. Install one with fastapi + uvicorn.'
  exit 1
}

Write-Host "python : $python"
Write-Host "cwd    : $here"
Write-Host "url    : http://127.0.0.1:8300"
Write-Host ''

# Refuse to start a second instance. Without this, a logon task firing while
# the panel is already up just dies with "address already in use".
$busy = Get-NetTCPConnection -State Listen -LocalPort 8300 -ErrorAction SilentlyContinue
if ($busy) {
  $pids = ($busy.OwningProcess | Select-Object -Unique) -join ','
  Write-Host "port 8300 already in use by pid $pids - panel is running, exiting."
  exit 0
}

& $python -m uvicorn app:app --host 127.0.0.1 --port 8300 --log-level info

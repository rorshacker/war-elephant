$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
$env:PYTHONPATH = "backend"
if (Test-Path .venv\Scripts\python.exe) { $python = ".\.venv\Scripts\python.exe" } else { $python = "python" }
& $python -m fleetguard serve

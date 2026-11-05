$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip download -r requirements.txt -d offline\wheels
.\.venv\Scripts\python -m pip install --no-index --find-links offline\wheels -r requirements.txt
if (Get-Command npm -ErrorAction SilentlyContinue) {
  Push-Location frontend
  npm ci
  npm run build
  Pop-Location
} else {
  Write-Host "npm was not found. Install Node from the prepared archive, then run npm ci and npm run build in frontend."
}
Write-Host "Offline bundle is in offline\wheels. Copy the whole FleetGuard directory into the enclave."

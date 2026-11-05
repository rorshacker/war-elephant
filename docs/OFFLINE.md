# Offline installation

Prepare this on a connected machine. The enclave copy must not download packages.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\prepare_offline.ps1
```

That creates `.venv`, downloads wheels into `offline\wheels`, and installs from those wheels. Build the UI while online:

```powershell
cd frontend
npm ci
npm run build
```

Copy the whole `FleetGuard` directory, including `.venv`, `offline\wheels`, `frontend`, and `backend\fleetguard\static`.

Inside the enclave:

```powershell
.\.venv\Scripts\python -m pip install --no-index --find-links offline\wheels -r requirements.txt
$env:PYTHONPATH = "backend"
$env:FLEETGUARD_DATA_DIR = "data"
$env:FLEETGUARD_LAB_ROOT = "data\lab"
python -m fleetguard diag
python -m fleetguard serve
```

Runtime code does not call pip, npm, or a guidance site. `ldap3` is included so a later lab directory test can import it; live query still requires `FLEETGUARD_ENABLE_LIVE_LDAP=1`, an approved controller, and a valid TLS certificate.

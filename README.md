# War Elephant

Offline-first workbench for preparing STIG baselines and a ship inventory on a connected machine, then running approved discovery, assessment, and a narrow lab change inside an isolated enclave.

War Elephant does not call the network for guidance, packages, or models at runtime. Live directory query is off unless `FLEETGUARD_ENABLE_LIVE_LDAP=1`. The only implemented configuration change writes one key in a lab file under the configured lab root.

## Run

```powershell
python -m pip install -r requirements.txt
$env:PYTHONPATH = "backend"
python -m fleetguard init
python -m fleetguard serve
```

Open `http://127.0.0.1:8000` after the React bundle is built. Until then, the API is at `/api/health`.

```powershell
cd frontend
npm ci
npm run build
```

Default bind address is loopback. Set `FLEETGUARD_HOST` only when another management workstation in the enclave must reach it.

## Tests

```powershell
$env:PYTHONPATH = "backend"
python -m pytest -q -p no:cacheprovider
```

The suite uses synthetic fixtures and loopback probes. It does not scan external networks or change a remote operating system.

## Layout

- `backend/fleetguard` API, SQLite migrations, adapters, audit chain
- `frontend` React operator console
- `fixtures` synthetic XCCDF, CSV, XLSX, and directory cache
- `docs` demo, offline install, capability matrix, transition plan

See `docs/DEMO.md` for the click path and `docs/CAPABILITIES.md` for what is real.

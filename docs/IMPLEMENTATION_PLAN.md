# Implementation plan

Milestone 1 is implemented: FastAPI and SQLite, STIG ZIP/XML import, CSV/XLSX preview and commit, synthetic fixtures, reconciliation, baseline confirmation, audit events, and CSV/JSON export.

Milestone 2 is implemented for local sessions, an encrypted vault, approved scope enforcement, cached directory snapshots, and bounded TCP probes. Live LDAPS is coded with certificate validation forced on, and it stays disabled unless explicitly enabled. No lab controller was contacted.

Milestone 3 is implemented for one reversible lab-file change: proposal hash, human approval, drift check, backup, verification, separate rollback approval, and ambiguous-outcome recovery. Windows, Linux SSH, and network-device adapters expose interfaces and refuse execution.

Milestone 4 is implemented for the sync outbox and local receiver. Offline wheel download is scripted. A one-page transition note is in `docs/FLEET_TRANSITION.md`.

Still simulated or absent:

- Publisher signature verification
- An independent audit signer
- Live Active Directory against a domain controller
- Windows, Linux, and vendor-device changes
- Parallel discovery
- Automatic reconnect execution, which is intentionally absent

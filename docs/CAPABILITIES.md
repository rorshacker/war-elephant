# Capabilities

| Capability | Status |
| --- | --- |
| STIG ZIP and XCCDF import, multiple versions, checksum versus authenticity | Implemented and tested |
| CSV and XLSX preview, mapping, validation, explicit commit | Implemented and tested |
| Reconciliation without IP-only merges | Implemented and tested |
| Deterministic baseline recommendation and recorded override | Implemented and tested |
| Proof-of-concept console | No sign-in and no stored secret. The lab-file change uses the recorded approval only |
| Safety case | Documented in `docs/SAFETY_CASE.md`. Lab-file controls are tested. Shipboard hazards are not met, and there is no independent acceptance |
| Local operator session | API remains; the console does not ask for an account |
| Encrypted vault | API remains; the console and the lab-file change do not use it |
| Approved, expiring discovery scope | Implemented and tested |
| TCP connect inside that scope | Implemented and tested on loopback |
| Live LDAPS | Library present, TLS bypass refused, disabled by default, no controller test |
| Cached directory and observation import | Implemented and tested |
| Automated check registry | One lab-file rule; other imported rules stay manual |
| Lab-file change, backup, drift block, verification, separate rollback | Implemented and tested |
| Automated remediation gate | Off. Assessment non-mutation, no arbitrary command execution, the single tested lab action, explicit maintenance authorization, a scheduling stop, and the audit record are met. Canary limits, kill switch, out-of-band recovery, dependency limits, a representative lab, publisher signatures, and a separate owner runbook approval are not met |
| Windows management | Interface only |
| Linux SSH | Interface only; connectivity-changing action is blocked; no live SSH |
| Network devices | Interface only |
| Hash-linked audit log and unsigned checkpoint | Implemented and tested |
| Independent signature | Extension point only |
| JSON and CSV reports, formula-prefixing | Implemented and tested |
| Sync outbox and idempotent receiver | Implemented and tested; receive never executes. Delivery can defer a record that exceeds a byte budget |
| Offline range evidence | Implemented and tested: imported snapshot, packages, container record, log, network rule, and host setting. Detectors are an explicit registry. Findings name the asset, rule or synthetic CVE, evidence line, and commander, system owner, and data owner statements |
| Procedure plan | Implemented and tested for failed imported evidence. Approval records the plan as not executed. The lab-file adapter remains the only change that writes a file |
| React console | Source included; bundle produced by the local frontend build |

Evidence shown as `real` was read from a bound lab file or from a TCP probe the operator started. `imported` and `cached` are files or snapshots the operator supplied. The application does not fill those fields with simulated scan results.

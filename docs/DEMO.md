# Demo script

Use only the synthetic fixtures. Do not point discovery at a production range.

1. `python -m fleetguard serve` and open the console. This proof of concept has no sign-in and stores no secrets.
2. Preparation: choose **Load synthetic training data** and confirm. Review the package row. Authenticity stays `not_verified`. Windows 10 version 2 is the newest imported version; version 1 remains.
3. Inventory: reconcile. `LAB-WIN` is a single documented workstation. `WS-ALPHA` is a provisional hostname match with directory data. `WS-DUP` shares an address and stays separate. `SW-01` is a switch with no directory object expected.
4. Select `LAB-WIN`. On Baselines, confirm the recommended Windows 10 import.
5. Findings: assess selected assets. `FG-WIN10-AUDIT-POLICY` fails from the real lab file. Banner and screen rules stay `not_reviewed`.
6. Approvals: propose the failed rule. Approve the displayed hash. This does not change the file.
7. Execution: classify `LAB-WIN` as approved noncritical, open a STIG configuration window, then execute the approved change. The lab file key becomes `enabled`, with status `verified_success` and `remote_atomic` false.
8. Propose rollback, approve that new hash, and execute it. The lab file returns to `disabled`.
9. Audit: verify the chain, export checkpoint, and queue a local sync delivery. The delivery count of executed changes stays 0.

Range path, still synthetic and still offline:

10. Range: **Load seeded scenario**. The score lists CVE-SYNTH-2026-0001, CONTAINER-PRIVILEGED, NET-PERMIT-ANY, HOST-AUDIT-POLICY, and LOG-PRIVILEGED-LOGIN. A specific firewall permit and a routine log line are not findings.
11. Approvals: propose one failed evidence finding and approve its hash. The score then has a time from import to that approval.
12. Execution: for a procedure, choose **Record plan, do not execute**. The status is `not_executed`.
13. Range: set a small link budget and deliver. A record larger than the budget stays deferred. Executed stays 0. A later delivery with a larger budget can send it. The receiver still applies nothing.

The bulletin file is a synthetic snapshot with a made-up identifier. It is not an NVD download. The Windows 11 benchmark file in `fixtures/range` is a stand-in id so the catalog can recommend `Windows_11_STIG` after that file is imported. It is not DISA text.

Optional: approve only `127.0.0.1/32`, then run a TCP probe. A closed port is recorded as refused or timed out, not as proof the host is absent.

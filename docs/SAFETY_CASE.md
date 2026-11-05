# Safety case for the lab pilot

This is not an acceptance report. No platform-engineering, operational, cybersecurity, or independent reviewer has signed it. The proof of concept does not decide that a system is safe to modify. Air-gapping does not change that.

A successful lab-file write is not evidence that a shipboard patch is safe. Stop, rollback, and restore are different operations. The controller does not stop an in-progress write, does not roll it back by itself, and does not treat an uncertain result as a failure to retry.

## Pilot boundary

The only registered change sets `audit_policy` in one local file, `fleetguard-lab.conf`, for an asset a person has classed `approved_noncritical`, during a current 1–8 hour `stig_config` maintenance authorization, after a person approves the exact proposal hash, and only while scheduling is not halted.

Patch and firmware have no deployer. Procedure proposals record a plan and do not touch the file. Imported fix text is stored and never executed. There is no model call on this path.

Anything outside that sentence is a no-go, including a host, a cluster, a reboot, a service restart, and a controller self-update.

## Go / no-go

A person sets these criteria. The software enforces the checks it has. It does not invent the missing ones, and it does not treat a missing check as a pass.

Go, for the lab file only, when every item below is true:

- A person recorded the class. The class was not inferred from the operating system.
- The class is `approved_noncritical`.
- The change type on the hash is `stig_config`.
- A current maintenance authorization names that asset and that change type.
- Scheduling is not halted.
- The stored proposal still hashes to the value the approval recorded.
- The file hash still equals `expected_start_hash`.
- The action is the one registered lab-file key.

No-go for this pilot when any of those is false. No-go for any wider use until the hazard rows marked not met have an owner, a test, and a recorded review. There is no force-deployment switch.

## Hazard register

| Hazard | Prevention in this build | Detection | Recovery | Evidence | Status |
| --- | --- | --- | --- | --- | --- |
| Wrong file is changed | Proposal identity stores asset id, address, and lab path. Execution refuses the write if any of those differ. Inventory does not merge on address alone. | Hash mismatch or identity mismatch returns 409 and does not start the write. | No file change, so no restore. | `test_change_controls`, `test_reconciliation_does_not_merge_on_ip_alone` | Met for the lab file only |
| Stale or altered proposal is approved or run | Approval and execution recompute the canonical hash, including change type. A proposal saved before change type was covered cannot be approved or run. | 409. The console hides Execute on that record. | Propose the finding again. The old approval is not reused. | `test_change_controls` alters a proposal and expects 409 | Met for hash binding |
| Change starts without authority | Class, change type, maintenance window, unused approval, and scheduling halt are checked before the write. | 409 before the file is opened for write. | Nothing was written. | `test_change_controls` | Met for the lab file |
| Write outcome is uncertain | The intent row is committed before the file write. If the process cannot confirm the result, the row stays `intent`. | Audit event `execution.ambiguous`. Recover report lists intent rows. | A person reads the file. The controller does not retry and does not roll back. | `test_ambiguous_execution_is_not_retried` | Met for the lab file |
| File changed underneath the proposal | Execution compares the current file hash with `expected_start_hash` before writing. | 409, execution list stays empty. | The drifted bytes are left in place. | `test_change_controls` | Met for the lab file |
| Rollback is applied to the wrong bytes | Rollback is a new proposal and a new approval. It is refused while the current hash differs from the recorded post-change hash, and it is refused while status is still `intent`. | 409 `intervening change` or the ambiguous-recovery message. | Manual recovery. Automatic restore is not attempted. | `test_change_controls` | Met for the lab file |
| Imported instructions run as commands | No shell, `eval`, or execution of imported fix text. | Source check refuses those calls. | Not required. The text is never started. | `test_source_has_no_shell_execution` | Met |
| Assessment mutates the target | Assessment reads the lab file and compares bytes before and after. | Test fails if the bytes change. | Not required on that path. | `test_change_controls` | Met for the lab file |
| Unexecuted plan is counted as a change | Procedure record writes `not_executed` and does not touch the file. Execute on a procedure is refused. | Range score keeps `plans_executed` at 0. | Not required. | `test_seeded_range_scores_and_records_an_unexecuted_plan` | Met |
| Sync delivery applies a change | Delivery copies records and reports `executed: 0`. | Test asserts that count. | Not required. | `test_link_budget_defers_without_executing` | Met |
| Loss of essential service or management access | The lab action sets `connectivity_risk` to 0. A connectivity-risk action without automatic recovery is refused. Windows, SSH, and network adapters do not run. | Adapter status is `not_implemented`. | No host session is opened. | `test_other_adapters_do_not_pretend_to_run` | Not met for a host |
| Partial installation and interrupted reboot | The lab action does not reboot. There is no `INSTALLING`, `REBOOT_PENDING`, or `VERIFYING` state for a host installer. | A lab write that cannot be confirmed stays `intent`. A timeout is not modeled. | Uncertain stays uncertain. | Lab-file test only | Not met for an installer |
| Loss of redundancy or a shared failure domain | None. There is no dependency graph, quorum check, or power-domain check. | The remediation gate reports `dependency_graph` not met. | None. | Gate payload in `test_change_controls` | Not met |
| Invalid or inapplicable finding | The lab rule reads one key. Range findings come from seeded files. There is no vendor-advisory, backport, cumulative-patch, firmware, or end-of-life check. | Evidence kind is `real` or `imported`, never a fabricated scan. | A person can reject the hash. | Range score test | Not met |
| Unreachable asset marked compliant | This build has no compliant default for an asset that was not assessed. | Absence of a finding is not a pass. | Leave it unassessed. | No dedicated unreachable-asset test | Not met as a stated control |
| Controller is the failure point | The console has no accounts and no stored secret. One local process can approve and write the lab file. The audit chain can show tampering of its own events. A checkpoint says a privileged local attacker is outside that guarantee. | `test_audit_sync_and_exports` flips one event and verification fails. | Restore the database from a copy a person kept. Controller backup is not a product feature. | Audit test | Not met for a ship |
| Competing controller or duplicate job | An approval is marked used when the intent is written. A second execute of that approval is 409. | Replay assertion in `test_change_controls`. | The second call does not write again. | That test | Partial. No cross-host lock. |
| Deferred reboot, service restart, first-boot task, or failover activation | None. The maintenance window covers the moment of the lab write only. | None. | None. | None | Not met |
| Mixed versions must move together | None. The planner cannot block a rolling sequence. | None. | None. | None | Not met |
| Signing-key revocation, clock drift, expired bundle, content downgrade | Approvals and maintenance windows expire by local timestamp. Imports store a checksum. Sequence numbers exist on audit events. | Expired approval is 409. Checksum is labeled `not_verified`. | A person imports a new file or approves a new hash. Downgrade prevention is not separate from an approved restore. | `test_change_controls` expiry case; package authenticity stays `not_verified` | Not met |
| Power, disk, thermal, or people not ready | The lab write checks that the file is still a file and the directory exists. | Verification can return `inconclusive` if that check fails. | No automatic restore. | No power or storage test | Not met |
| Service responds but data is wrong | Verification checks `audit_policy` and the file hash. | `verified_failure` if the key is wrong. | Separate approved rollback, and only if the post-change hash is unchanged. | `test_change_controls` | Not met for application behavior |
| Model recommends a bad change, or collected content contains instructions | No model produces the lab plan. Collected content is not executed. | Source and import tests. | Not required on this path. | `test_source_has_no_shell_execution` | Model qualification is not met, because no model is in the pilot |
| Emergency exception becomes a standing bypass | There is no force-deployment control. | Code inspection. | Not applicable. | No emergency-authorization record exists | The missing switch is intentional. The emergency procedure is not defined. |

Responsible owner for every row: unassigned. A name in the console is not an operational authority.

## Deployment states

The lab file uses these records.

| State | Meaning | Allowed next step |
| --- | --- | --- |
| No intent | Checks failed, or the person has not started the change. | Fix the failed check. The file is unchanged. |
| `intent` | The approval was consumed and the outcome is not confirmed. | A person inspects the file. No retry. No automatic rollback. |
| `failed` | The failure happened before the file bytes changed. | Propose again if the hash is still valid. |
| `verified_success` | The key and the file are what the proposal named. | Leave it, or propose a separate rollback. |
| `verified_failure` | The write finished and the key is not the expected value. | Separate rollback proposal, if the post-change hash is unchanged. |
| `inconclusive` | The file or directory check did not pass. | Manual recovery. |
| `not_executed` | A procedure plan was recorded. | None. Execute is refused. |

`INSTALLING`, `REBOOT_PENDING`, `VERIFYING`, and `OUTCOME_UNKNOWN` are not implemented. A timeout is not classified. Adding those names without a host installer would be a label, not a control.

Stop means scheduling halt: new work does not start, and an in-progress lab write is not killed. Rollback means a new hash and a new approval that restores the backup only when the current bytes still match the recorded result. Restore of the controller database is a person copying a database file. Those three are not one button.

## Eligibility

A finding may become a lab change only when the rule is the registered lab-file rule and the asset baseline was confirmed or explicitly overridden. Range evidence becomes a procedure plan, not a write.

An installed package, a seeded log line, or a newest imported benchmark is not proof of remediation. The lab change counts only after the file is read again. Publisher signature, feed age, superseded patches, backported fixes, firmware applicability, and conflicting scanners are not decided here.

## Recovery runbook for the lab file

This runbook is the local file only. It has automated tests. It has not been walked through on a disconnected ship, and out-of-band recovery is not met.

1. Read `fleetguard-lab.conf` and the execution row before doing anything else.
2. If status is `intent`, leave the file as it is. Do not run the change again and do not restore the backup from this console.
3. If status is `verified_success` or `verified_failure` and the file hash still equals the recorded post-change hash, propose rollback, approve that new hash, and execute that proposal.
4. If the file hash has moved again, the console will refuse the rollback. Keep the current bytes and recover by hand.
5. Scheduling halt is available the whole time. It does not undo the file.
6. Sync delivery does not apply any of these steps on the receiver.

## Failure injection that exists

The pytest suite injects these failures against the lab file and the local database:

- Approval missing, expired, reused, or bound to a proposal whose body changed.
- Asset class still unknown, scheduling halted, and file drift before the write.
- Crash after the write, leaving `intent`, with a second execute refused.
- Procedure execute refused.
- Tampered audit event.
- Delivery that cannot fit the byte budget, with executed still 0.

No test injects power loss, a reboot, a revoked signing key, a drifted clock, a split cluster, or a second controller.

## Traceability

Each hazard row above is the chain the review asked for: hazard, the control this build actually has, the test that exercises it, and the evidence status. The approval column is empty. Independent review has not been done.

STIG import and a failed lab rule do not authorize a deployment.

## What stays out of the next code change

Do not add a deployer for patch or firmware, a force switch, a self-update, a model that selects targets, or a button that combines stop with rollback. The next evidence for a wider pilot is an owner for each not-met row, a test that fails closed, and a review by someone who does not maintain this code.

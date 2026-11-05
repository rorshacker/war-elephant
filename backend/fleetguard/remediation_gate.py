from __future__ import annotations


def remediation_gate() -> dict:
    requirements = [
        {
            "id": "assessment_only",
            "requirement": "Assessment-only mode verified not to invoke mutating actions.",
            "status": "met",
            "evidence": "Assessment reads the bound lab file and records findings. It does not write that file.",
        },
        {
            "id": "no_ai_commands",
            "requirement": "No arbitrary AI-generated commands can execute.",
            "status": "met",
            "evidence": "Imported fix text and model output have no execution path. The only write is the registered lab-file key.",
        },
        {
            "id": "tested_action",
            "requirement": "Every automated action has tested preconditions, health checks, and recovery behavior.",
            "status": "met",
            "evidence": "The one registered action checks the file hash, verifies the key after writing, and uses a separate approved rollback. No other action is registered.",
        },
        {
            "id": "canary",
            "requirement": "Canary deployment and dependency-aware concurrency limits work.",
            "status": "not_met",
            "evidence": "No canary target selection or concurrency limit is implemented.",
        },
        {
            "id": "kill_switch",
            "requirement": "Kill switch and crash recovery have been tested.",
            "status": "not_met",
            "evidence": "An interrupted discovery job is marked interrupted. An in-flight lab write has no tested kill switch, and a crash after the intent is recorded does not roll back by itself.",
        },
        {
            "id": "maintenance_window",
            "requirement": "High-risk actions require explicit approval and a maintenance window.",
            "status": "met",
            "evidence": "A lab change requires a matching approval and a current maintenance authorization for that asset and change type. The controller does not reboot a target.",
        },
        {
            "id": "recovery_demonstrated",
            "requirement": "Backups and out-of-band recovery have been demonstrated.",
            "status": "not_met",
            "evidence": "The lab change writes a backup and can restore it through a separate approval. Out-of-band recovery has not been demonstrated.",
        },
        {
            "id": "audit_record",
            "requirement": "Audit records capture evidence, approvals, action versions, changes, and results.",
            "status": "met",
            "evidence": "The hash chain records the proposal, approval, execution intent, verification result, and rollback as separate events.",
        },
        {
            "id": "owner_runbook",
            "requirement": "Operations and application owners approve the rollout and recovery runbook.",
            "status": "not_met",
            "evidence": "One operator approves the proposal hash. A separate owner acceptance of the rollout and recovery runbook is not recorded.",
        },
        {
            "id": "dependency_graph",
            "requirement": "Dependency and failure-domain limits prevent paired, quorum, and capacity failures.",
            "status": "not_met",
            "evidence": "Assets are a reconciled inventory. There is no dependency graph, quorum check, or failover demonstration.",
        },
        {
            "id": "representative_lab",
            "requirement": "Representative testing decides pass or fail from predefined tests.",
            "status": "not_met",
            "evidence": "The lab target is one configuration file. It does not represent firmware, workload, segmentation, or an observation period.",
        },
        {
            "id": "supply_chain",
            "requirement": "Offline imports validate publisher signatures, provenance, and feed age.",
            "status": "not_met",
            "evidence": "A checksum is recorded. It is not publisher authentication, and vulnerability-feed age is not shown.",
        },
        {
            "id": "stop_control",
            "requirement": "An operator stop control halts new work without killing an active installation.",
            "status": "met",
            "evidence": "Stopping scheduling blocks a new change. It does not interrupt a write that has already started.",
        },
    ]
    return {
        "automated_remediation": False,
        "statement": "Automated remediation is off. A person can still approve one lab-file change. Unattended remediation stays disabled until every condition is met.",
        "requirements": requirements,
    }

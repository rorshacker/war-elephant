from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .adapters import LocalFileAdapter, read_config
from .audit import append_event
from .boundary import assert_deployment_allowed
from .db import Database
from .discovery import target_allowed
from .policy import PolicyError
from .util import canon, new_id, parse_time, sha256_text, utcnow

LOCAL = LocalFileAdapter()


def create_credential(db, vault, actor: str, label: str, purpose: str, adapter: str, secret: str, scope: dict) -> dict:
    if purpose not in {"discovery", "remediation"}:
        raise PolicyError("purpose must be discovery or remediation")
    if adapter not in {"ldap", "local_lab_file", "windows", "linux_ssh", "network_device"}:
        raise PolicyError("unknown adapter")
    if not label or not secret:
        raise PolicyError("label and secret are required")
    if not isinstance(scope, dict):
        raise PolicyError("credential scope is required")
    credential_id = new_id()
    vault.put_secret(credential_id, secret)
    created = utcnow()
    try:
        with db.transaction() as tx:
            tx.execute(
                """
                INSERT INTO credential_meta (id, label, purpose, adapter, scope_json, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (credential_id, label, purpose, adapter, json.dumps(scope), created, actor),
            )
            append_event(
                db,
                actor=actor,
                action="credential.create",
                outcome="recorded",
                object_type="credential",
                object_id=credential_id,
                detail={"label": label, "purpose": purpose, "adapter": adapter},
                tx=tx,
            )
    except Exception:
        vault.delete_secret(credential_id)
        raise
    return public_credential(db.query_one("SELECT * FROM credential_meta WHERE id = ?", (credential_id,)))


def public_credential(row: dict) -> dict:
    return {
        "id": row["id"],
        "label": row["label"],
        "purpose": row["purpose"],
        "adapter": row["adapter"],
        "scope": json.loads(row["scope_json"]),
        "created_at": row["created_at"],
        "created_by": row["created_by"],
    }


def list_credentials(db) -> list[dict]:
    return [public_credential(row) for row in db.query("SELECT * FROM credential_meta ORDER BY created_at")]


def validate_credential(db, vault, credential_id: str, target: str, actor: str) -> dict:
    row = db.query_one("SELECT * FROM credential_meta WHERE id = ?", (credential_id,))
    if not row:
        raise PolicyError("credential not found", 404)
    scopes = db.query("SELECT * FROM discovery_scopes WHERE status = 'approved'")
    allowed = False
    for scope in scopes:
        if parse_time(scope["expires_at"]) <= datetime.now(timezone.utc):
            continue
        if target_allowed(target, json.loads(scope["cidrs_json"]), json.loads(scope["excluded_json"])):
            allowed = True
            break
    if not allowed:
        append_event(
            db,
            actor=actor,
            action="credential.validate",
            outcome="blocked",
            object_type="credential",
            object_id=credential_id,
            detail={"target": target, "reason": "target is outside an approved unexpired scope"},
        )
        raise PolicyError("credential checks are limited to approved unexpired endpoints", 403)
    scope = json.loads(row["scope_json"])
    if "lab" not in scope.get("targets", []) and not target_allowed(target, scope.get("cidrs", []), []):
        append_event(db, actor=actor, action="credential.validate", outcome="blocked", object_type="credential", object_id=credential_id, detail={"target": target})
        raise PolicyError("credential is not scoped to that endpoint", 403)
    secret = vault.get_secret(credential_id)
    try:
        usable = bool(secret)
    finally:
        del secret
    if not usable:
        raise PolicyError("credential secret is empty")
    with db.transaction() as tx:
        append_event(
            db,
            actor=actor,
            action="credential.validate",
            outcome="checked",
            object_type="credential",
            object_id=credential_id,
            detail={"target": target, "change_permitted": False, "purpose": row["purpose"]},
            tx=tx,
        )
    return {
        "credential_id": credential_id,
        "target": target,
        "change_permitted": False,
        "result": "secret decrypted for an approved endpoint; this does not authorize a change",
    }


def _proposal_body(row: dict) -> dict:
    return {
        "id": row["id"],
        "version": row["version"],
        "action_type": row["action_type"],
        "asset_id": row["asset_id"],
        "finding_id": row["finding_id"],
        "execution_id": row["execution_id"],
        "benchmark_id": row["benchmark_id"],
        "benchmark_row_id": row["benchmark_row_id"],
        "rule_id": row["rule_id"],
        "rule_version": row["rule_version"],
        "target_identity": json.loads(row["target_identity_json"]),
        "evidence": json.loads(row["evidence_json"]),
        "intended_change": json.loads(row["intended_change_json"]),
        "preconditions": json.loads(row["preconditions_json"]),
        "expected_start_hash": row["expected_start_hash"],
        "impact": row["impact"],
        "dependencies": row["dependencies"],
        "backup_scope": row["backup_scope"],
        "verification": json.loads(row["verification_json"]),
        "rollback_procedure": row["rollback_procedure"],
        "rollback_capability": row["rollback_capability"],
        "connectivity_risk": bool(row["connectivity_risk"]),
        "adapter_name": row["adapter_name"],
        "adapter_version": row["adapter_version"],
        "change_type": row.get("change_type") or "unspecified",
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
    }


def proposal_hash(row: dict) -> str:
    return sha256_text(canon(_proposal_body(row)))


def public_proposal(row: dict) -> dict:
    body = _proposal_body(row)
    body["proposal_hash"] = row["proposal_hash"]
    body["created_by"] = row["created_by"]
    body["hash_matches_record"] = proposal_hash(row) == row["proposal_hash"]
    return body


def _procedure_proposal(db, finding: dict, actor: str) -> dict:
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (finding["asset_id"],))
    if not asset:
        raise PolicyError("asset for this finding no longer exists", 404)
    previous = db.query_one("SELECT id, version FROM proposals WHERE finding_id = ? ORDER BY version DESC LIMIT 1", (finding["id"],))
    proposal_id = new_id()
    created = utcnow()
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).replace(microsecond=0).isoformat()
    identity = {"asset_id": asset["id"], "hostname": asset["hostname"], "ip_address": asset["ip_address"], "lab_target_path": asset["lab_target_path"]}
    intended = {"action": "manual_steps", "steps": [finding["observation"]], "executed": False}
    row = {
        "id": proposal_id,
        "version": (previous["version"] + 1) if previous else 1,
        "supersedes_id": previous["id"] if previous else None,
        "action_type": "procedure",
        "asset_id": asset["id"],
        "finding_id": finding["id"],
        "execution_id": None,
        "benchmark_id": "range-evidence",
        "benchmark_row_id": finding["benchmark_row_id"],
        "rule_id": finding["rule_id"],
        "rule_version": finding["rule_version"],
        "target_identity_json": json.dumps(identity),
        "evidence_json": json.dumps({"observation": finding["observation"], "collected_at": finding["collected_at"], "evidence_kind": finding["evidence_kind"], "risk": json.loads(finding["risk_json"]) if finding.get("risk_json") else None}),
        "intended_change_json": json.dumps(intended),
        "preconditions_json": json.dumps(["a person approves this exact hash", "no command from imported text is run"]),
        "expected_start_hash": "not-applicable",
        "impact": "Records an approved procedure. It does not change a host, container, or network device.",
        "dependencies": "The cited imported evidence remains available for review.",
        "backup_scope": "No configuration is replaced.",
        "verification_json": json.dumps(["re-read the cited evidence after the owner completes the steps", "record whether the finding is still present"]),
        "rollback_procedure": "Manual recovery only. Nothing was changed automatically, so there is no backup to restore.",
        "rollback_capability": "manual",
        "connectivity_risk": 0,
        "adapter_name": "none",
        "adapter_version": "procedure-1",
        "change_type": "procedure",
        "created_at": created,
        "created_by": actor,
        "expires_at": expires,
        "proposal_hash": "",
    }
    row["proposal_hash"] = proposal_hash(row)
    _insert_proposal(db, row, actor, "procedure.propose")
    return public_proposal(db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,)))


def _insert_proposal(db, row: dict, actor: str, action: str) -> None:
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO proposals (
              id, version, supersedes_id, action_type, asset_id, finding_id, execution_id, benchmark_id,
              benchmark_row_id, rule_id, rule_version, target_identity_json, evidence_json, intended_change_json,
              preconditions_json, expected_start_hash, impact, dependencies, backup_scope, verification_json,
              rollback_procedure, rollback_capability, connectivity_risk, adapter_name, adapter_version,
              change_type, proposal_hash, created_at, created_by, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(row[key] for key in [
                "id", "version", "supersedes_id", "action_type", "asset_id", "finding_id", "execution_id", "benchmark_id",
                "benchmark_row_id", "rule_id", "rule_version", "target_identity_json", "evidence_json", "intended_change_json",
                "preconditions_json", "expected_start_hash", "impact", "dependencies", "backup_scope", "verification_json",
                "rollback_procedure", "rollback_capability", "connectivity_risk", "adapter_name", "adapter_version",
                "change_type", "proposal_hash", "created_at", "created_by", "expires_at",
            ]),
        )
        append_event(db, actor=actor, action=action, outcome="recorded", object_type="proposal", object_id=row["id"], detail={"proposal_hash": row["proposal_hash"], "action_type": row["action_type"]}, tx=tx)


def record_plan(db, proposal_id: str, approval_id: str, actor: str) -> dict:
    proposal = db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    approval = db.query_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    if not proposal or not approval:
        raise PolicyError("proposal or approval was not found", 404)
    if proposal["action_type"] != "procedure":
        raise PolicyError("only a procedure proposal can be recorded as not executed")
    if approval["proposal_id"] != proposal["id"] or approval["decision"] != "approved":
        raise PolicyError("approval does not match this proposal", 403)
    if approval["used"]:
        raise PolicyError("approval was already used", 409)
    now = datetime.now(timezone.utc)
    if parse_time(approval["expires_at"]) <= now or parse_time(proposal["expires_at"]) <= now:
        raise PolicyError("approval or proposal has expired", 403)
    current = proposal_hash(proposal)
    if current != proposal["proposal_hash"] or current != approval["proposal_hash"]:
        raise PolicyError("proposal hash does not match the approval", 409)
    intent_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO execution_intents (
              id, proposal_id, approval_id, asset_id, action_type, status, remote_atomic, started_at, finished_at,
              adapter_name, adapter_version, detail
            ) VALUES (?, ?, ?, ?, 'procedure', 'not_executed', 0, ?, ?, 'none', 'procedure-1', ?)
            """,
            (intent_id, proposal_id, approval_id, proposal["asset_id"], utcnow(), utcnow(), "approved steps were recorded and not executed"),
        )
        tx.execute("UPDATE approvals SET used = 1 WHERE id = ?", (approval_id,))
        append_event(db, actor=actor, action="procedure.record", outcome="not_executed", object_type="execution", object_id=intent_id, detail={"proposal_hash": current}, tx=tx)
    return get_execution(db, intent_id)


def create_proposal(db, settings, finding_id: str, actor: str) -> dict:
    finding = db.query_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
    if not finding:
        raise PolicyError("finding not found", 404)
    if finding["classification"] == "evidence_check" and finding["result"] == "fail":
        return _procedure_proposal(db, finding, actor)
    if finding["result"] != "fail" or finding["classification"] != "automated_check_supported":
        raise PolicyError("only a failed automated check with an implemented remediation can be proposed")
    if finding["rule_id"] != "FG-WIN10-AUDIT-POLICY":
        raise PolicyError("no implemented remediation adapter is registered for this rule")
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (finding["asset_id"],))
    if not asset or not asset["lab_target_path"]:
        raise PolicyError("asset has no authorized lab target")
    _data, digest, _raw = LOCAL.read(settings, asset["lab_target_path"])
    previous = db.query_one("SELECT id, version FROM proposals WHERE finding_id = ? ORDER BY version DESC LIMIT 1", (finding_id,))
    proposal_id = new_id()
    created = utcnow()
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).replace(microsecond=0).isoformat()
    identity = {
        "asset_id": asset["id"],
        "hostname": asset["hostname"],
        "ip_address": asset["ip_address"],
        "lab_target_path": asset["lab_target_path"],
    }
    intended = {"action": "set_audit_policy", "key": "audit_policy", "value": "enabled"}
    row = {
        "id": proposal_id,
        "version": (previous["version"] + 1) if previous else 1,
        "supersedes_id": previous["id"] if previous else None,
        "action_type": "remediate",
        "asset_id": asset["id"],
        "finding_id": finding_id,
        "execution_id": None,
        "benchmark_id": db.query_one("SELECT benchmark_id FROM stig_benchmarks WHERE id = ?", (finding["benchmark_row_id"],))["benchmark_id"],
        "benchmark_row_id": finding["benchmark_row_id"],
        "rule_id": finding["rule_id"],
        "rule_version": finding["rule_version"],
        "target_identity_json": json.dumps(identity),
        "evidence_json": json.dumps({"observation": finding["observation"], "collected_at": finding["collected_at"], "evidence_kind": finding["evidence_kind"]}),
        "intended_change_json": json.dumps(intended),
        "preconditions_json": json.dumps(["lab file exists", "current hash matches expected_start_hash", "approval hash matches this proposal"]),
        "expected_start_hash": digest,
        "impact": "Sets audit_policy=enabled in the bound lab configuration file. It does not change a remote operating system.",
        "dependencies": "Local lab target remains inside the configured lab root.",
        "backup_scope": "Exact bytes of the lab configuration file.",
        "verification_json": json.dumps(["re-read audit_policy", "compare file hash", "confirm the file is still readable and the directory is writable"]),
        "rollback_procedure": "After a separate rollback approval, restore the backup bytes if the current hash still equals the post-change hash.",
        "rollback_capability": "automatic",
        "connectivity_risk": 0,
        "adapter_name": LOCAL.name,
        "adapter_version": LOCAL.version,
        "change_type": "stig_config",
        "created_at": created,
        "created_by": actor,
        "expires_at": expires,
        "proposal_hash": "",
    }
    row["proposal_hash"] = proposal_hash(row)
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO proposals (
              id, version, supersedes_id, action_type, asset_id, finding_id, execution_id, benchmark_id,
              benchmark_row_id, rule_id, rule_version, target_identity_json, evidence_json, intended_change_json,
              preconditions_json, expected_start_hash, impact, dependencies, backup_scope, verification_json,
              rollback_procedure, rollback_capability, connectivity_risk, adapter_name, adapter_version,
              change_type, proposal_hash, created_at, created_by, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"], row["version"], row["supersedes_id"], row["action_type"], row["asset_id"], row["finding_id"],
                row["execution_id"], row["benchmark_id"], row["benchmark_row_id"], row["rule_id"], row["rule_version"],
                row["target_identity_json"], row["evidence_json"], row["intended_change_json"], row["preconditions_json"],
                row["expected_start_hash"], row["impact"], row["dependencies"], row["backup_scope"], row["verification_json"],
                row["rollback_procedure"], row["rollback_capability"], row["connectivity_risk"], row["adapter_name"],
                row["adapter_version"], row["change_type"], row["proposal_hash"], row["created_at"], row["created_by"], row["expires_at"],
            ),
        )
        append_event(db, actor=actor, action="proposal.create", outcome="recorded", object_type="proposal", object_id=proposal_id, detail={"proposal_hash": row["proposal_hash"], "version": row["version"]}, tx=tx)
    return public_proposal(db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,)))


def create_install_proposal(db, settings, kind: str, source_id: str, asset_id: str, actor: str) -> dict:
    from .scans import material_label, presence_token
    from .updates import read_imported_msu

    label = material_label(db, kind, source_id)
    token = presence_token(kind, source_id)
    package = read_imported_msu(db, settings, source_id) if kind == "msu" else None
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    if not asset["selected"]:
        raise PolicyError("asset is not selected")
    if not asset["lab_target_path"]:
        raise PolicyError("asset has no authorized lab target")
    data, digest, _raw = LOCAL.read(settings, asset["lab_target_path"])
    recorded = [part for part in data.get("installed", "").split(",") if part]
    if token in recorded:
        raise PolicyError("that update is already recorded on this lab file", 409)
    previous = db.query_one(
        "SELECT id, version FROM proposals WHERE asset_id = ? AND rule_id = ? AND action_type = 'record_install' ORDER BY version DESC LIMIT 1",
        (asset["id"], token),
    )
    proposal_id = new_id()
    created = utcnow()
    expires = (datetime.now(timezone.utc) + timedelta(hours=8)).replace(microsecond=0).isoformat()
    identity = {
        "asset_id": asset["id"],
        "hostname": asset["hostname"],
        "ip_address": asset["ip_address"],
        "lab_target_path": asset["lab_target_path"],
    }
    intended = {"action": "record_lab_install", "token": token, "executed_package": False}
    row = {
        "id": proposal_id,
        "version": (previous["version"] + 1) if previous else 1,
        "supersedes_id": previous["id"] if previous else None,
        "action_type": "record_install",
        "asset_id": asset["id"],
        "finding_id": None,
        "execution_id": None,
        "benchmark_id": label["benchmark_id"],
        "benchmark_row_id": source_id,
        "rule_id": token,
        "rule_version": "imported",
        "target_identity_json": json.dumps(identity),
        "evidence_json": json.dumps({
            "observation": package["statement"] if package else f"{label['label']} is not recorded in the lab file",
            "presence": "absent",
            "package_read": bool(package),
            "executed": False,
        }),
        "intended_change_json": json.dumps(intended),
        "preconditions_json": json.dumps(["lab file exists", "current hash matches expected_start_hash", "approval hash matches this proposal", "imported package is not executed"]),
        "expected_start_hash": digest,
        "impact": f"Records {token} in the lab file key installed. The imported package is not executed and a remote operating system is not changed.",
        "dependencies": "A current patch maintenance window and an approved noncritical class.",
        "backup_scope": "Exact bytes of the lab configuration file.",
        "verification_json": json.dumps(["re-read installed", "confirm audit_policy is unchanged", "confirm the imported package was not executed"]),
        "rollback_procedure": "After a separate rollback approval, restore the backup bytes if the current hash still equals the post-change hash.",
        "rollback_capability": "automatic",
        "connectivity_risk": 0,
        "adapter_name": LOCAL.name,
        "adapter_version": LOCAL.version,
        "change_type": "patch",
        "created_at": created,
        "created_by": actor,
        "expires_at": expires,
        "proposal_hash": "",
    }
    row["proposal_hash"] = proposal_hash(row)
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO proposals (
              id, version, supersedes_id, action_type, asset_id, finding_id, execution_id, benchmark_id,
              benchmark_row_id, rule_id, rule_version, target_identity_json, evidence_json, intended_change_json,
              preconditions_json, expected_start_hash, impact, dependencies, backup_scope, verification_json,
              rollback_procedure, rollback_capability, connectivity_risk, adapter_name, adapter_version,
              change_type, proposal_hash, created_at, created_by, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"], row["version"], row["supersedes_id"], row["action_type"], row["asset_id"], row["finding_id"],
                row["execution_id"], row["benchmark_id"], row["benchmark_row_id"], row["rule_id"], row["rule_version"],
                row["target_identity_json"], row["evidence_json"], row["intended_change_json"], row["preconditions_json"],
                row["expected_start_hash"], row["impact"], row["dependencies"], row["backup_scope"], row["verification_json"],
                row["rollback_procedure"], row["rollback_capability"], row["connectivity_risk"], row["adapter_name"],
                row["adapter_version"], row["change_type"], row["proposal_hash"], row["created_at"], row["created_by"], row["expires_at"],
            ),
        )
        append_event(db, actor=actor, action="proposal.create", outcome="recorded", object_type="proposal", object_id=proposal_id, detail={"proposal_hash": row["proposal_hash"], "action_type": "record_install", "executed": False}, tx=tx)
    return public_proposal(db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,)))


def decide_approval(db, proposal_id: str, decision: str, actor: str) -> dict:
    if decision not in {"approved", "rejected"}:
        raise PolicyError("decision must be approved or rejected")
    row = db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    if not row:
        raise PolicyError("proposal not found", 404)
    current = proposal_hash(row)
    if current != row["proposal_hash"]:
        recorded = _proposal_body(row)
        recorded.pop("change_type", None)
        if sha256_text(canon(recorded)) == row["proposal_hash"]:
            raise PolicyError("this proposal was recorded before the hash included the change type. Propose the finding again.", 409)
        raise PolicyError("proposal record does not match its stored hash", 409)
    if parse_time(row["expires_at"]) <= datetime.now(timezone.utc):
        raise PolicyError("proposal has expired", 403)
    expires = min(parse_time(row["expires_at"]), datetime.now(timezone.utc) + timedelta(hours=4)).replace(microsecond=0).isoformat()
    approval_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO approvals (id, proposal_id, proposal_hash, actor, decision, created_at, expires_at, used)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (approval_id, proposal_id, current, actor, decision, utcnow(), expires),
        )
        append_event(db, actor=actor, action="proposal.decision", outcome=decision, object_type="proposal", object_id=proposal_id, detail={"approval_id": approval_id, "proposal_hash": current}, tx=tx)
    return db.query_one("SELECT id, proposal_id, proposal_hash, actor, decision, created_at, expires_at, used FROM approvals WHERE id = ?", (approval_id,))


def _require_execution_parts(db, proposal_id: str, approval_id: str):
    proposal = db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,))
    approval = db.query_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
    if not proposal:
        raise PolicyError("proposal was not found", 404)
    if not approval:
        raise PolicyError("approval was not found", 404)
    if approval["proposal_id"] != proposal["id"]:
        raise PolicyError("approval does not match this proposal", 403)
    if approval["decision"] != "approved":
        raise PolicyError("approval was not granted", 403)
    if approval["used"]:
        raise PolicyError("approval was already used", 409)
    now = datetime.now(timezone.utc)
    if parse_time(approval["expires_at"]) <= now or parse_time(proposal["expires_at"]) <= now:
        raise PolicyError("approval or proposal has expired", 403)
    current = proposal_hash(proposal)
    if current != proposal["proposal_hash"] or current != approval["proposal_hash"]:
        raise PolicyError("proposal hash does not match the approval", 409)
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (proposal["asset_id"],))
    if not asset:
        raise PolicyError("target asset no longer exists", 409)
    identity = json.loads(proposal["target_identity_json"])
    if identity.get("asset_id") != asset["id"] or identity.get("lab_target_path") != asset["lab_target_path"] or identity.get("ip_address") != asset["ip_address"]:
        raise PolicyError("target identity changed after approval", 409)
    if proposal["connectivity_risk"] and proposal["rollback_capability"] != "automatic":
        raise PolicyError("connectivity-affecting change blocked; no safe recovery strategy is configured", 403)
    return proposal, approval, asset


def execute_proposal(db, settings, proposal_id: str, approval_id: str, actor: str, after_intent=None, after_write=None) -> dict:
    existing = db.query_one("SELECT action_type FROM proposals WHERE id = ?", (proposal_id,))
    if existing and existing["action_type"] == "procedure":
        raise PolicyError("this proposal records steps only; record the plan instead. No change was applied.", 409)
    proposal, approval, asset = _require_execution_parts(db, proposal_id, approval_id)
    change_type = proposal.get("change_type") or "unspecified"
    if proposal["action_type"] == "remediate" and change_type != "stig_config":
        raise PolicyError("a STIG configuration change cannot run as another change type", 409)
    if proposal["action_type"] == "record_install" and change_type != "patch":
        raise PolicyError("recording an install requires a patch proposal", 409)
    assert_deployment_allowed(db, asset, change_type)
    data, digest, raw = LOCAL.read(settings, asset["lab_target_path"])
    if digest != proposal["expected_start_hash"]:
        append_event(db, actor=actor, action="execution.blocked", outcome="blocked", object_type="proposal", object_id=proposal_id, detail={"reason": "configuration drift"})
        raise PolicyError("configuration drift detected; execution was not started", 409)
    intent_id = new_id()
    settings.backup_dir.mkdir(parents=True, exist_ok=True)
    backup = settings.backup_dir / f"{intent_id}.bak"
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO execution_intents (
              id, proposal_id, approval_id, asset_id, action_type, status, backup_path, prior_hash,
              remote_atomic, started_at, adapter_name, adapter_version, detail
            ) VALUES (?, ?, ?, ?, ?, 'intent', ?, ?, 0, ?, ?, ?, ?)
            """,
            (
                intent_id, proposal_id, approval_id, asset["id"], proposal["action_type"], str(backup), digest,
                utcnow(), proposal["adapter_name"], proposal["adapter_version"],
                "database transaction does not make the file change atomic",
            ),
        )
        tx.execute("UPDATE approvals SET used = 1 WHERE id = ?", (approval_id,))
        append_event(db, actor=actor, action="execution.intent", outcome="recorded", object_type="execution", object_id=intent_id, correlation_id=intent_id, tx=tx)
    backup.write_bytes(raw)
    try:
        if after_intent:
            after_intent(intent_id)
        intended = json.loads(proposal["intended_change_json"])
        if proposal["action_type"] == "remediate":
            LOCAL.apply(settings, asset["lab_target_path"], intended["value"])
        elif proposal["action_type"] == "record_install":
            LOCAL.record_installed(settings, asset["lab_target_path"], intended["token"])
        elif proposal["action_type"] == "rollback":
            LOCAL.restore(settings, asset["lab_target_path"], backup_bytes_for_rollback(db, proposal))
        else:
            raise PolicyError("unsupported action")
        if after_write:
            after_write(intent_id)
        current, post_hash, _raw = LOCAL.read(settings, asset["lab_target_path"])
        expected_value = intended.get("value") if proposal["action_type"] == "remediate" else json.loads(proposal["intended_change_json"]).get("restore_value")
        path = LOCAL.read.__func__ if False else None
        file_path = __import__("fleetguard.adapters", fromlist=["lab_file"]).lab_file(settings, asset["lab_target_path"])
        healthy = file_path.is_file() and file_path.parent.exists()
        if proposal["action_type"] == "rollback":
            setting_ok = post_hash == json.loads(proposal["intended_change_json"])["restore_hash"] or current.get("audit_policy") == expected_value
        elif proposal["action_type"] == "record_install":
            recorded = [part for part in current.get("installed", "").split(",") if part]
            setting_ok = intended["token"] in recorded and current.get("audit_policy") == data.get("audit_policy")
        else:
            setting_ok = current.get("audit_policy") == expected_value
        if setting_ok and healthy:
            status = "verified_success"
        elif not healthy:
            status = "inconclusive"
        else:
            status = "verified_failure"
        _finish(db, intent_id, status, post_hash, actor, "verification compared the lab file after the write")
        return get_execution(db, intent_id)
    except PolicyError:
        raise
    except Exception as exc:
        try:
            _current, post_hash, _raw = LOCAL.read(settings, asset["lab_target_path"])
        except Exception:
            post_hash = None
        if post_hash == digest:
            _finish(db, intent_id, "failed", post_hash, actor, exc.__class__.__name__)
            raise PolicyError("execution failed before the configuration changed", 409) from exc
        append_event(db, actor=actor, action="execution.ambiguous", outcome="ambiguous", object_type="execution", object_id=intent_id, detail={"error_type": exc.__class__.__name__})
        raise PolicyError("execution outcome is ambiguous; it was not retried or rolled back automatically", 409) from exc


def backup_bytes_for_rollback(db, proposal) -> bytes:
    execution = db.query_one("SELECT * FROM execution_intents WHERE id = ?", (proposal["execution_id"],))
    return __import__("pathlib").Path(execution["backup_path"]).read_bytes()


def _finish(db, intent_id, status, post_hash, actor, detail) -> None:
    with db.transaction() as tx:
        tx.execute(
            "UPDATE execution_intents SET status = ?, post_hash = ?, finished_at = ?, detail = ? WHERE id = ?",
            (status, post_hash, utcnow(), detail, intent_id),
        )
        append_event(db, actor=actor, action="execution.finish", outcome=status, object_type="execution", object_id=intent_id, tx=tx)


def get_execution(db, intent_id: str) -> dict:
    row = db.query_one("SELECT * FROM execution_intents WHERE id = ?", (intent_id,))
    if not row:
        raise PolicyError("execution not found", 404)
    row["remote_atomic"] = bool(row["remote_atomic"])
    return row


def list_executions(db) -> list[dict]:
    rows = db.query("SELECT * FROM execution_intents ORDER BY started_at")
    for row in rows:
        row["remote_atomic"] = bool(row["remote_atomic"])
    return rows


def create_rollback_proposal(db, settings, execution_id: str, actor: str) -> dict:
    execution = db.query_one("SELECT * FROM execution_intents WHERE id = ?", (execution_id,))
    if not execution:
        raise PolicyError("execution not found", 404)
    if execution["status"] not in {"verified_success", "verified_failure"}:
        raise PolicyError("rollback needs a finished execution; ambiguous work is left for manual recovery")
    if execution["adapter_name"] != LOCAL.name:
        raise PolicyError("automatic rollback is not implemented for this adapter")
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (execution["asset_id"],))
    _data, digest, _raw = LOCAL.read(settings, asset["lab_target_path"])
    if digest != execution["post_hash"]:
        append_event(db, actor=actor, action="rollback.blocked", outcome="blocked", object_type="execution", object_id=execution_id, detail={"reason": "intervening change"})
        raise PolicyError("intervening change detected; rollback will not overwrite it", 409)
    original = db.query_one("SELECT * FROM proposals WHERE id = ?", (execution["proposal_id"],))
    prior = read_config(__import__("pathlib").Path(execution["backup_path"]))
    proposal_id = new_id()
    created = utcnow()
    expires = (datetime.now(timezone.utc) + timedelta(hours=4)).replace(microsecond=0).isoformat()
    identity = json.loads(original["target_identity_json"])
    intended = {"action": "restore_backup", "backup_execution_id": execution_id, "restore_value": prior[0].get("audit_policy"), "restore_hash": prior[1]}
    row = {
        "id": proposal_id,
        "version": 1,
        "supersedes_id": None,
        "action_type": "rollback",
        "asset_id": asset["id"],
        "finding_id": original["finding_id"],
        "execution_id": execution_id,
        "benchmark_id": original["benchmark_id"],
        "benchmark_row_id": original["benchmark_row_id"],
        "rule_id": original["rule_id"],
        "rule_version": original["rule_version"],
        "target_identity_json": json.dumps(identity),
        "evidence_json": json.dumps({"execution_status": execution["status"], "post_hash": execution["post_hash"]}),
        "intended_change_json": json.dumps(intended),
        "preconditions_json": json.dumps(["current hash equals the recorded post-change hash", "separate approval required"]),
        "expected_start_hash": digest,
        "impact": "Restores the backed-up lab configuration bytes.",
        "dependencies": "Backup file from the original execution.",
        "backup_scope": "Current lab file is not replaced when its hash has changed again.",
        "verification_json": json.dumps(["re-read lab file", "compare to backup hash"]),
        "rollback_procedure": "Manual recovery only after this rollback.",
        "rollback_capability": "manual",
        "connectivity_risk": 0,
        "adapter_name": LOCAL.name,
        "adapter_version": LOCAL.version,
        "change_type": original.get("change_type") or "stig_config",
        "created_at": created,
        "created_by": actor,
        "expires_at": expires,
        "proposal_hash": "",
    }
    row["proposal_hash"] = proposal_hash(row)
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO proposals (
              id, version, supersedes_id, action_type, asset_id, finding_id, execution_id, benchmark_id,
              benchmark_row_id, rule_id, rule_version, target_identity_json, evidence_json, intended_change_json,
              preconditions_json, expected_start_hash, impact, dependencies, backup_scope, verification_json,
              rollback_procedure, rollback_capability, connectivity_risk, adapter_name, adapter_version,
              change_type, proposal_hash, created_at, created_by, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(row[key] for key in [
                "id", "version", "supersedes_id", "action_type", "asset_id", "finding_id", "execution_id", "benchmark_id",
                "benchmark_row_id", "rule_id", "rule_version", "target_identity_json", "evidence_json", "intended_change_json",
                "preconditions_json", "expected_start_hash", "impact", "dependencies", "backup_scope", "verification_json",
                "rollback_procedure", "rollback_capability", "connectivity_risk", "adapter_name", "adapter_version",
                "change_type", "proposal_hash", "created_at", "created_by", "expires_at",
            ]),
        )
        append_event(db, actor=actor, action="rollback.propose", outcome="recorded", object_type="proposal", object_id=proposal_id, detail={"proposal_hash": row["proposal_hash"]}, tx=tx)
    return public_proposal(db.query_one("SELECT * FROM proposals WHERE id = ?", (proposal_id,)))


def recover_report(db) -> dict:
    ambiguous = db.query("SELECT * FROM execution_intents WHERE status = 'intent' ORDER BY started_at")
    interrupted = db.query("SELECT * FROM discovery_jobs WHERE status = 'interrupted' ORDER BY created_at")
    return {
        "ambiguous_executions": ambiguous,
        "interrupted_discovery_jobs": interrupted,
        "note": "Ambiguous executions are not retried or rolled back automatically. SQLite records are not a transaction around a device change.",
    }

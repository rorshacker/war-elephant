from __future__ import annotations

import json

from .adapters import LocalFileAdapter
from .audit import append_event
from .baselines import _latest_assignments
from .db import Database
from .policy import PolicyError
from .reconcile import assessment_allowed
from .util import new_id, utcnow

CHECK_VERSION = "registry-1"
FAMILY = {
    "FLEETGUARD-SYNTH-WIN10": "win-client",
    "FLEETGUARD-SYNTH-WIN-SERVER": "win-server",
    "FLEETGUARD-SYNTH-RHEL8": "rhel",
}
AUTOMATED = {
    "FG-WIN10-AUDIT-POLICY": "win-client",
}


def _imported_checklist(db: Database) -> dict | None:
    from .stig import list_benchmarks

    newest = [row for row in list_benchmarks(db) if row["version_label"] == "newest imported version"]
    if not newest:
        return None
    row = max(newest, key=lambda item: item["imported_at"])
    return {"benchmark_row_id": row["id"], "benchmark_id": row["benchmark_id"]}


def asset_family(os_name: str | None, device_type: str | None) -> str | None:
    text = (os_name or "").lower()
    device = (device_type or "").lower()
    if "windows server" in text and device == "server":
        return "win-server"
    if ("windows 10" in text or "windows 11" in text) and device in {"workstation", "client", "desktop"}:
        return "win-client"
    if ("rhel" in text or "red hat enterprise" in text) and device == "server":
        return "rhel"
    return None


def assess_assets(db: Database, settings, asset_ids: list[str], actor: str) -> dict:
    if not asset_ids:
        raise PolicyError("select at least one asset")
    created = []
    for asset_id in asset_ids:
        created.append(_assess_one(db, settings, asset_id, actor))
    return {"assessments": created}


def _assess_one(db: Database, settings, asset_id: str, actor: str, forced_benchmark: dict | None = None) -> dict:
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    if not asset["selected"]:
        raise PolicyError("asset is not selected")
    if not assessment_allowed(asset):
        raise PolicyError("identity is not confirmed enough for assessment")
    if forced_benchmark:
        assignment = forced_benchmark
    else:
        assignment = _latest_assignments(db).get(asset_id)
        if not assignment or assignment["status"] not in {"confirmed", "overridden"}:
            assignment = _imported_checklist(db)
        if not assignment:
            raise PolicyError("import a checklist before assessment")
    rules = db.query("SELECT * FROM stig_rules WHERE benchmark_row_id = ? ORDER BY rule_id", (assignment["benchmark_row_id"],))
    assessment_id = new_id()
    family = FAMILY.get(assignment["benchmark_id"])
    actual = asset_family(asset["os_name"], asset["device_type"])
    findings = []
    collected = utcnow()
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO assessments (id, asset_id, benchmark_row_id, created_at, created_by, status) VALUES (?, ?, ?, ?, ?, 'completed')",
            (assessment_id, asset_id, assignment["benchmark_row_id"], collected, actor),
        )
        for rule in rules:
            finding = _classify(settings, asset, assignment, rule, family, actual, collected)
            finding_id = new_id()
            tx.execute(
                """
                INSERT INTO findings (
                  id, assessment_id, asset_id, benchmark_row_id, rule_id, rule_version, classification, result,
                  observation, collected_at, check_impl_version, evidence_ref, evidence_kind, rule_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    assessment_id,
                    asset_id,
                    assignment["benchmark_row_id"],
                    rule["rule_id"],
                    rule["version"],
                    finding["classification"],
                    finding["result"],
                    finding["observation"],
                    collected,
                    finding["check_impl_version"],
                    finding["evidence_ref"],
                    finding["evidence_kind"],
                    "imported",
                ),
            )
            findings.append({"id": finding_id, **finding, "rule_id": rule["rule_id"]})
        append_event(
            db,
            actor=actor,
            action="assessment.run",
            outcome="completed",
            object_type="assessment",
            object_id=assessment_id,
            detail={"asset_id": asset_id, "findings": len(findings)},
            tx=tx,
        )
    return {"id": assessment_id, "asset_id": asset_id, "findings": findings}


def assess_imported_benchmark(db: Database, settings, benchmark_row_id: str, actor: str) -> dict:
    benchmark = db.query_one("SELECT * FROM stig_benchmarks WHERE id = ?", (benchmark_row_id,))
    if not benchmark:
        raise PolicyError("benchmark not found", 404)
    label = benchmark["title"] or benchmark["benchmark_id"]
    assets = db.query("SELECT id FROM assets WHERE selected = 1")
    if not assets:
        return {
            "kind": "stig",
            "source_id": benchmark_row_id,
            "label": label,
            "status": "not_started",
            "observation": "No asset is selected. No host was read and no rule was marked compliant.",
            "executed": False,
        }
    totals = {"pass": 0, "fail": 0, "not_reviewed": 0, "not_applicable": 0, "error": 0}
    checked_assets = 0
    for asset in assets:
        try:
            result = _assess_one(
                db,
                settings,
                asset["id"],
                actor,
                {"benchmark_row_id": benchmark["id"], "benchmark_id": benchmark["benchmark_id"]},
            )
        except PolicyError:
            continue
        checked_assets += 1
        for finding in result["findings"]:
            key = finding["result"] if finding["result"] in totals else "error"
            totals[key] += 1
    if checked_assets == 0:
        return {
            "kind": "stig",
            "source_id": benchmark_row_id,
            "label": label,
            "status": "not_started",
            "observation": "No selected asset was confirmed enough to assess. No host was read and no rule was marked compliant.",
            "executed": False,
        }
    return {
        "kind": "stig",
        "source_id": benchmark_row_id,
        "label": label,
        "status": "recorded",
        "observation": f"{totals['pass']} pass, {totals['fail']} fail, {totals['not_reviewed']} not reviewed, {totals['not_applicable']} not applicable, {totals['error']} error. Imported check text was not executed.",
        "executed": False,
        "counts": totals,
    }


def _classify(settings, asset, assignment, rule, family, actual, collected: str) -> dict:
    device = (asset["device_type"] or "").lower()
    if family and actual and family != actual:
        return _finding("not_applicable", "not_applicable", "asset platform does not match the confirmed baseline family", "none", None, "not-applicable")
    if family and actual is None:
        if device in {"switch", "printer", "appliance", "standalone"}:
            return _finding("not_applicable", "not_applicable", "asset platform does not match the confirmed baseline family", "none", None, "not-applicable")
        return _finding("error", "error", "insufficient evidence to confirm platform family", "none", None, "insufficient-evidence")
    automated_family = AUTOMATED.get(rule["rule_id"])
    if automated_family is None:
        return _finding(
            "manual_review_required",
            "not_reviewed",
            "No implemented check adapter is registered for this rule. Imported check text was not executed.",
            "none",
            None,
            "manual",
        )
    if automated_family != family:
        return _finding("not_applicable", "not_applicable", "registered check does not apply to this baseline family", "none", None, "not-applicable")
    if not asset["lab_target_path"]:
        return _finding("error", "error", "insufficient evidence: no authorized lab target is bound", "none", None, CHECK_VERSION)
    try:
        data, digest, _raw = LocalFileAdapter().read(settings, asset["lab_target_path"])
    except PolicyError as exc:
        return _finding("error", "error", exc.message, "none", asset["lab_target_path"], CHECK_VERSION)
    value = data.get("audit_policy")
    result = "pass" if value == "enabled" else "fail"
    observation = f"lab file key audit_policy={value or 'missing'}; sha256={digest}; collected_at={collected}"
    return _finding("automated_check_supported", result, observation, "real", asset["lab_target_path"], CHECK_VERSION)


def _finding(classification, result, observation, evidence_kind, evidence_ref, version) -> dict:
    return {
        "classification": classification,
        "result": result,
        "observation": observation,
        "evidence_kind": evidence_kind,
        "evidence_ref": evidence_ref,
        "check_impl_version": version,
    }


def list_findings(db: Database, asset_id: str | None = None) -> list[dict]:
    if asset_id:
        rows = db.query("SELECT * FROM findings WHERE asset_id = ? ORDER BY collected_at, rule_id", (asset_id,))
    else:
        rows = db.query("SELECT * FROM findings ORDER BY collected_at, rule_id")
    return [_with_risk(row) for row in rows]


def _with_risk(row: dict) -> dict:
    risk = row.get("risk_json")
    row["risk"] = json.loads(risk) if risk else None
    return row

from __future__ import annotations

import json
from pathlib import Path

from .audit import append_event
from .inventory import commit_inventory, preview_inventory
from .policy import PolicyError
from .reconcile import reconcile
from .util import new_id, sha256_bytes, utcnow

ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "range"
CONFIRM = "LOAD SEEDED RANGE SCENARIO"
MAX_BYTES = 2 * 1024 * 1024
EXPECTED = (
    "CVE-SYNTH-2026-0001",
    "CONTAINER-PRIVILEGED",
    "NET-PERMIT-ANY",
    "HOST-AUDIT-POLICY",
    "LOG-PRIVILEGED-LOGIN",
)


def _load_json(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise PolicyError("evidence file exceeds the size limit")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyError("evidence file must be UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise PolicyError("evidence file must be a JSON object")
    return parsed


def _record_import(tx, kind: str, filename: str, data: bytes, actor: str, count: int) -> str:
    import_id = new_id()
    tx.execute(
        """
        INSERT INTO evidence_imports (id, kind, filename, sha256, imported_at, imported_by, record_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (import_id, kind, filename, sha256_bytes(data), utcnow(), actor, count),
    )
    return import_id


def import_nvd(db, data: bytes, actor: str, filename: str = "nvd.json") -> dict:
    parsed = _load_json(data)
    items = parsed.get("items") or []
    if not items:
        raise PolicyError("NVD snapshot contains no items")
    with db.transaction() as tx:
        import_id = _record_import(tx, "nvd", filename, data, actor, len(items))
        for item in items:
            if not item.get("cve_id") or not item.get("product_name") or not item.get("version"):
                raise PolicyError("CVE item needs cve_id, product_name, and version")
            tx.execute(
                """
                INSERT INTO cve_items (id, import_id, cve_id, severity, description, product_name, version, source_ref)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    import_id,
                    item["cve_id"],
                    item.get("severity") or "unknown",
                    item.get("description") or "",
                    item["product_name"],
                    item["version"],
                    item.get("source_ref") or "offline-nvd-snapshot",
                ),
            )
        append_event(db, actor=actor, action="range.nvd_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"items": len(items), "evidence_kind": "imported"}, tx=tx)
    return {"import_id": import_id, "items": len(items), "evidence_kind": "imported"}


def import_packages(db, data: bytes, actor: str, filename: str = "packages.json") -> dict:
    parsed = _load_json(data)
    records = parsed.get("records") or []
    if not records:
        raise PolicyError("package evidence contains no records")
    with db.transaction() as tx:
        import_id = _record_import(tx, "packages", filename, data, actor, len(records))
        for record in records:
            tx.execute(
                """
                INSERT INTO package_observations (id, import_id, hostname, package_name, version, evidence_line)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (new_id(), import_id, record["hostname"], record["package"], record["version"], record.get("evidence_line") or f"{record['hostname']} {record['package']} {record['version']}"),
            )
        append_event(db, actor=actor, action="range.package_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"records": len(records)}, tx=tx)
    return {"import_id": import_id, "records": len(records)}


def import_containers(db, data: bytes, actor: str, filename: str = "containers.json") -> dict:
    parsed = _load_json(data)
    records = parsed.get("containers") or []
    if not records:
        raise PolicyError("container evidence contains no records")
    with db.transaction() as tx:
        import_id = _record_import(tx, "containers", filename, data, actor, len(records))
        for record in records:
            tx.execute(
                """
                INSERT INTO container_records (id, import_id, name, hostname, image, user_name, privileged, evidence_line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    import_id,
                    record.get("name") or record["hostname"],
                    record["hostname"],
                    record.get("image") or "",
                    record.get("user_name") or "",
                    1 if record.get("privileged") else 0,
                    record.get("evidence_line") or record["hostname"],
                ),
            )
        append_event(db, actor=actor, action="range.container_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"records": len(records)}, tx=tx)
    return {"import_id": import_id, "records": len(records)}


def import_logs(db, data: bytes, actor: str, filename: str = "logs.json") -> dict:
    parsed = _load_json(data)
    events = parsed.get("events") or []
    if not events:
        raise PolicyError("log evidence contains no events")
    with db.transaction() as tx:
        import_id = _record_import(tx, "logs", filename, data, actor, len(events))
        for event in events:
            tx.execute(
                "INSERT INTO log_events (id, import_id, hostname, message, evidence_line) VALUES (?, ?, ?, ?, ?)",
                (new_id(), import_id, event["hostname"], event["message"], event.get("evidence_line") or event["message"]),
            )
        append_event(db, actor=actor, action="range.log_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"events": len(events)}, tx=tx)
    return {"import_id": import_id, "events": len(events)}


def import_network(db, data: bytes, actor: str, filename: str = "network.json") -> dict:
    parsed = _load_json(data)
    rules = parsed.get("rules") or []
    if not rules:
        raise PolicyError("network evidence contains no rules")
    with db.transaction() as tx:
        import_id = _record_import(tx, "network", filename, data, actor, len(rules))
        for rule in rules:
            tx.execute(
                """
                INSERT INTO network_rules (id, import_id, device_name, action, source, destination, port, evidence_line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    import_id,
                    rule["device_name"],
                    rule["action"],
                    rule["source"],
                    rule["destination"],
                    str(rule["port"]),
                    rule.get("evidence_line") or f"{rule['device_name']} {rule['action']} {rule['source']} {rule['destination']} {rule['port']}",
                ),
            )
        append_event(db, actor=actor, action="range.network_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"rules": len(rules)}, tx=tx)
    return {"import_id": import_id, "rules": len(rules)}


def import_host_settings(db, data: bytes, actor: str, filename: str = "host_settings.json") -> dict:
    parsed = _load_json(data)
    records = parsed.get("records") or []
    if not records:
        raise PolicyError("host setting evidence contains no records")
    with db.transaction() as tx:
        import_id = _record_import(tx, "host_settings", filename, data, actor, len(records))
        for record in records:
            tx.execute(
                """
                INSERT INTO host_settings (id, import_id, hostname, setting_key, setting_value, evidence_line)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (new_id(), import_id, record["hostname"], record["key"], record["value"], record.get("evidence_line") or f"{record['hostname']} {record['key']}={record['value']}"),
            )
        append_event(db, actor=actor, action="range.host_setting_import", outcome="imported", object_type="evidence_import", object_id=import_id, detail={"records": len(records)}, tx=tx)
    return {"import_id": import_id, "records": len(records)}


def _risk(asset_name: str, title: str, severity: str, evidence: str, source: str, owner_impact: str) -> dict:
    return {
        "commander": f"{asset_name}: {title}. Severity {severity}. {owner_impact} Source: {source}.",
        "system_owner": f"Evidence '{evidence}' matched {source}. Review the cited source before choosing a fix. The imported text was not executed.",
        "data_owner": f"Data handled by {asset_name} is affected while this {severity} finding remains open. Source: {source}.",
        "source": source,
    }


def _assets_by_host(db) -> dict[str, dict]:
    found = {}
    for asset in db.query("SELECT * FROM assets"):
        if asset.get("hostname"):
            found[asset["hostname"].lower()] = asset
    return found


def assess_range(db, actor: str) -> dict:
    hosts = _assets_by_host(db)
    found = []
    checks = []
    for package in db.query("SELECT * FROM package_observations"):
        for cve in db.query(
            "SELECT * FROM cve_items WHERE lower(product_name) = ? AND version = ?",
            (package["package_name"].lower(), package["version"]),
        ):
            checks.append(_check(hosts, package["hostname"], cve["cve_id"], "fail", cve["severity"], package["evidence_line"], cve["source_ref"], f"{cve['cve_id']} matches installed {package['package_name']} {package['version']}", "The listed package version is in the offline vulnerability snapshot."))
    for container in db.query("SELECT * FROM container_records"):
        if container["privileged"] or (container["user_name"] or "").lower() == "root":
            checks.append(_check(hosts, container["hostname"], "CONTAINER-PRIVILEGED", "fail", "high", container["evidence_line"], "imported container inventory", "Container is privileged or runs as root.", "A privileged container can change the host that stores its data."))
    for rule in db.query("SELECT * FROM network_rules"):
        if rule["action"].lower() == "permit" and rule["source"].lower() == "any" and rule["destination"].lower() == "any":
            checks.append(_check(hosts, rule["device_name"], "NET-PERMIT-ANY", "fail", "high", rule["evidence_line"], "imported network configuration", f"Permit-any rule on port {rule['port']}.", "Any source can reach the listed port."))
    for event in db.query("SELECT * FROM log_events"):
        if event["message"] == "privileged_login user=root":
            checks.append(_check(hosts, event["hostname"], "LOG-PRIVILEGED-LOGIN", "fail", "medium", event["evidence_line"], "imported log", "A privileged login was recorded.", "The log shows an administrator login that the system owner has not yet explained."))
    for setting in db.query("SELECT * FROM host_settings"):
        if setting["setting_key"] == "audit_policy" and setting["setting_value"] != "enabled":
            checks.append(_check(hosts, setting["hostname"], "HOST-AUDIT-POLICY", "fail", "medium", setting["evidence_line"], "imported host configuration", "Audit policy is not enabled.", "Activity on this host can go unrecorded."))
    assessment_id = new_id()
    collected = utcnow()
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO assessments (id, asset_id, benchmark_row_id, created_at, created_by, status) VALUES (?, ?, ?, ?, ?, 'completed')",
            (assessment_id, "range", "range-evidence", collected, actor),
        )
        for check in checks:
            if check is None:
                continue
            finding_id = new_id()
            tx.execute(
                """
                INSERT INTO findings (
                  id, assessment_id, asset_id, benchmark_row_id, rule_id, rule_version, classification, result,
                  observation, collected_at, check_impl_version, evidence_ref, evidence_kind, rule_source, risk_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    assessment_id,
                    check["asset_id"],
                    "range-evidence",
                    check["rule_id"],
                    "snapshot",
                    "evidence_check",
                    "fail",
                    check["observation"],
                    collected,
                    "range-registry-1",
                    check["evidence"],
                    "imported",
                    "imported",
                    json.dumps(check["risk"]),
                ),
            )
            found.append(check["rule_id"])
        append_event(db, actor=actor, action="range.assess", outcome="completed", object_type="assessment", object_id=assessment_id, detail={"found": found}, tx=tx)
    return {"assessment_id": assessment_id, "found": found}


def _check(hosts, hostname, rule_id, result, severity, evidence, source, title, impact):
    asset = hosts.get((hostname or "").lower())
    if not asset:
        return None
    return {
        "asset_id": asset["id"],
        "rule_id": rule_id,
        "result": result,
        "evidence": evidence,
        "observation": f"{title} Evidence: {evidence}. Steps remain unexecuted until a person approves a plan.",
        "risk": _risk(asset.get("hostname") or hostname, title, severity, evidence, source, impact),
    }


def load_scenario(db, settings, actor: str, confirmation: str) -> dict:
    if confirmation != CONFIRM:
        raise PolicyError("confirm the seeded range scenario before loading it")
    if db.query_one("SELECT id FROM scenario_runs LIMIT 1"):
        raise PolicyError("the seeded scenario is already loaded in this database")
    inventory = (ROOT / "inventory.csv").read_bytes()
    preview = preview_inventory(db, "range_inventory.csv", inventory, None, None)
    commit_inventory(db, preview["preview_id"], actor, True, True)
    reconcile(db, actor)
    import_nvd(db, (ROOT / "nvd_snapshot.json").read_bytes(), actor, "nvd_snapshot.json")
    import_packages(db, (ROOT / "packages.json").read_bytes(), actor, "packages.json")
    import_containers(db, (ROOT / "containers.json").read_bytes(), actor, "containers.json")
    import_logs(db, (ROOT / "logs.json").read_bytes(), actor, "logs.json")
    import_network(db, (ROOT / "network.json").read_bytes(), actor, "network.json")
    import_host_settings(db, (ROOT / "host_settings.json").read_bytes(), actor, "host_settings.json")
    started = utcnow()
    run_id = new_id()
    with db.transaction() as tx:
        tx.execute("INSERT INTO scenario_runs (id, started_at, actor) VALUES (?, ?, ?)", (run_id, started, actor))
        append_event(db, actor=actor, action="range.scenario_load", outcome="imported", object_type="scenario", object_id=run_id, detail={"evidence_kind": "imported"}, tx=tx)
    assessed = assess_range(db, actor)
    return {"scenario_id": run_id, "started_at": started, "found": assessed["found"], "statement": "Seeded synthetic range data. No live network was contacted and no change was approved."}


def score_scenario(db) -> dict:
    run = db.query_one("SELECT * FROM scenario_runs ORDER BY started_at DESC LIMIT 1")
    if not run:
        raise PolicyError("load the seeded scenario before scoring it", 404)
    rows = db.query("SELECT rule_id, risk_json, collected_at FROM findings WHERE classification = 'evidence_check'")
    found = sorted({row["rule_id"] for row in rows})
    missed = [item for item in EXPECTED if item not in found]
    approved = db.query(
        """
        SELECT approvals.created_at, proposals.action_type, proposals.rule_id
        FROM approvals JOIN proposals ON proposals.id = approvals.proposal_id
        WHERE approvals.decision = 'approved' AND proposals.rule_id IN ({})
        ORDER BY approvals.created_at
        """.format(",".join("?" for _ in EXPECTED)),
        EXPECTED,
    )
    from datetime import datetime

    seconds = None
    if approved:
        started = datetime.fromisoformat(run["started_at"])
        ready = datetime.fromisoformat(approved[0]["created_at"])
        seconds = max(0, int((ready - started).total_seconds()))
    plans = db.query("SELECT action_type, status FROM execution_intents WHERE action_type = 'procedure'")
    return {
        "expected": list(EXPECTED),
        "found": found,
        "missed": missed,
        "found_count": len(found),
        "missed_count": len(missed),
        "import_started_at": run["started_at"],
        "seconds_to_plan": seconds,
        "plan_state": "approved_plan_recorded" if seconds is not None else "awaiting_approval",
        "plans_not_executed": sum(1 for row in plans if row["status"] == "not_executed"),
        "plans_executed": sum(1 for row in plans if row["status"] not in {"not_executed", "intent"}),
        "false_positives": [row["rule_id"] for row in rows if row["rule_id"] not in EXPECTED],
    }

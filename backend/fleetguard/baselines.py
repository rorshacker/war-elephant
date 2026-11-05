from __future__ import annotations

import json

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .stig import list_benchmarks
from .updates import KINDS, list_updates
from .util import new_id, utcnow

UNAVAILABLE = "baseline unavailable—import required"
CONFIRMATION = "confirmation required"

PLATFORM_RULES = [
    {
        "name": "synthetic-win-client",
        "os_tokens": ("windows 10", "windows 11"),
        "exclude_tokens": ("server",),
        "device_types": ("workstation", "client", "desktop"),
        "benchmark_id": "FLEETGUARD-SYNTH-WIN10",
    },
    {
        "name": "synthetic-win-server",
        "os_tokens": ("windows server",),
        "exclude_tokens": (),
        "device_types": ("server",),
        "benchmark_id": "FLEETGUARD-SYNTH-WIN-SERVER",
    },
    {
        "name": "synthetic-rhel",
        "os_tokens": ("rhel", "red hat enterprise"),
        "exclude_tokens": (),
        "device_types": ("server",),
        "benchmark_id": "FLEETGUARD-SYNTH-RHEL8",
    },
    {
        "name": "public-windows-11",
        "os_tokens": ("windows 11",),
        "exclude_tokens": ("server",),
        "device_types": ("workstation", "client", "desktop"),
        "benchmark_id": "Windows_11_STIG",
        "benchmark_ids": ("Windows_11_STIG", "Microsoft_Windows_11_STIG"),
    },
    {
        "name": "public-rhel-8",
        "os_tokens": ("rhel 8", "red hat enterprise linux 8"),
        "exclude_tokens": (),
        "device_types": ("server",),
        "benchmark_id": "RHEL_8_STIG",
    },
    {
        "name": "public-container-image",
        "os_tokens": ("container image", "docker"),
        "exclude_tokens": (),
        "device_types": ("container",),
        "benchmark_id": "Container_Image_STIG",
    },
]


def recommend(asset: dict, benchmarks: list[dict]) -> dict:
    questions = []
    os_name = (asset.get("os_name") or "").lower()
    device = (asset.get("device_type") or "").lower()
    flags = asset.get("flags") or []
    if isinstance(flags, str):
        flags = json.loads(flags)
    if "os_conflict" in flags or not asset.get("os_name"):
        if not asset.get("os_name"):
            questions.append("operating system was not recorded")
        if "os_conflict" in flags:
            questions.append("recorded operating systems disagree across sources")
        return _result(asset, None, CONFIRMATION, questions, None)
    hits = []
    for rule in PLATFORM_RULES:
        if any(token in os_name for token in rule["exclude_tokens"]):
            continue
        if not any(token in os_name for token in rule["os_tokens"]):
            continue
        if device not in rule["device_types"]:
            continue
        hits.append(rule)
    if not hits:
        questions.append("no deterministic platform mapping matched the recorded OS and device type")
        return _result(asset, None, CONFIRMATION, questions, None)
    available = []
    for rule in hits:
        accepted = rule.get("benchmark_ids") or (rule["benchmark_id"],)
        imported = [row for row in benchmarks if row["benchmark_id"] in accepted]
        if imported:
            available.append((rule, imported))
    if len(available) > 1:
        questions.append("multiple imported platform mappings matched")
        return _result(asset, None, CONFIRMATION, questions, None)
    if len(available) == 1:
        rule, imported = available[0]
        newest = next(row for row in imported if row["version_label"] == "newest imported version")
        explanation = (
            f"Recorded operating system '{asset.get('os_name')}' and device type '{asset.get('device_type')}' "
            f"match imported baseline config {newest['benchmark_id']}."
        )
        questions.append("confirm the imported baseline version before assessment")
        matched = dict(rule)
        matched["benchmark_id"] = newest["benchmark_id"]
        return _result(asset, matched, "recommended", questions, explanation, newest)
    if len(hits) == 1:
        rule = hits[0]
        explanation = (
            f"Recorded operating system '{asset.get('os_name')}' and device type '{asset.get('device_type')}' "
            "have no imported baseline config."
        )
        questions.append(UNAVAILABLE)
        return _result(asset, rule, UNAVAILABLE, questions, explanation)
    questions.append(UNAVAILABLE)
    questions.append("multiple platform mappings matched")
    return _result(asset, None, UNAVAILABLE, questions, None)


def _result(asset, rule, status, questions, explanation, benchmark=None) -> dict:
    return {
        "asset_id": asset["id"],
        "hostname": asset.get("hostname"),
        "status": status,
        "mapping_name": rule["name"] if rule else None,
        "benchmark_id": rule["benchmark_id"] if rule else None,
        "benchmark_row_id": benchmark["id"] if benchmark else None,
        "version": benchmark["version"] if benchmark else None,
        "version_label": benchmark["version_label"] if benchmark else None,
        "applicability": explanation or status,
        "questions": questions,
    }


def recommendations(db: Database) -> list[dict]:
    benchmarks = list_benchmarks(db)
    assets = db.query("SELECT * FROM assets ORDER BY display_name")
    latest = _latest_assignments(db)
    results = []
    for row in assets:
        public_flags = json.loads(row["flags_json"])
        asset = {"id": row["id"], "hostname": row["hostname"], "os_name": row["os_name"], "device_type": row["device_type"], "flags": public_flags}
        item = recommend(asset, benchmarks)
        assignment = latest.get(row["id"])
        item["selected"] = bool(row["selected"])
        item["assigned"] = _current_configs(db).get(row["id"], [])
        item["assignment"] = assignment
        if assignment and item.get("benchmark_row_id") and assignment.get("benchmark_row_id") != item["benchmark_row_id"]:
            item["questions"] = list(item["questions"]) + ["a newer imported version is available; the current assignment was not moved"]
        results.append(item)
    return results


def list_configs(db: Database) -> list[dict]:
    configs = []
    for row in list_benchmarks(db):
        configs.append({
            "kind": "stig",
            "source_id": row["id"],
            "label": row["title"] or row["benchmark_id"],
            "detail": f"{row['benchmark_id']} · version {row['version']} · {row['rule_count']} rules · {row['version_label']}",
        })
    for row in list_updates(db):
        configs.append({
            "kind": row["kind"],
            "source_id": row["id"],
            "label": f"{row['label']} · {row['original_filename']}",
            "detail": "Imported file. The checksum is not publisher authentication.",
        })
    return configs


def assign_configs(db: Database, asset_ids: list, items: list, actor: str) -> dict:
    if not isinstance(asset_ids, list) or not asset_ids:
        raise PolicyError("select at least one asset")
    if not isinstance(items, list) or not items:
        raise PolicyError("select at least one baseline config")
    resolved = [_resolve_config(db, item) for item in items]
    created = utcnow()
    with db.transaction() as tx:
        for asset_id in asset_ids:
            asset = tx.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
            if not asset:
                raise PolicyError("asset not found", 404)
            if not asset["selected"]:
                raise PolicyError("assign baseline configs only to selected assets")
            for kind, source_id, label in resolved:
                tx.execute(
                    """
                    INSERT INTO baseline_assignments (
                      id, asset_id, benchmark_row_id, benchmark_id, version_label, mapping_name, applicability,
                      status, questions_json, override_reason, actor, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'assigned', ?, ?, ?, ?)
                    """,
                    (
                        new_id(),
                        asset_id,
                        source_id,
                        label,
                        "imported",
                        kind,
                        "Assigned imported baseline config. This does not scan the host or mark anything compliant.",
                        json.dumps([]),
                        "Assigned imported baseline config",
                        actor,
                        created,
                    ),
                )
                append_event(
                    db,
                    actor=actor,
                    action="baseline.assign",
                    outcome="assigned",
                    object_type="asset",
                    object_id=asset_id,
                    detail={"kind": kind, "source_id": source_id, "executed": False},
                    tx=tx,
                )
    return {"assets": len(asset_ids), "configs": len(resolved), "executed": False}


def _resolve_config(db: Database, item) -> tuple[str, str, str]:
    if not isinstance(item, dict):
        raise PolicyError("each baseline config needs a kind and a source")
    kind = str(item.get("kind") or "")
    source_id = str(item.get("source_id") or "")
    if kind == "stig":
        row = db.query_one("SELECT * FROM stig_benchmarks WHERE id = ?", (source_id,))
        if not row:
            raise PolicyError("benchmark not found", 404)
        return kind, row["id"], row["title"] or row["benchmark_id"]
    if kind not in KINDS:
        raise PolicyError("baseline kind must be stig, ecu, fam, msu, or iava")
    row = db.query_one("SELECT * FROM update_imports WHERE id = ? AND kind = ?", (source_id, kind))
    if not row:
        raise PolicyError("that update is not imported", 404)
    return kind, row["id"], f"{KINDS[kind]} · {row['original_filename']}"


def _current_configs(db: Database) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in db.query("SELECT * FROM baseline_assignments ORDER BY created_at"):
        grouped.setdefault(row["asset_id"], []).append(row)
    current = {}
    for asset_id, items in grouped.items():
        stamp = items[-1]["created_at"]
        current[asset_id] = [
            {"kind": row["mapping_name"], "source_id": row["benchmark_row_id"], "label": row["benchmark_id"], "status": row["status"]}
            for row in items
            if row["created_at"] == stamp
        ]
    return current


def _latest_assignments(db: Database) -> dict[str, dict]:
    stig_ids = {row["id"] for row in db.query("SELECT id FROM stig_benchmarks")}
    latest = {}
    for asset_id, configs in _current_configs(db).items():
        chosen = next((row for row in reversed(configs) if row["source_id"] in stig_ids), None)
        if not chosen:
            continue
        latest[asset_id] = {
            "id": None,
            "benchmark_row_id": chosen["source_id"],
            "benchmark_id": chosen["label"],
            "status": chosen["status"] if chosen["status"] in {"confirmed", "overridden"} else "overridden",
            "applicability": "Assigned imported baseline config.",
            "override_reason": None,
            "version_label": "imported",
            "created_at": None,
        }
    rows = db.query("SELECT * FROM baseline_assignments ORDER BY created_at")
    for row in rows:
        if row["benchmark_row_id"] not in stig_ids:
            continue
        if row["asset_id"] not in latest:
            continue
        if latest[row["asset_id"]]["benchmark_row_id"] == row["benchmark_row_id"]:
            latest[row["asset_id"]] = {
                "id": row["id"],
                "benchmark_row_id": row["benchmark_row_id"],
                "benchmark_id": row["benchmark_id"],
                "status": row["status"] if row["status"] in {"confirmed", "overridden"} else "overridden",
                "applicability": row["applicability"],
                "override_reason": row["override_reason"],
                "version_label": row["version_label"],
                "created_at": row["created_at"],
            }
    return latest


def confirm_baseline(
    db: Database,
    asset_id: str,
    actor: str,
    mode: str,
    benchmark_row_id: str | None = None,
    reason: str | None = None,
) -> dict:
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    item = next(entry for entry in recommendations(db) if entry["asset_id"] == asset_id)
    if mode == "confirm":
        if item["status"] != "recommended" or not item["benchmark_row_id"]:
            raise PolicyError("this asset has no recommended imported baseline to confirm")
        chosen = item["benchmark_row_id"]
        status = "confirmed"
        mapping = item["mapping_name"]
        applicability = item["applicability"]
        benchmark_id = item["benchmark_id"]
        version_label = item["version_label"]
        override = None
    elif mode == "override":
        if len(reason or "") < 8:
            raise PolicyError("an override reason is required")
        benchmark = db.query_one("SELECT * FROM stig_benchmarks WHERE id = ?", (benchmark_row_id,))
        if not benchmark:
            raise PolicyError("benchmark not found", 404)
        chosen = benchmark["id"]
        status = "overridden"
        mapping = item["mapping_name"]
        applicability = f"Operator override. Recommendation was: {item['applicability']}"
        benchmark_id = benchmark["benchmark_id"]
        labels = {row["id"]: row["version_label"] for row in list_benchmarks(db)}
        version_label = labels.get(benchmark["id"], "operator selected imported version")
        override = reason
    else:
        raise PolicyError("mode must be confirm or override")
    assignment_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO baseline_assignments (
              id, asset_id, benchmark_row_id, benchmark_id, version_label, mapping_name, applicability,
              status, questions_json, override_reason, actor, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assignment_id,
                asset_id,
                chosen,
                benchmark_id,
                version_label,
                mapping,
                applicability,
                status,
                json.dumps(item["questions"]),
                override,
                actor,
                utcnow(),
            ),
        )
        append_event(
            db,
            actor=actor,
            action="baseline.assign",
            outcome=status,
            object_type="asset",
            object_id=asset_id,
            detail={"benchmark_id": benchmark_id, "benchmark_row_id": chosen, "mode": mode},
            tx=tx,
        )
    return {"assignment_id": assignment_id, "status": status, "benchmark_row_id": chosen, "benchmark_id": benchmark_id}

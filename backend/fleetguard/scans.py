from __future__ import annotations

import json

from . import assess
from .adapters import INSTALL_TOKEN, LocalFileAdapter
from .audit import append_event
from .db import Database
from .policy import PolicyError
from .settings import Settings
from .updates import KINDS, read_imported_msu
from .util import new_id, utcnow

LOCAL = LocalFileAdapter()
KINDS_WITH_STIG = {"stig": "STIG", **KINDS}


def run_scan(db: Database, settings: Settings, items: list, actor: str) -> dict:
    if not isinstance(items, list) or not items:
        raise PolicyError("select at least one update to scan")
    results = []
    for item in items:
        if not isinstance(item, dict):
            raise PolicyError("each scan selection needs a kind and a source")
        result = _one(db, settings, str(item.get("kind") or ""), str(item.get("source_id") or ""), actor)
        scan_id = new_id()
        created = utcnow()
        with db.transaction() as tx:
            tx.execute(
                """
                INSERT INTO content_scans (id, kind, source_id, label, status, observation, created_at, created_by, assets_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    result["kind"],
                    result["source_id"],
                    result["label"],
                    result["status"],
                    result["observation"],
                    created,
                    actor,
                    json.dumps([
                        {"asset_id": asset["asset_id"], "hostname": asset["hostname"], "presence": asset["presence"]}
                        for asset in result.get("assets") or []
                    ]),
                ),
            )
            append_event(
                db,
                actor=actor,
                action="scan.apply",
                outcome=result["status"],
                object_type="content_scan",
                object_id=scan_id,
                detail={"kind": result["kind"], "source_id": result["source_id"], "executed": False},
                tx=tx,
            )
        results.append({"id": scan_id, "created_at": created, **result})
    return {"results": results}


def list_scans(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM content_scans ORDER BY created_at DESC LIMIT 40")
    for row in rows:
        raw = row.pop("assets_json", "[]")
        try:
            row["assets"] = json.loads(raw or "[]")
        except json.JSONDecodeError:
            row["assets"] = []
    return rows


def material_label(db: Database, kind: str, source_id: str) -> dict:
    if kind == "stig":
        row = db.query_one("SELECT * FROM stig_benchmarks WHERE id = ?", (source_id,))
        if not row:
            raise PolicyError("benchmark not found", 404)
        return {"kind": kind, "source_id": source_id, "label": row["title"] or row["benchmark_id"], "benchmark_id": row["benchmark_id"]}
    if kind not in KINDS:
        raise PolicyError("update kind must be stig, ecu, fam, msu, or iava")
    row = db.query_one("SELECT * FROM update_imports WHERE id = ? AND kind = ?", (source_id, kind))
    if not row:
        raise PolicyError("that update is not imported", 404)
    return {"kind": kind, "source_id": source_id, "label": f"{KINDS[kind]} · {row['original_filename']}", "benchmark_id": kind}
def presence_token(kind: str, source_id: str) -> str:
    token = f"{kind}:{source_id}"
    if not INSTALL_TOKEN.match(token):
        raise PolicyError("that material cannot be checked for presence")
    return token


def _one(db: Database, settings: Settings, kind: str, source_id: str, actor: str) -> dict:
    label = material_label(db, kind, source_id)
    token = presence_token(kind, source_id)
    assets = db.query("SELECT id, hostname, lab_target_path FROM assets WHERE selected = 1")
    checked = []
    for asset in assets:
        checked.append(_asset_presence(settings, asset, token))
    observable = [row for row in checked if row["presence"] in {"present", "absent"}]
    if not observable:
        status = "not_observable"
        observation = "No selected asset has a readable lab file. No host package inventory was queried, the imported file was not executed, and nothing was marked compliant."
    else:
        states = {row["presence"] for row in observable}
        status = next(iter(states)) if len(states) == 1 else "mixed"
        parts = [f"{row['hostname'] or row['asset_id']}: {row['presence']}" for row in checked]
        observation = (
            "; ".join(parts)
            + ". Presence is the lab file key installed. The imported file was not executed and was not marked compliant."
        )
    package_read = kind != "msu"
    if kind == "msu":
        try:
            package = read_imported_msu(db, settings, source_id)
        except PolicyError as exc:
            for row in checked:
                row["presence"] = "not_observable"
            status = "not_observable"
            observation = f"{exc.message} The MSU was not suggested for any workstation."
        else:
            package_read = True
            observation = f"{package['statement']} {observation}"
    result = {
        "kind": kind,
        "source_id": source_id,
        "label": label["label"],
        "status": status,
        "observation": observation,
        "executed": False,
        "package_read": package_read,
        "install_offered": package_read and any(row["presence"] == "absent" for row in checked),
        "assets": checked,
    }
    if kind == "stig":
        assessed = assess.assess_imported_benchmark(db, settings, source_id, actor)
        result["stig_status"] = assessed["status"]
        result["observation"] = f"{observation} Checklist read: {assessed['observation']}"
    return result


def _asset_presence(settings: Settings, asset: dict, token: str) -> dict:
    base = {"asset_id": asset["id"], "hostname": asset["hostname"]}
    if not asset["lab_target_path"]:
        return base | {"presence": "not_observable"}
    try:
        data, _digest, _raw = LOCAL.read(settings, asset["lab_target_path"])
    except PolicyError:
        return base | {"presence": "not_observable"}
    recorded = [part for part in data.get("installed", "").split(",") if part]
    return base | {"presence": "present" if token in recorded else "absent"}

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .util import canon, new_id, sha256_text, utcnow

NO_AD_TYPES = {"switch", "printer", "appliance", "standalone"}
BLOCKING_FLAGS = {"duplicate_address", "disabled_ad_observed", "uncertain_match", "os_conflict"}


def norm_host(value: str | None) -> str | None:
    if not value:
        return None
    token = value.strip().lower().rstrip(".")
    if not token:
        return None
    return token.split(".")[0]


def _spreadsheet_sources(db: Database) -> list[dict]:
    rows = db.query(
        """
        SELECT r.*, i.imported_at FROM inventory_rows r
        JOIN inventory_imports i ON i.id = r.import_id
        """
    )
    sources = []
    for row in rows:
        sources.append(
            {
                "ref": f"spreadsheet:{row['id']}",
                "kind": "spreadsheet",
                "hostname": row["hostname"],
                "norm": norm_host(row["hostname"]),
                "ip": row["ip_address"],
                "os": row["os_name"],
                "device_type": (row["device_type"] or "").lower() or None,
                "owner": row["owner"],
                "criticality": row["criticality"],
                "enabled": None,
                "observed_at": row["imported_at"],
                "evidence_kind": "imported",
                "detail": {"row_number": row["row_number"], "enclave": row["enclave"], "department": row["department"]},
            }
        )
    return sources


def _ad_sources(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM ad_computers")
    sources = []
    for row in rows:
        hostname = row["dns_hostname"] or row["computer_name"]
        sources.append(
            {
                "ref": f"ad:{row['id']}",
                "kind": "ad",
                "hostname": hostname,
                "norm": norm_host(row["computer_name"] or hostname),
                "ip": None,
                "os": " ".join(part for part in (row["os_name"], row["os_version"]) if part).strip() or None,
                "device_type": None,
                "owner": None,
                "criticality": None,
                "enabled": None if row["enabled"] is None else bool(row["enabled"]),
                "observed_at": row["observed_at"],
                "evidence_kind": row["evidence_kind"],
                "detail": {
                    "object_guid": row["object_guid"],
                    "distinguished_name": row["distinguished_name"],
                    "last_logon_timestamp": row["last_logon_timestamp"],
                    "online_status": "unknown",
                    "online_status_reason": "lastLogonTimestamp is not treated as current online status",
                    "source_mode": row["source_mode"],
                },
            }
        )
    return sources


def _observation_sources(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM observations ORDER BY observed_at")
    grouped: dict[str, dict] = {}
    for row in rows:
        current = grouped.get(row["address"])
        if current is None:
            grouped[row["address"]] = {
                "ref": f"discovery:{row['address']}",
                "kind": "discovery",
                "hostname": row["hostname"],
                "norm": norm_host(row["hostname"]),
                "ip": row["address"],
                "os": None,
                "device_type": None,
                "owner": None,
                "criticality": None,
                "enabled": None,
                "observed_at": row["observed_at"],
                "evidence_kind": row["evidence_kind"],
                "detail": {"probes": []},
            }
            current = grouped[row["address"]]
        current["observed_at"] = row["observed_at"]
        if row["hostname"] and not current["hostname"]:
            current["hostname"] = row["hostname"]
            current["norm"] = norm_host(row["hostname"])
        current["detail"]["probes"].append(
            {"port": row["port"], "status": row["status"], "note": row["note"], "evidence_kind": row["evidence_kind"]}
        )
    return list(grouped.values())


def _find(parent: dict[str, str], ref: str) -> str:
    while parent[ref] != ref:
        parent[ref] = parent[parent[ref]]
        ref = parent[ref]
    return ref


def _union(parent: dict[str, str], left: str, right: str) -> None:
    a, b = _find(parent, left), _find(parent, right)
    if a != b:
        parent[b] = a


def build_groups(sources: list[dict], links: list[dict]) -> tuple[list[dict], list[dict]]:
    parent = {source["ref"]: source["ref"] for source in sources}
    distinct = set()
    manual = []
    for link in links:
        pair = tuple(sorted((link["left_ref"], link["right_ref"])))
        if link["decision"] == "mark_distinct":
            distinct.add(pair)
        elif link["decision"] == "confirm_same":
            manual.append(pair)
    by_host = defaultdict(list)
    for source in sources:
        if source["norm"]:
            by_host[source["norm"]].append(source["ref"])
    for members in by_host.values():
        for index, left in enumerate(members):
            for right in members[index + 1 :]:
                if tuple(sorted((left, right))) in distinct:
                    continue
                _union(parent, left, right)
    manual_pairs = set()
    for left, right in manual:
        if left not in parent or right not in parent:
            continue
        if tuple(sorted((left, right))) in distinct:
            continue
        _union(parent, left, right)
        manual_pairs.add(tuple(sorted((left, right))))
    by_root = defaultdict(list)
    for source in sources:
        by_root[_find(parent, source["ref"])].append(source)
    ip_refs = defaultdict(list)
    for source in sources:
        if source["ip"]:
            ip_refs[source["ip"]].append(source["ref"])
    flags: dict[str, set[str]] = defaultdict(set)
    conflicts = []
    for address, refs in ip_refs.items():
        doc_refs = [ref for ref in refs if ref.startswith("spreadsheet:")]
        groups = {_find(parent, ref) for ref in refs}
        if len(doc_refs) > 1:
            for ref in doc_refs:
                flags[_find(parent, ref)].add("duplicate_address")
            conflicts.append({"kind": "duplicate_address", "detail": {"ip_address": address, "refs": doc_refs}})
        kinds = {ref.split(":", 1)[0] for ref in refs}
        if len(groups) > 1 and len(kinds) > 1:
            for ref in refs:
                flags[_find(parent, ref)].add("address_overlap")
            conflicts.append({"kind": "address_overlap", "detail": {"ip_address": address, "refs": refs, "merged": False}})
        members = [source for source in sources if source["ref"] in set(refs)]
        if any(item["kind"] == "ad" and item["enabled"] is False for item in members) and any(item["kind"] == "discovery" for item in members):
            for ref in refs:
                flags[_find(parent, ref)].add("disabled_ad_observed")
            conflicts.append({"kind": "disabled_ad_observed", "detail": {"ip_address": address, "refs": refs}})
    groups = []
    for members in by_root.values():
        refs = sorted(member["ref"] for member in members)
        root = _find(parent, members[0]["ref"])
        group_flags = set(flags.get(root, set()))
        ips = {member["ip"] for member in members if member["ip"]}
        if len(ips) > 1:
            group_flags.add("uncertain_match")
        os_values = {member["os"] for member in members if member["os"]}
        if len(os_values) > 1:
            group_flags.add("os_conflict")
        if any((member["device_type"] or "") in NO_AD_TYPES for member in members) and not any(member["kind"] == "ad" for member in members):
            group_flags.add("no_ad_expected")
        if any(member["kind"] == "ad" and member["enabled"] is False for member in members) and any(member["kind"] == "discovery" for member in members):
            group_flags.add("disabled_ad_observed")
        linked = any(tuple(sorted(pair)) in manual_pairs for pair in _pairs(refs))
        if linked:
            basis = "manual_link"
        elif len(members) > 1:
            basis = "hostname_provisional"
        else:
            basis = "single_source"
        if basis == "hostname_provisional":
            group_flags.add("provisional_hostname")
        groups.append({"refs": refs, "members": members, "flags": group_flags, "match_basis": basis})
    return groups, conflicts


def _pairs(refs: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for index, left in enumerate(refs):
        for right in refs[index + 1 :]:
            pairs.append((left, right))
    return pairs


def _confidence(basis: str, flags: set[str], decision: str | None, members: list[dict]) -> str:
    if decision == "confirm_identity":
        return "high"
    if basis == "hostname_provisional" or flags & BLOCKING_FLAGS or "address_overlap" in flags:
        return "low"
    if basis == "manual_link" and decision == "confirm_identity":
        return "high"
    if basis == "single_source" and any(member["hostname"] for member in members):
        return "medium"
    return "low"


def assessment_allowed(asset: dict) -> bool:
    flags = set(json.loads(asset["flags_json"]))
    if "provisional_hostname" in flags and asset.get("human_decision") != "confirm_identity":
        return False
    if flags & BLOCKING_FLAGS and asset.get("human_decision") not in {"confirm_identity", "accepted_with_risk"}:
        return False
    return True


def reconcile(db: Database, actor: str) -> dict:
    sources = _spreadsheet_sources(db) + _ad_sources(db) + _observation_sources(db)
    links = db.query("SELECT * FROM identity_links")
    groups, conflicts = build_groups(sources, links)
    now = utcnow()
    with db.transaction() as tx:
        states = {row["group_key"]: row for row in tx.query("SELECT * FROM asset_state")}
        tx.execute("DELETE FROM assets")
        tx.execute("DELETE FROM conflicts")
        assets = []
        for group in groups:
            group_key = sha256_text(canon(group["refs"]))
            state = states.get(group_key, {})
            members = group["members"]
            spreadsheet = next((member for member in members if member["kind"] == "spreadsheet"), None)
            named = next((member for member in members if member["hostname"]), None)
            addressed = next((member for member in members if member["ip"]), None)
            os_observations = [
                {"source": member["kind"], "os": member["os"], "evidence_kind": member["evidence_kind"]}
                for member in members
                if member["os"]
            ]
            flags = sorted(group["flags"])
            decision = state.get("human_decision")
            confidence = _confidence(group["match_basis"], set(flags), decision, members)
            display = (spreadsheet or named or addressed or members[0])
            display_name = display.get("hostname") or display.get("ip") or display["ref"]
            chosen_os = None if "os_conflict" in flags else next((item["os"] for item in os_observations), None)
            asset = {
                "id": group_key,
                "display_name": display_name,
                "hostname": (spreadsheet or named or {}).get("hostname") if (spreadsheet or named) else None,
                "ip_address": (spreadsheet or addressed or {}).get("ip") if (spreadsheet or addressed) else None,
                "os_name": chosen_os,
                "device_type": next((member["device_type"] for member in members if member["device_type"]), None),
                "owner": next((member["owner"] for member in members if member["owner"]), None),
                "criticality": next((member["criticality"] for member in members if member["criticality"]), None),
                "match_basis": group["match_basis"],
                "flags": flags,
                "identity_confidence": confidence,
                "sources": [
                    {
                        "ref": member["ref"],
                        "kind": member["kind"],
                        "evidence_kind": member["evidence_kind"],
                        "hostname": member["hostname"],
                        "ip_address": member["ip"],
                        "observed_at": member["observed_at"],
                        "enabled": member["enabled"],
                        "os": member["os"],
                        "detail": member["detail"],
                    }
                    for member in members
                ],
                "freshness": {
                    "spreadsheet": next((member["observed_at"] for member in members if member["kind"] == "spreadsheet"), None),
                    "ad": next((member["observed_at"] for member in members if member["kind"] == "ad"), None),
                    "discovery": next((member["observed_at"] for member in members if member["kind"] == "discovery"), None),
                },
                "selected": int(state.get("selected") or 0),
                "human_decision": decision,
                "decision_reason": state.get("decision_reason"),
                "lab_target_path": state.get("lab_target_path"),
                "automation_class": state.get("automation_class") or "unknown",
            }
            tx.execute(
                """
                INSERT INTO assets (
                  id, display_name, hostname, ip_address, os_name, os_observations_json, device_type, owner,
                  criticality, match_basis, flags_json, identity_confidence, sources_json, freshness_json,
                  selected, human_decision, decision_reason, decided_by, decided_at, lab_target_path, automation_class, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    asset["id"],
                    asset["display_name"],
                    asset["hostname"],
                    asset["ip_address"],
                    asset["os_name"],
                    json.dumps(os_observations),
                    asset["device_type"],
                    asset["owner"],
                    asset["criticality"],
                    asset["match_basis"],
                    json.dumps(flags),
                    confidence,
                    json.dumps(asset["sources"]),
                    json.dumps(asset["freshness"]),
                    asset["selected"],
                    decision,
                    state.get("decision_reason"),
                    state.get("decided_by"),
                    state.get("decided_at"),
                    state.get("lab_target_path"),
                    asset["automation_class"],
                    now,
                ),
            )
            assets.append(asset)
        for conflict in conflicts:
            tx.execute(
                "INSERT INTO conflicts (id, kind, detail_json, created_at) VALUES (?, ?, ?, ?)",
                (new_id(), conflict["kind"], json.dumps(conflict["detail"]), now),
            )
        append_event(
            db,
            actor=actor,
            action="inventory.reconcile",
            outcome="recorded",
            object_type="reconciliation",
            detail={"assets": len(assets), "conflicts": len(conflicts)},
            tx=tx,
        )
    return {"assets": len(assets), "conflicts": len(conflicts)}


def list_assets(db: Database) -> dict:
    assets = []
    for row in db.query("SELECT * FROM assets ORDER BY display_name"):
        assets.append(_public_asset(row))
    conflicts = []
    for row in db.query("SELECT * FROM conflicts ORDER BY kind"):
        conflicts.append({"id": row["id"], "kind": row["kind"], "detail": json.loads(row["detail_json"])})
    return {"assets": assets, "conflicts": conflicts}


def _public_asset(row: dict) -> dict:
    asset = dict(row)
    asset["flags"] = json.loads(row["flags_json"])
    asset["sources"] = json.loads(row["sources_json"])
    asset["freshness"] = json.loads(row["freshness_json"])
    asset["os_observations"] = json.loads(row["os_observations_json"])
    asset["selected"] = bool(row["selected"])
    asset["assessment_allowed"] = assessment_allowed(row)
    for key in ("flags_json", "sources_json", "freshness_json", "os_observations_json"):
        asset.pop(key, None)
    return asset


def record_decision(db: Database, asset_id: str, decision: str, reason: str, actor: str) -> dict:
    if decision not in {"confirm_identity", "accepted_with_risk"}:
        raise PolicyError("decision must confirm identity or accept the residual risk")
    if len(reason or "") < 8:
        raise PolicyError("a decision reason is required")
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    now = utcnow()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO asset_state (group_key, selected, human_decision, decision_reason, decided_by, decided_at, lab_target_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_key) DO UPDATE SET
              human_decision = excluded.human_decision,
              decision_reason = excluded.decision_reason,
              decided_by = excluded.decided_by,
              decided_at = excluded.decided_at
            """,
            (asset_id, asset["selected"], decision, reason, actor, now, asset["lab_target_path"]),
        )
        tx.execute(
            """
            UPDATE assets SET human_decision = ?, decision_reason = ?, decided_by = ?, decided_at = ?, identity_confidence = ?
            WHERE id = ?
            """,
            (decision, reason, actor, now, "high" if decision == "confirm_identity" else asset["identity_confidence"], asset_id),
        )
        append_event(
            db,
            actor=actor,
            action="inventory.identity_decision",
            outcome="recorded",
            object_type="asset",
            object_id=asset_id,
            detail={"decision": decision},
            tx=tx,
        )
    updated = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    return _public_asset(updated)


def set_selected(db: Database, asset_id: str, selected: bool, actor: str) -> dict:
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    if selected and not assessment_allowed(asset) and asset.get("human_decision") not in {"confirm_identity", "accepted_with_risk"}:
        public = _public_asset(asset)
        if not public["assessment_allowed"]:
            raise PolicyError("resolve identity conflicts or record a decision before selecting this asset")
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO asset_state (group_key, selected, human_decision, decision_reason, decided_by, decided_at, lab_target_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_key) DO UPDATE SET selected = excluded.selected
            """,
            (
                asset_id,
                1 if selected else 0,
                asset["human_decision"],
                asset["decision_reason"],
                asset["decided_by"],
                asset["decided_at"],
                asset["lab_target_path"],
            ),
        )
        tx.execute("UPDATE assets SET selected = ? WHERE id = ?", (1 if selected else 0, asset_id))
        append_event(
            db,
            actor=actor,
            action="inventory.selection",
            outcome="selected" if selected else "cleared",
            object_type="asset",
            object_id=asset_id,
            tx=tx,
        )
    return _public_asset(db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,)))


def bind_lab(db: Database, settings, asset_id: str, relative_dir: str, actor: str) -> dict:
    from .adapters import lab_file

    path = lab_file(settings, relative_dir)
    if not path.is_file():
        raise PolicyError("fleetguard-lab.conf is missing; refusing to invent a configuration")
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    relative = Path(relative_dir).as_posix()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO asset_state (group_key, selected, human_decision, decision_reason, decided_by, decided_at, lab_target_path)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_key) DO UPDATE SET lab_target_path = excluded.lab_target_path
            """,
            (asset_id, asset["selected"], asset["human_decision"], asset["decision_reason"], asset["decided_by"], asset["decided_at"], relative),
        )
        tx.execute("UPDATE assets SET lab_target_path = ? WHERE id = ?", (relative, asset_id))
        append_event(db, actor=actor, action="lab.bind", outcome="bound", object_type="asset", object_id=asset_id, detail={"lab_target_path": relative}, tx=tx)
    return _public_asset(db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,)))


def link_sources(db: Database, left_ref: str, right_ref: str, decision: str, reason: str, actor: str) -> dict:
    if decision not in {"confirm_same", "mark_distinct"}:
        raise PolicyError("link decision must confirm the same asset or mark the sources distinct")
    if left_ref == right_ref:
        raise PolicyError("choose two source identities")
    if len(reason or "") < 8:
        raise PolicyError("a decision reason is required")
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO identity_links (id, left_ref, right_ref, decision, reason, actor, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (new_id(), left_ref, right_ref, decision, reason, actor, utcnow()),
        )
        append_event(
            db,
            actor=actor,
            action="inventory.link",
            outcome=decision,
            object_type="identity_link",
            detail={"left_ref": left_ref, "right_ref": right_ref},
            tx=tx,
        )
    return reconcile(db, actor)

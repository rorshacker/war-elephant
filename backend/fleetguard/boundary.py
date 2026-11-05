from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .audit import append_event
from .policy import PolicyError
from .util import new_id, parse_time, utcnow

CLASSES = {
    "unknown": "Inventory and manual review only. No automatic patching.",
    "approved_noncritical": "Controlled scanning and a single staged change on an approved noncritical administrative system.",
    "shared_infrastructure": "Shared infrastructure needs explicit approval, dependency-aware sequencing, and independent recovery. This controller does not deploy to it.",
    "safety_mission": "Passive or vendor-approved assessment only. Changes go through the designated engineering authority.",
}
CHANGE_TYPES = ("stig_config", "patch", "firmware")
DEPLOYABLE = {"stig_config", "patch"}


def boundary_view(db) -> dict:
    state = _state(db)
    return {
        "role": "ai_assisted_patch_management",
        "autonomous_remediation": False,
        "statement": "AI can assist with assessment and planning. It is not the authority that decides a system is safe to modify. Air-gapping does not change that.",
        "classes": [{"id": key, "policy": text} for key, text in CLASSES.items()],
        "change_types": list(CHANGE_TYPES),
        "scheduling_halted": bool(state["scheduling_halted"]),
        "halt_reason": state["halt_reason"],
        "deployable_change_types": sorted(DEPLOYABLE),
    }


def set_automation_class(db, asset_id: str, automation_class: str, actor: str) -> dict:
    if automation_class not in CLASSES:
        raise PolicyError("unknown automation class")
    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO asset_state (group_key, selected, human_decision, decision_reason, decided_by, decided_at, lab_target_path, automation_class)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_key) DO UPDATE SET automation_class = excluded.automation_class
            """,
            (
                asset_id,
                asset["selected"],
                asset["human_decision"],
                asset["decision_reason"],
                asset["decided_by"],
                asset["decided_at"],
                asset["lab_target_path"],
                automation_class,
            ),
        )
        tx.execute("UPDATE assets SET automation_class = ? WHERE id = ?", (automation_class, asset_id))
        append_event(db, actor=actor, action="asset.automation_class", outcome="recorded", object_type="asset", object_id=asset_id, detail={"automation_class": automation_class}, tx=tx)
    return {"asset_id": asset_id, "automation_class": automation_class, "policy": CLASSES[automation_class]}


def authorize_maintenance(db, asset_id: str, change_type: str, hours: int, actor: str) -> dict:
    if change_type not in CHANGE_TYPES:
        raise PolicyError("change type must be stig_config, patch, or firmware")
    if not isinstance(hours, int) or isinstance(hours, bool) or hours < 1 or hours > 8:
        raise PolicyError("maintenance authorization must last from 1 to 8 hours")
    asset = db.query_one("SELECT id FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    start = datetime.now(timezone.utc).replace(microsecond=0)
    end = start + timedelta(hours=hours)
    authorization_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO maintenance_authorizations (
              id, asset_id, change_type, starts_at, ends_at, authorized_by, created_at, revoked
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (authorization_id, asset_id, change_type, start.isoformat(), end.isoformat(), actor, utcnow()),
        )
        append_event(
            db,
            actor=actor,
            action="maintenance.authorize",
            outcome="recorded",
            object_type="asset",
            object_id=asset_id,
            detail={"change_type": change_type, "ends_at": end.isoformat()},
            tx=tx,
        )
    return {"id": authorization_id, "asset_id": asset_id, "change_type": change_type, "starts_at": start.isoformat(), "ends_at": end.isoformat()}


def set_scheduling_halt(db, halted: bool, reason: str, actor: str) -> dict:
    if halted and len(reason or "") < 8:
        raise PolicyError("record why new work is stopping")
    with db.transaction() as tx:
        tx.execute(
            """
            UPDATE controller_state
            SET scheduling_halted = ?, halted_by = ?, halted_at = ?, halt_reason = ?
            WHERE id = 'local'
            """,
            (1 if halted else 0, actor if halted else None, utcnow() if halted else None, reason if halted else None),
        )
        append_event(
            db,
            actor=actor,
            action="controller.scheduling",
            outcome="stopped" if halted else "resumed",
            detail={"reason": reason if halted else None},
            tx=tx,
        )
    return boundary_view(db)


def assert_deployment_allowed(db, asset: dict, change_type: str) -> None:
    state = _state(db)
    if state["scheduling_halted"]:
        raise PolicyError("scheduling is stopped; no new change will start. An in-progress installation is not killed.", 409)
    automation_class = asset.get("automation_class") or "unknown"
    if automation_class != "approved_noncritical":
        raise PolicyError(CLASSES.get(automation_class, CLASSES["unknown"]), 409)
    if change_type not in CHANGE_TYPES:
        raise PolicyError("missing or conflicting change type blocks the change. No best guess was applied.", 409)
    if change_type not in DEPLOYABLE:
        raise PolicyError(f"{change_type} is a separate change type and has no deployer. It was not combined with another change.", 409)
    now = datetime.now(timezone.utc)
    rows = db.query(
        """
        SELECT * FROM maintenance_authorizations
        WHERE asset_id = ? AND change_type = ? AND revoked = 0
        ORDER BY created_at DESC
        """,
        (asset["id"], change_type),
    )
    current = [row for row in rows if parse_time(row["starts_at"]) <= now < parse_time(row["ends_at"])]
    if not current:
        raise PolicyError("operational maintenance authorization is not current for this asset and change type", 409)


def _state(db) -> dict:
    row = db.query_one("SELECT * FROM controller_state WHERE id = 'local'")
    if row:
        return row
    db.execute("INSERT INTO controller_state (id, scheduling_halted) VALUES ('local', 0)")
    return db.query_one("SELECT * FROM controller_state WHERE id = 'local'")

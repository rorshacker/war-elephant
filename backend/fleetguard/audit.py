from __future__ import annotations

import json
from typing import Any

from .db import Database, Transaction
from .util import canon, new_id, redact, sha256_text, utcnow

PROTECTION_STATEMENT = (
    "This hash chain detects accidental or partial tampering of the local database. "
    "A privileged local attacker who can rewrite the database can recompute the chain. "
    "Independently protected signed checkpoints are an extension point and are not configured by default."
)
GENESIS = "GENESIS"


def event_payload(
    event_id: str,
    actor: str,
    action: str,
    outcome: str,
    object_type: str | None,
    object_id: str | None,
    correlation_id: str | None,
    detail: dict,
    created_at: str,
) -> dict:
    return {
        "event_id": event_id,
        "actor": actor,
        "action": action,
        "outcome": outcome,
        "object_type": object_type,
        "object_id": object_id,
        "correlation_id": correlation_id,
        "detail": detail,
        "created_at": created_at,
    }


def append_event(
    db: Database,
    *,
    actor: str,
    action: str,
    outcome: str,
    object_type: str | None = None,
    object_id: str | None = None,
    correlation_id: str | None = None,
    detail: dict | None = None,
    tx: Transaction | None = None,
) -> str:
    if tx is None:
        with db.transaction() as owned:
            return append_event(
                db,
                actor=actor,
                action=action,
                outcome=outcome,
                object_type=object_type,
                object_id=object_id,
                correlation_id=correlation_id,
                detail=detail,
                tx=owned,
            )
    cleaned = redact(detail or {})
    created_at = utcnow()
    event_id = new_id()
    previous = tx.query_one("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
    prev_hash = previous["event_hash"] if previous else GENESIS
    payload = event_payload(
        event_id, actor, action, outcome, object_type, object_id, correlation_id, cleaned, created_at
    )
    event_hash = sha256_text(prev_hash + "|" + canon(payload))
    tx.execute(
        """
        INSERT INTO audit_events (
          event_id, actor, action, object_type, object_id, correlation_id, outcome,
          detail_json, prev_hash, event_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            actor,
            action,
            object_type,
            object_id,
            correlation_id,
            outcome,
            canon(cleaned),
            prev_hash,
            event_hash,
            created_at,
        ),
    )
    return event_id


def verify_chain(db: Database) -> dict:
    rows = db.query("SELECT * FROM audit_events ORDER BY seq")
    prev_hash = GENESIS
    for row in rows:
        detail = json.loads(row["detail_json"])
        payload = event_payload(
            row["event_id"],
            row["actor"],
            row["action"],
            row["outcome"],
            row["object_type"],
            row["object_id"],
            row["correlation_id"],
            detail,
            row["created_at"],
        )
        expected = sha256_text(prev_hash + "|" + canon(payload))
        if row["prev_hash"] != prev_hash or row["event_hash"] != expected:
            return {
                "ok": False,
                "seq": row["seq"],
                "event_id": row["event_id"],
                "count": len(rows),
                "statement": PROTECTION_STATEMENT,
            }
        prev_hash = row["event_hash"]
    return {
        "ok": True,
        "head": prev_hash,
        "count": len(rows),
        "statement": PROTECTION_STATEMENT,
    }


def list_events(db: Database, limit: int = 200) -> list[dict]:
    rows = db.query(
        "SELECT seq, event_id, actor, action, object_type, object_id, correlation_id, outcome, detail_json, created_at, event_hash FROM audit_events ORDER BY seq DESC LIMIT ?",
        (limit,),
    )
    for row in rows:
        row["detail"] = json.loads(row.pop("detail_json"))
    return rows


class UnsignedCheckpointSigner:
    """Extension point. Production should replace this with a signer whose key is outside the enclave database."""

    name = "unsigned"

    def sign(self, payload: bytes) -> str | None:
        return None


def export_checkpoint(db: Database, actor: str, signer: UnsignedCheckpointSigner | None = None) -> dict:
    signer = signer or UnsignedCheckpointSigner()
    verified = verify_chain(db)
    if not verified["ok"]:
        from .policy import PolicyError

        raise PolicyError("audit chain does not verify; checkpoint refused")
    events = db.query(
        "SELECT seq, event_id, event_hash, prev_hash, action, outcome, created_at FROM audit_events ORDER BY seq"
    )
    payload = {
        "head": verified["head"],
        "count": verified["count"],
        "events": events,
        "statement": PROTECTION_STATEMENT,
    }
    raw = canon(payload).encode("utf-8")
    signature = signer.sign(raw)
    status = "signed_extension" if signature else "unsigned_local_checkpoint"
    checkpoint_id = new_id()
    created_at = utcnow()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO audit_checkpoints (
              id, head_hash, event_count, payload_json, signature_status, signature, created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (checkpoint_id, verified["head"], verified["count"], canon(payload), status, signature, created_at, actor),
        )
        append_event(
            db,
            actor=actor,
            action="audit.checkpoint",
            outcome="recorded",
            object_type="audit_checkpoint",
            object_id=checkpoint_id,
            detail={"signature_status": status, "event_count": verified["count"]},
            tx=tx,
        )
    return {
        "id": checkpoint_id,
        "head_hash": verified["head"],
        "event_count": verified["count"],
        "signature_status": status,
        "signature": signature,
        "statement": PROTECTION_STATEMENT,
        "payload": payload,
    }

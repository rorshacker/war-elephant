from __future__ import annotations

import json

from .audit import append_event
from .reports import bundle, content_hash
from .util import new_id, utcnow


class TemporaryFailure(Exception):
    pass


def enqueue(db, settings, actor: str) -> dict:
    snapshot = bundle(db, settings)
    created = []
    interesting = {
        "inventory": snapshot["inventory"],
        "finding": snapshot["findings"],
        "execution": snapshot["executions"],
        "manual_work": snapshot["outstanding_manual_work"],
    }
    with db.transaction() as tx:
        for record_type, items in interesting.items():
            for item in items:
                record_id = item.get("id") or new_id()
                payload = {
                    "origin": settings.enclave,
                    "schema_version": settings.schema_version,
                    "record_type": record_type,
                    "record": item,
                }
                digest = content_hash(payload)
                outbox_id = new_id()
                tx.execute(
                    """
                    INSERT INTO sync_outbox (
                      id, origin, schema_version, record_type, payload_json, content_hash, created_at, attempts, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'queued')
                    """,
                    (outbox_id, settings.enclave, settings.schema_version, record_type, json.dumps(payload), digest, utcnow()),
                )
                created.append(outbox_id)
        append_event(db, actor=actor, action="sync.enqueue", outcome="queued", detail={"records": len(created)}, tx=tx)
    return {"queued": len(created)}


def list_outbox(db) -> list[dict]:
    rows = db.query("SELECT id, origin, schema_version, record_type, content_hash, created_at, acked_at, attempts, status, last_error FROM sync_outbox ORDER BY created_at")
    return rows


def deliver(db, sender, max_bytes: int | None = None) -> dict:
    rows = db.query("SELECT * FROM sync_outbox WHERE status IN ('queued', 'retry', 'deferred') ORDER BY created_at")
    acked = 0
    retried = 0
    deferred = 0
    for row in rows:
        payload_bytes = len(row["payload_json"].encode("utf-8"))
        if max_bytes is not None and payload_bytes > max_bytes:
            db.execute(
                "UPDATE sync_outbox SET status = 'deferred', last_error = ? WHERE id = ?",
                (f"payload is {payload_bytes} bytes and the link budget is {max_bytes}", row["id"]),
            )
            deferred += 1
            continue
        attempts = row["attempts"] + 1
        try:
            sender(json.loads(row["payload_json"]), row["content_hash"], row["id"])
        except TemporaryFailure as exc:
            db.execute(
                "UPDATE sync_outbox SET attempts = ?, status = 'retry', last_error = ? WHERE id = ?",
                (attempts, str(exc), row["id"]),
            )
            retried += 1
        else:
            db.execute(
                "UPDATE sync_outbox SET attempts = ?, status = 'acked', acked_at = ?, last_error = NULL WHERE id = ?",
                (attempts, utcnow(), row["id"]),
            )
            acked += 1
    return {"acked": acked, "retrying": retried, "deferred": deferred, "executed": 0}


def receive(db, records: list[dict]) -> dict:
    stored = duplicate = conflict = 0
    for record in records:
        record_id = record["id"]
        digest = record["content_hash"]
        payload = record["payload"]
        existing = db.query("SELECT content_hash FROM sync_inbox WHERE record_id = ?", (record_id,))
        if any(row["content_hash"] == digest for row in existing):
            duplicate += 1
            continue
        disposition = "conflict" if existing else "stored"
        db.execute(
            """
            INSERT INTO sync_inbox (
              record_id, content_hash, origin, schema_version, record_type, payload_json, received_at, disposition
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                digest,
                record.get("origin") or payload.get("origin"),
                record.get("schema_version") or payload.get("schema_version"),
                record.get("record_type") or payload.get("record_type"),
                json.dumps(payload),
                utcnow(),
                disposition,
            ),
        )
        if disposition == "stored":
            stored += 1
        else:
            conflict += 1
    return {"stored": stored, "duplicate": duplicate, "conflict": conflict, "executed": 0}

from __future__ import annotations

from pathlib import Path

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .settings import Settings
from .util import new_id, sha256_bytes, utcnow

KINDS = {
    "ecu": "ECU",
    "fam": "FAM",
    "msu": "MSU",
    "iava": "IAVA",
}
DISPLAY = {**KINDS, "iava_b": "IAVA", "iava_t": "IAVA"}

ALLOWED_SUFFIXES = {".zip", ".xml", ".pdf", ".json", ".csv", ".txt", ".xlsx", ".msu", ".cab"}
STATEMENT = "Checksum integrity was computed locally. Publisher authenticity was not verified. The file was stored and not executed."


def import_update(db: Database, settings: Settings, kind: str, filename: str, data: bytes, actor: str) -> dict:
    if kind not in KINDS:
        raise PolicyError("update kind must be ecu, fam, msu, or iava")
    if not data:
        raise PolicyError("update file is empty")
    if len(data) > settings.max_upload:
        raise PolicyError("file exceeds the upload limit")
    name = Path(filename).name
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise PolicyError("upload a document or package. Executable files are not accepted, and nothing imported here is run.")
    digest = sha256_bytes(data)
    existing = db.query_one("SELECT * FROM update_imports WHERE kind = ? AND sha256 = ?", (kind, digest))
    if existing:
        return _public(existing) | {"status": "duplicate"}
    folder = settings.data_dir / "updates" / kind
    folder.mkdir(parents=True, exist_ok=True)
    update_id = new_id()
    stored = folder / f"{update_id}{suffix}"
    imported_at = utcnow()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO update_imports (
              id, kind, original_filename, sha256, size_bytes, stored_path, imported_at, imported_by,
              authenticity, authenticity_statement
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'not_verified', ?)
            """,
            (update_id, kind, name, digest, len(data), str(stored), imported_at, actor, STATEMENT),
        )
        append_event(
            db,
            actor=actor,
            action="update.import",
            outcome="stored",
            object_type="update_import",
            object_id=update_id,
            detail={"kind": kind, "filename": name, "sha256": digest, "authenticity": "not_verified", "executed": False},
            tx=tx,
        )
    stored.write_bytes(data)
    row = db.query_one("SELECT * FROM update_imports WHERE id = ?", (update_id,))
    return _public(row) | {"status": "imported"}


def list_updates(db: Database) -> list[dict]:
    return [_public(row) for row in db.query("SELECT * FROM update_imports ORDER BY kind, imported_at")]


def read_imported_msu(db: Database, settings: Settings, source_id: str) -> dict:
    row = db.query_one("SELECT * FROM update_imports WHERE id = ? AND kind = 'msu'", (source_id,))
    if not row:
        raise PolicyError("that MSU is not imported", 404)
    root = (settings.data_dir / "updates").resolve()
    candidate = Path(row["stored_path"]).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise PolicyError("the imported MSU could not be read")
    data = candidate.read_bytes()
    digest = sha256_bytes(data)
    if digest != row["sha256"] or len(data) != row["size_bytes"]:
        raise PolicyError("the imported MSU does not match the stored checksum")
    filename = row["original_filename"]
    return {
        "id": row["id"],
        "filename": filename,
        "sha256": digest,
        "size_bytes": len(data),
        "executed": False,
        "statement": (
            f"MSU read: {filename}, {len(data)} bytes. "
            "Checksum matches the imported file. The package was not executed."
        ),
    }


def _public(row: dict) -> dict:
    return {
        "id": row["id"],
        "kind": row["kind"],
        "label": DISPLAY.get(row["kind"], row["kind"]),
        "original_filename": row["original_filename"],
        "sha256": row["sha256"],
        "size_bytes": row["size_bytes"],
        "imported_at": row["imported_at"],
        "imported_by": row["imported_by"],
        "authenticity": row["authenticity"],
        "authenticity_statement": row["authenticity_statement"],
        "executed": False,
    }

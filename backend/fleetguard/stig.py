from __future__ import annotations

import io
import zipfile
from pathlib import Path

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .settings import Settings
from .util import new_id, sha256_bytes, utcnow

try:
    from defusedxml.ElementTree import fromstring
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("defusedxml is required") from exc


def _local(tag: str | None) -> str:
    if not tag:
        return ""
    return tag.rsplit("}", 1)[-1]


def _child_text(element, name: str) -> str:
    for child in list(element):
        if _local(child.tag) == name:
            return "".join(child.itertext()).strip()
    return ""


def parse_xccdf(xml_bytes: bytes, max_bytes: int) -> dict:
    if len(xml_bytes) > max_bytes:
        raise PolicyError("XML member exceeds the size limit")
    lowered = xml_bytes[:800].lower()
    if b"<!doctype" in lowered:
        raise PolicyError("DOCTYPE is not allowed in imported XML")
    try:
        root = fromstring(xml_bytes)
    except Exception as exc:
        raise PolicyError(f"malformed or unsafe XML ({exc.__class__.__name__})") from exc
    if _local(root.tag) != "Benchmark":
        raise PolicyError("root element must be an XCCDF Benchmark")
    benchmark_id = (root.attrib.get("id") or "").strip()
    if not benchmark_id:
        raise PolicyError("benchmark id is missing")
    release = ""
    for child in list(root):
        if _local(child.tag) == "plain-text" and child.attrib.get("id") == "release":
            release = (child.text or "").strip()
    rules = []
    for element in root.iter():
        if _local(element.tag) != "Rule":
            continue
        rule_id = (element.attrib.get("id") or "").strip()
        if not rule_id:
            raise PolicyError("a rule is missing an id")
        check_text = ""
        fix_text = ""
        source_ref = ""
        for child in element.iter():
            local = _local(child.tag)
            if local == "check-content" and not check_text:
                check_text = "".join(child.itertext()).strip()
            elif local == "fix" and not fix_text:
                fix_text = "".join(child.itertext()).strip()
            elif local == "reference" and not source_ref:
                source_ref = child.attrib.get("href") or "".join(child.itertext()).strip()
        rules.append(
            {
                "rule_id": rule_id,
                "version": _child_text(element, "version"),
                "severity": element.attrib.get("severity") or "",
                "title": _child_text(element, "title"),
                "check_text": check_text,
                "fix_text": fix_text,
                "source_ref": source_ref,
            }
        )
    return {
        "benchmark_id": benchmark_id,
        "version": _child_text(root, "version") or "0",
        "release_info": release,
        "title": _child_text(root, "title"),
        "description": _child_text(root, "description"),
        "rules": rules,
    }


def _reject_member_name(name: str) -> None:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise PolicyError("archive member path is not allowed")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise PolicyError("archive member path is not allowed")
    if not parts or not parts[-1].lower().endswith(".xml"):
        raise PolicyError("archive members must be .xml checklist files")


def extract_xml_members(data: bytes, settings: Settings) -> list[tuple[str, bytes]]:
    if len(data) > settings.max_upload:
        raise PolicyError("file exceeds the upload limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PolicyError("file is not a readable ZIP package") from exc
    infos = [info for info in archive.infolist() if not info.is_dir()]
    if len(infos) > settings.max_zip_files:
        raise PolicyError("archive contains too many files")
    total = 0
    members: list[tuple[str, bytes]] = []
    for info in infos:
        _reject_member_name(info.filename)
        if info.flag_bits & 0x1:
            raise PolicyError("encrypted archive members are not allowed")
        if info.file_size < 0 or info.file_size > settings.max_member:
            raise PolicyError("archive member exceeds the size limit")
        total += info.file_size
        if total > settings.max_uncompressed:
            raise PolicyError("archive exceeds the uncompressed size limit")
        if info.compress_size and (info.file_size / info.compress_size) > settings.max_ratio:
            raise PolicyError("archive compression ratio is not allowed")
        payload = archive.read(info)
        if len(payload) > settings.max_member:
            raise PolicyError("archive member exceeds the size limit")
        members.append((Path(info.filename).name, payload))
    if not members:
        raise PolicyError("archive does not contain an XML checklist")
    return members


def import_package(db: Database, settings: Settings, filename: str, data: bytes, actor: str) -> dict:
    if len(data) > settings.max_upload:
        raise PolicyError("file exceeds the upload limit")
    digest = sha256_bytes(data)
    existing = db.query_one("SELECT * FROM stig_packages WHERE sha256 = ?", (digest,))
    if existing:
        return {
            "status": "duplicate",
            "package_id": existing["id"],
            "sha256": digest,
            "authenticity": "not_verified",
            "authenticity_statement": existing["authenticity_statement"],
            "benchmarks": _benchmarks_for_package(db, existing["id"]),
        }
    lower = filename.lower()
    if lower.endswith(".zip"):
        members = extract_xml_members(data, settings)
    elif lower.endswith(".xml"):
        if len(data) > settings.max_member:
            raise PolicyError("XML member exceeds the size limit")
        members = [(Path(filename).name, data)]
    else:
        raise PolicyError("import a .zip package or an .xml checklist")
    parsed = [(name, payload, parse_xccdf(payload, settings.max_member)) for name, payload in members]
    package_id = new_id()
    settings.stig_dir.mkdir(parents=True, exist_ok=True)
    stored = settings.stig_dir / f"{package_id}{Path(filename).suffix.lower() or '.bin'}"
    statement = "Checksum integrity was computed locally. Publisher authenticity was not verified."
    imported_at = utcnow()
    benchmark_rows = []
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO stig_packages (
              id, original_filename, sha256, size_bytes, stored_path, imported_at, imported_by,
              authenticity, authenticity_statement
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (package_id, Path(filename).name, digest, len(data), str(stored), imported_at, actor, "not_verified", statement),
        )
        for name, payload, document in parsed:
            xml_sha = sha256_bytes(payload)
            found = tx.query_one(
                """
                SELECT id FROM stig_benchmarks
                WHERE benchmark_id = ? AND version = ? AND xml_sha256 = ?
                """,
                (document["benchmark_id"], document["version"], xml_sha),
            )
            if found:
                benchmark_rows.append({"id": found["id"], "benchmark_id": document["benchmark_id"], "version": document["version"], "status": "already_imported"})
                continue
            benchmark_row_id = new_id()
            tx.execute(
                """
                INSERT INTO stig_benchmarks (
                  id, package_id, benchmark_id, version, release_info, title, description, xml_sha256, imported_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    benchmark_row_id,
                    package_id,
                    document["benchmark_id"],
                    document["version"],
                    document["release_info"],
                    document["title"],
                    document["description"],
                    xml_sha,
                    imported_at,
                ),
            )
            for rule in document["rules"]:
                tx.execute(
                    """
                    INSERT INTO stig_rules (
                      id, benchmark_row_id, rule_id, version, severity, title, check_text, fix_text, source_ref
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id(),
                        benchmark_row_id,
                        rule["rule_id"],
                        rule["version"],
                        rule["severity"],
                        rule["title"],
                        rule["check_text"],
                        rule["fix_text"],
                        rule["source_ref"],
                    ),
                )
            benchmark_rows.append(
                {
                    "id": benchmark_row_id,
                    "benchmark_id": document["benchmark_id"],
                    "version": document["version"],
                    "release_info": document["release_info"],
                    "title": document["title"],
                    "rule_count": len(document["rules"]),
                    "status": "imported",
                    "member": name,
                }
            )
        append_event(
            db,
            actor=actor,
            action="stig.import",
            outcome="imported",
            object_type="stig_package",
            object_id=package_id,
            detail={
                "filename": Path(filename).name,
                "sha256": digest,
                "authenticity": "not_verified",
                "benchmarks": [row["benchmark_id"] for row in benchmark_rows],
            },
            tx=tx,
        )
    stored.write_bytes(data)
    return {
        "status": "imported",
        "package_id": package_id,
        "sha256": digest,
        "authenticity": "not_verified",
        "authenticity_statement": statement,
        "benchmarks": benchmark_rows,
    }


def _benchmarks_for_package(db: Database, package_id: str) -> list[dict]:
    return db.query(
        "SELECT id, benchmark_id, version, release_info, title FROM stig_benchmarks WHERE package_id = ?",
        (package_id,),
    )


def _version_key(version: str, release: str, imported_at: str) -> tuple:
    def parts(value: str) -> tuple:
        numbers = []
        current = ""
        for char in value or "":
            if char.isdigit():
                current += char
            elif current:
                numbers.append(int(current))
                current = ""
        if current:
            numbers.append(int(current))
        return tuple(numbers) or (0,)

    return (parts(version), parts(release), imported_at)


def list_benchmarks(db: Database) -> list[dict]:
    rows = db.query(
        """
        SELECT b.*, p.sha256 AS package_sha256, p.authenticity, p.authenticity_statement, p.original_filename,
          (SELECT COUNT(*) FROM stig_rules r WHERE r.benchmark_row_id = b.id) AS rule_count
        FROM stig_benchmarks b JOIN stig_packages p ON p.id = b.package_id
        ORDER BY b.benchmark_id, b.imported_at
        """
    )
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row["benchmark_id"], []).append(row)
    newest_ids = set()
    for items in grouped.values():
        winner = max(items, key=lambda item: _version_key(item["version"], item["release_info"], item["imported_at"]))
        newest_ids.add(winner["id"])
    for row in rows:
        row["version_label"] = "newest imported version" if row["id"] in newest_ids else "earlier imported version"
        row["published_claim"] = "not asserted while offline"
    return rows


def list_packages(db: Database) -> list[dict]:
    return db.query(
        """
        SELECT id, original_filename, sha256, size_bytes, imported_at, imported_by, authenticity, authenticity_statement
        FROM stig_packages ORDER BY imported_at
        """
    )


def list_rules(db: Database, benchmark_row_id: str) -> list[dict]:
    rows = db.query(
        """
        SELECT id, rule_id, version, severity, title, check_text, fix_text, source_ref
        FROM stig_rules WHERE benchmark_row_id = ? ORDER BY rule_id
        """,
        (benchmark_row_id,),
    )
    if not rows and not db.query_one("SELECT id FROM stig_benchmarks WHERE id = ?", (benchmark_row_id,)):
        raise PolicyError("benchmark not found", 404)
    return rows

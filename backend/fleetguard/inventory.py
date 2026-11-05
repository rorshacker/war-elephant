from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import zipfile
from datetime import timedelta
from datetime import datetime, timezone

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .util import new_id, parse_time, sha256_bytes, utcnow

FIELDS = [
    "hostname",
    "ip_address",
    "subnet",
    "device_type",
    "os_name",
    "vlan",
    "enclave",
    "department",
    "owner",
    "mission_function",
    "criticality",
    "maintenance_window",
    "scan_restrictions",
]
ALIASES = {
    "hostname": {"hostname", "host", "computername", "computer"},
    "ip_address": {"ipaddress", "ip", "ipv4", "ipv4address"},
    "subnet": {"subnet", "network", "cidr"},
    "device_type": {"devicetype", "type", "role"},
    "os_name": {"os", "osname", "operatingsystem"},
    "vlan": {"vlan", "vlanid"},
    "enclave": {"enclave"},
    "department": {"department", "dept"},
    "owner": {"owner"},
    "mission_function": {"missionfunction", "mission", "function"},
    "criticality": {"criticality", "priority"},
    "maintenance_window": {"maintenancewindow", "maintwindow"},
    "scan_restrictions": {"scanrestrictions", "restrictions"},
}
CRITICALITY = {"", "low", "medium", "high"}
MAX_ROWS = 5000


def _norm_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def suggest_mapping(headers: list[str]) -> dict:
    used = set()
    mapping = {}
    normalized = {header: _norm_header(header) for header in headers}
    for field, aliases in ALIASES.items():
        for header, token in normalized.items():
            if header in used:
                continue
            if token in aliases:
                mapping[field] = header
                used.add(header)
                break
    return mapping


class FormulaText:
    def __init__(self, text: str):
        self.text = text


def _clean_cell(value) -> tuple[str | None, str | None]:
    if isinstance(value, FormulaText):
        return None, "formula ignored and not executed"
    if value is None:
        return None, None
    text = str(value).strip()
    return (text or None), None


def _validate_row(mapped: dict, row_number: int) -> list[dict]:
    errors = []
    if not mapped.get("hostname") and not mapped.get("ip_address"):
        errors.append({"row": row_number, "field": "hostname", "message": "hostname or IP address is required"})
    ip_value = mapped.get("ip_address")
    if ip_value:
        try:
            ipaddress.ip_address(ip_value)
        except ValueError:
            errors.append({"row": row_number, "field": "ip_address", "message": "invalid IP address"})
    subnet = mapped.get("subnet")
    if subnet:
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            errors.append({"row": row_number, "field": "subnet", "message": "invalid subnet"})
    criticality = (mapped.get("criticality") or "").lower()
    if criticality not in CRITICALITY:
        errors.append({"row": row_number, "field": "criticality", "message": "criticality must be low, medium, high, or blank"})
        mapped["criticality"] = criticality
    elif mapped.get("criticality"):
        mapped["criticality"] = criticality
    return errors


def _records_from_table(headers: list[str], table: list[list], mapping: dict) -> dict:
    errors = []
    rows = []
    seen_hosts: dict[str, int] = {}
    seen_ips: dict[str, int] = {}
    duplicates = []
    if "hostname" not in mapping and "ip_address" not in mapping:
        errors.append({"row": 1, "field": "mapping", "message": "map hostname or IP address before preview"})
    index = {header: pos for pos, header in enumerate(headers)}
    for offset, raw in enumerate(table, start=2):
        if not any(cell not in (None, "") for cell in raw):
            continue
        mapped = {}
        raw_obj = {}
        for field, header in mapping.items():
            if field not in FIELDS:
                errors.append({"row": offset, "field": field, "message": "unknown field"})
                continue
            if header not in index:
                errors.append({"row": offset, "field": field, "message": f"column {header} is not in this worksheet"})
                continue
            position = index[header]
            value = raw[position] if position < len(raw) else None
            raw_obj[header] = None if value is None else str(value)
            cleaned, problem = _clean_cell(value)
            if problem:
                errors.append({"row": offset, "field": field, "message": problem})
            mapped[field] = cleaned
        errors.extend(_validate_row(mapped, offset))
        host_key = (mapped.get("hostname") or "").lower()
        if host_key:
            if host_key in seen_hosts:
                duplicates.append({"row": offset, "field": "hostname", "value": mapped.get("hostname"), "first_row": seen_hosts[host_key]})
            else:
                seen_hosts[host_key] = offset
        ip_key = mapped.get("ip_address") or ""
        if ip_key:
            if ip_key in seen_ips:
                duplicates.append({"row": offset, "field": "ip_address", "value": ip_key, "first_row": seen_ips[ip_key]})
            else:
                seen_ips[ip_key] = offset
        rows.append({"row_number": offset, "values": mapped, "raw": raw_obj})
        if len(rows) > MAX_ROWS:
            raise PolicyError("worksheet exceeds the row limit")
    blocking = [error for error in errors if error.get("message") != "formula ignored and not executed" or True]
    return {"rows": rows, "errors": errors, "duplicates": duplicates, "blocking": bool(errors)}


def _read_csv(data: bytes) -> tuple[list[str], list[list], str]:
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            text = ""
    else:
        raise PolicyError("inventory file encoding is not supported")
    reader = csv.reader(io.StringIO(text))
    material = list(reader)
    if not material:
        raise PolicyError("inventory file is empty")
    headers = [cell.strip() for cell in material[0]]
    return headers, material[1:], encoding


def _reject_macros(data: bytes) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PolicyError("workbook is not a readable xlsx file") from exc
    for name in archive.namelist():
        if "vbaProject" in name or name.lower().endswith(".bin") and "vba" in name.lower():
            raise PolicyError("macro-enabled workbooks are refused and macros are not executed")


def list_worksheets(data: bytes) -> list[str]:
    _reject_macros(data)
    from openpyxl import load_workbook

    workbook = load_workbook(io.BytesIO(data), read_only=True, data_only=False, keep_vba=False)
    try:
        return list(workbook.sheetnames)
    finally:
        workbook.close()


def _read_xlsx(data: bytes, worksheet: str | None) -> tuple[list[str], list[list], str]:
    sheets = list_worksheets(data)
    if worksheet is None:
        if len(sheets) != 1:
            raise NeedWorksheet(sheets)
        worksheet = sheets[0]
    elif worksheet not in sheets:
        raise PolicyError("worksheet was not found")
    from openpyxl import load_workbook

    workbook = load_workbook(io.BytesIO(data), read_only=True, data_only=False, keep_vba=False)
    try:
        sheet = workbook[worksheet]
        rows = []
        for row in sheet.iter_rows(values_only=False):
            values = []
            for cell in row:
                if cell.data_type == "f":
                    values.append(FormulaText(str(cell.value)))
                else:
                    values.append(cell.value)
            rows.append(values)
    finally:
        workbook.close()
    if not rows:
        raise PolicyError("worksheet is empty")
    headers = ["" if cell is None else str(cell).strip() for cell in rows[0]]
    return headers, rows[1:], worksheet


class NeedWorksheet(Exception):
    def __init__(self, sheets: list[str]):
        self.sheets = sheets


def preview_inventory(
    db: Database,
    filename: str,
    data: bytes,
    worksheet: str | None,
    mapping: dict | None,
) -> dict:
    if len(data) > 30 * 1024 * 1024:
        raise PolicyError("file exceeds the upload limit")
    lower = filename.lower()
    if lower.endswith(".xlsm") or lower.endswith(".xls"):
        raise PolicyError("only .csv and .xlsx files are accepted; macros and legacy workbooks are refused")
    digest = sha256_bytes(data)
    try:
        if lower.endswith(".csv"):
            headers, table, selected_sheet = _read_csv(data)
            selected_sheet = None
        elif lower.endswith(".xlsx"):
            headers, table, selected_sheet = _read_xlsx(data, worksheet)
        else:
            raise PolicyError("only .csv and .xlsx files are accepted")
    except NeedWorksheet as need:
        return {
            "need_worksheet": True,
            "worksheets": need.sheets,
            "sha256": digest,
            "filename": filename,
            "message": "select a worksheet before preview",
        }
    chosen = mapping or suggest_mapping(headers)
    parsed = _records_from_table(headers, table, chosen)
    stored = _store_preview(db, filename, digest, selected_sheet, chosen, parsed)
    return {
        "need_worksheet": False,
        **stored,
        "worksheets": list_worksheets(data) if lower.endswith(".xlsx") else [],
        "headers": headers,
        "suggested_mapping": suggest_mapping(headers),
        "mapping": chosen,
        "scope_statement": "Spreadsheet addresses propose discovery scope. They do not authorize discovery or changes.",
    }


def preview_ip_list(db: Database, text: str) -> dict:
    if not isinstance(text, str) or not text.strip():
        raise PolicyError("paste at least one IP address")
    if len(text.encode("utf-8")) > 1024 * 1024:
        raise PolicyError("address list is too large")
    table = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if len(table) >= 256:
            raise PolicyError("an IP import is limited to 256 addresses")
        table.append(_address_line(stripped))
    if not table:
        raise PolicyError("paste at least one IP address")
    mapping = {"hostname": "hostname", "ip_address": "ip_address"}
    parsed = _records_from_table(["hostname", "ip_address"], table, mapping)
    for row in parsed["rows"]:
        host = row["values"].get("hostname") or ""
        if host and host[0] in "=+-@":
            parsed["errors"].append({"row": row["row_number"], "field": "hostname", "message": "formula text is not accepted"})
    for error in parsed["errors"]:
        if error.get("message") == "invalid IP address":
            row = next((item for item in parsed["rows"] if item["row_number"] == error["row"]), None)
            value = (row or {}).get("values", {}).get("ip_address") or ""
            if "/" in value:
                error["message"] = "a network range is not an import. Paste individual addresses."
    payload = "\n".join(f"{host or ''},{ip}" for host, ip in table).encode("utf-8")
    stored = _store_preview(db, "ip-import.txt", sha256_bytes(payload), None, mapping, parsed)
    return {
        "need_worksheet": False,
        **stored,
        "headers": ["hostname", "ip_address"],
        "mapping": mapping,
        "scope_statement": "These addresses were imported. They were not probed, and the import does not authorize discovery.",
    }


def _address_line(line: str) -> list[str | None]:
    if "," in line:
        left, right = [part.strip() for part in line.split(",", 1)]
        if _looks_like_address(right) and not _looks_like_address(left):
            return [left or None, right]
        if _looks_like_address(left):
            return [right or None, left]
        return [None, line]
    parts = line.split()
    if len(parts) == 2 and _looks_like_address(parts[0]):
        return [parts[1], parts[0]]
    if len(parts) == 2 and _looks_like_address(parts[1]):
        return [parts[0], parts[1]]
    return [None, line]


def _looks_like_address(value: str) -> bool:
    candidate = value.split("/", 1)[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _store_preview(db: Database, filename: str, digest: str, worksheet: str | None, mapping: dict, parsed: dict) -> dict:
    preview_id = new_id()
    created = datetime.now(timezone.utc).replace(microsecond=0)
    expires = (created + timedelta(hours=2)).isoformat()
    db.execute(
        """
        INSERT INTO inventory_previews (
          id, filename, sha256, worksheet, mapping_json, rows_json, errors_json, duplicates_json, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            preview_id,
            filename,
            digest,
            worksheet,
            json.dumps(mapping),
            json.dumps(parsed["rows"]),
            json.dumps(parsed["errors"]),
            json.dumps(parsed["duplicates"]),
            created.isoformat(),
            expires,
        ),
    )
    return {
        "preview_id": preview_id,
        "filename": filename,
        "sha256": digest,
        "worksheet": worksheet,
        "sample": parsed["rows"][:5],
        "row_count": len(parsed["rows"]),
        "errors": parsed["errors"],
        "duplicates": parsed["duplicates"],
        "expires_at": expires,
    }


def commit_inventory(db: Database, preview_id: str, actor: str, confirm: bool, acknowledge_duplicates: bool) -> dict:
    if not confirm:
        raise PolicyError("explicit confirmation is required before inventory is committed")
    preview = db.query_one("SELECT * FROM inventory_previews WHERE id = ?", (preview_id,))
    if not preview:
        raise PolicyError("preview not found", 404)
    if preview["committed"]:
        raise PolicyError("preview was already committed", 409)
    if parse_time(preview["expires_at"]) <= datetime.now(timezone.utc):
        raise PolicyError("preview expired; generate a new preview")
    errors = json.loads(preview["errors_json"])
    duplicates = json.loads(preview["duplicates_json"])
    if errors:
        raise PolicyError("preview still has validation errors")
    if duplicates and not acknowledge_duplicates:
        raise PolicyError("acknowledge duplicate hostnames or addresses before commit")
    rows = json.loads(preview["rows_json"])
    import_id = new_id()
    imported_at = utcnow()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO inventory_imports (
              id, preview_id, filename, sha256, worksheet, mapping_json, imported_at, imported_by, row_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                import_id,
                preview_id,
                preview["filename"],
                preview["sha256"],
                preview["worksheet"],
                preview["mapping_json"],
                imported_at,
                actor,
                len(rows),
            ),
        )
        tx.execute("UPDATE inventory_previews SET committed = 1 WHERE id = ?", (preview_id,))
        for row in rows:
            values = row["values"]
            tx.execute(
                """
                INSERT INTO inventory_rows (
                  id, import_id, row_number, hostname, ip_address, subnet, device_type, os_name, vlan,
                  enclave, department, owner, mission_function, criticality, maintenance_window,
                  scan_restrictions, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    import_id,
                    row["row_number"],
                    values.get("hostname"),
                    values.get("ip_address"),
                    values.get("subnet"),
                    values.get("device_type"),
                    values.get("os_name"),
                    values.get("vlan"),
                    values.get("enclave"),
                    values.get("department"),
                    values.get("owner"),
                    values.get("mission_function"),
                    values.get("criticality"),
                    values.get("maintenance_window"),
                    values.get("scan_restrictions"),
                    json.dumps(row["raw"]),
                ),
            )
        append_event(
            db,
            actor=actor,
            action="inventory.import",
            outcome="committed",
            object_type="inventory_import",
            object_id=import_id,
            detail={
                "filename": preview["filename"],
                "sha256": preview["sha256"],
                "worksheet": preview["worksheet"],
                "row_count": len(rows),
                "duplicate_count": len(duplicates),
            },
            tx=tx,
        )
    return {"import_id": import_id, "row_count": len(rows), "sha256": preview["sha256"], "worksheet": preview["worksheet"]}


def list_imports(db: Database) -> list[dict]:
    return db.query(
        "SELECT id, filename, sha256, worksheet, imported_at, imported_by, row_count FROM inventory_imports ORDER BY imported_at"
    )


def list_rows(db: Database) -> list[dict]:
    return db.query(
        """
        SELECT r.*, i.filename, i.sha256, i.imported_at, i.worksheet
        FROM inventory_rows r JOIN inventory_imports i ON i.id = r.import_id
        ORDER BY i.imported_at, r.row_number
        """
    )

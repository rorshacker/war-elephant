from __future__ import annotations

import csv
import io
import json

from .util import canon, sha256_text


def csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def _write_csv(headers: list[str], rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: csv_safe(row.get(key)) for key in headers})
    return buffer.getvalue()


def inventory_rows(db) -> list[dict]:
    rows = []
    for asset in db.query("SELECT * FROM assets ORDER BY display_name"):
        flags = json.loads(asset["flags_json"])
        rows.append(
            {
                "id": asset["id"],
                "display_name": asset["display_name"],
                "hostname": asset["hostname"],
                "ip_address": asset["ip_address"],
                "os_name": asset["os_name"],
                "device_type": asset["device_type"],
                "owner": asset["owner"],
                "criticality": asset["criticality"],
                "match_basis": asset["match_basis"],
                "identity_confidence": asset["identity_confidence"],
                "flags": " ".join(flags),
                "human_decision": asset["human_decision"],
                "lab_target_path": asset["lab_target_path"],
            }
        )
    return rows


def finding_rows(db) -> list[dict]:
    return db.query(
        """
        SELECT id, asset_id, rule_id, rule_version, classification, result, observation, collected_at,
               check_impl_version, evidence_kind, evidence_ref, rule_source
        FROM findings ORDER BY collected_at, rule_id
        """
    )


def execution_rows(db) -> list[dict]:
    return db.query(
        """
        SELECT id, proposal_id, approval_id, asset_id, action_type, status, prior_hash, post_hash,
               remote_atomic, started_at, finished_at, adapter_name, adapter_version
        FROM execution_intents ORDER BY started_at
        """
    )


def bundle(db, settings) -> dict:
    from .baselines import recommendations
    from .audit import verify_chain

    manual = [row for row in finding_rows(db) if row["result"] == "not_reviewed"]
    return {
        "origin": settings.enclave,
        "schema_version": settings.schema_version,
        "inventory": inventory_rows(db),
        "conflicts": db.query("SELECT id, kind, detail_json FROM conflicts"),
        "baselines": recommendations(db),
        "findings": finding_rows(db),
        "executions": execution_rows(db),
        "outstanding_manual_work": manual,
        "audit": verify_chain(db),
    }


def csv_for(kind: str, db) -> str:
    if kind == "inventory":
        rows = inventory_rows(db)
    elif kind == "findings":
        rows = finding_rows(db)
    elif kind == "executions":
        rows = execution_rows(db)
    else:
        from .policy import PolicyError

        raise PolicyError("unknown report")
    headers = list(rows[0].keys()) if rows else ["id"]
    return _write_csv(headers, rows)


def content_hash(payload: dict) -> str:
    return sha256_text(canon(payload))


def work_summary(db) -> dict:
    findings = finding_rows(db)
    counts: dict[str, int] = {}
    for row in findings:
        counts[row["result"]] = counts.get(row["result"], 0) + 1
    selected = db.query("SELECT id, hostname, display_name, ip_address, os_name FROM assets WHERE selected = 1 ORDER BY display_name")
    return {
        "statement": "This is a record of what was stored. It is not a compliance determination, and imported check text was not executed.",
        "selected_assets": selected,
        "scans": db.query("SELECT id, kind, label, status, created_at FROM content_scans ORDER BY created_at DESC"),
        "discovery_jobs": db.query("SELECT id, kind, status, error, created_at, finished_at FROM discovery_jobs ORDER BY created_at DESC"),
        "finding_counts": counts,
        "findings": len(findings),
        "executions": execution_rows(db),
    }


def checklist_ckl(db, asset_id: str) -> tuple[str, str]:
    from xml.sax.saxutils import escape

    from .policy import PolicyError
    from .stig import list_benchmarks, list_rules

    asset = db.query_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not asset:
        raise PolicyError("asset not found", 404)
    benchmarks = [row for row in list_benchmarks(db) if row["version_label"] == "newest imported version"]
    if not benchmarks:
        raise PolicyError("import a checklist before exporting one")
    benchmark = benchmarks[-1]
    rules = list_rules(db, benchmark["id"])
    findings = {}
    for row in db.query(
        "SELECT rule_id, result, observation, collected_at FROM findings WHERE asset_id = ? ORDER BY collected_at",
        (asset_id,),
    ):
        findings[row["rule_id"]] = row
    vulns = []
    for rule in rules:
        found = findings.get(rule["rule_id"])
        result = found["result"] if found else "not_reviewed"
        status = {"pass": "NotAFinding", "fail": "Open", "not_applicable": "Not_Applicable"}.get(result, "Not_Reviewed")
        detail = found["observation"] if found else "No result was recorded for this rule."
        fields = [
            ("Vuln_Num", rule["rule_id"]),
            ("Severity", rule["severity"] or ""),
            ("Rule_ID", rule["rule_id"]),
            ("Rule_Ver", rule["version"] or ""),
            ("Rule_Title", rule["title"] or ""),
            ("Check_Content", rule["check_text"] or ""),
            ("Fix_Text", rule["fix_text"] or ""),
        ]
        data = "".join(
            f"<STIG_DATA><VULN_ATTRIBUTE>{escape(name)}</VULN_ATTRIBUTE><ATTRIBUTE_DATA>{escape(value)}</ATTRIBUTE_DATA></STIG_DATA>"
            for name, value in fields
        )
        vulns.append(
            "<VULN>"
            f"{data}<STATUS>{status}</STATUS>"
            f"<FINDING_DETAILS>{escape(detail)} Imported check text was not executed.</FINDING_DETAILS>"
            f"<COMMENTS>{escape('Stored result: ' + result)}</COMMENTS>"
            "<SEVERITY_OVERRIDE></SEVERITY_OVERRIDE><SEVERITY_JUSTIFICATION></SEVERITY_JUSTIFICATION>"
            "</VULN>"
        )
    hostname = asset["hostname"] or asset["display_name"] or asset["id"]
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<CHECKLIST>"
        "<ASSET>"
        f"<HOST_NAME>{escape(hostname)}</HOST_NAME>"
        f"<HOST_IP>{escape(asset['ip_address'] or '')}</HOST_IP>"
        f"<HOST_FQDN>{escape(hostname)}</HOST_FQDN>"
        "</ASSET>"
        "<STIGS><iSTIG><STIG_INFO>"
        f"<SI_DATA><SID_NAME>title</SID_NAME><SID_DATA>{escape(benchmark['title'] or benchmark['benchmark_id'])}</SID_DATA></SI_DATA>"
        f"<SI_DATA><SID_NAME>version</SID_NAME><SID_DATA>{escape(benchmark['version'] or '')}</SID_DATA></SI_DATA>"
        "<SI_DATA><SID_NAME>releaseinfo</SID_NAME><SID_DATA>newest imported version</SID_DATA></SI_DATA>"
        "</STIG_INFO>"
        + "".join(vulns)
        + "</iSTIG></STIGS></CHECKLIST>"
    )
    safe_name = "".join(char if char.isalnum() or char in "-_" else "_" for char in hostname) or "asset"
    return body, f"{safe_name}-checklist.ckl"

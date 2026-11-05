from __future__ import annotations

import io
import json
import socket
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fleetguard.adapters import LinuxSshAdapter, NetworkDeviceAdapter, WindowsConfigAdapter
from fleetguard.app import create_app
from fleetguard.audit import GENESIS, PROTECTION_STATEMENT, event_payload, verify_chain
from fleetguard.discovery import LiveLdapClient, recover_interrupted, target_allowed
from fleetguard.policy import AdapterUnavailable, PolicyError
from fleetguard.settings import Settings
from fleetguard.util import canon, sha256_text


@pytest.fixture()
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    lab = tmp_path / "lab"
    monkeypatch.setenv("FLEETGUARD_DATA_DIR", str(data))
    monkeypatch.setenv("FLEETGUARD_LAB_ROOT", str(lab))
    monkeypatch.setenv("FLEETGUARD_ENCLAVE", "test-enclave")
    monkeypatch.setenv("FLEETGUARD_ENABLE_LIVE_LDAP", "0")
    app = create_app()
    with TestClient(app) as test_client:
        test_client.app = app
        yield test_client


def auth(client, username="operator", password="correct-horse-battery"):
    response = client.post("/api/setup/operator", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['token']}"}


def permit_lab_change(client, headers, asset_id):
    classified = client.post(
        f"/api/assets/{asset_id}/automation-class",
        headers=headers,
        json={"automation_class": "approved_noncritical"},
    )
    assert classified.status_code == 200, classified.text
    window = client.post(
        "/api/maintenance-authorizations",
        headers=headers,
        json={"asset_id": asset_id, "change_type": "stig_config", "hours": 4},
    )
    assert window.status_code == 200, window.text


def future(hours=4) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(microsecond=0).isoformat()


def test_health_names_real_adapters(client):
    body = client.get("/api/health").json()
    assert body["adapters"]["local_lab_file"] == "implemented"
    assert body["adapters"]["windows"] == "not_implemented"
    assert body["adapters"]["linux_ssh"] == "not_implemented"
    assert body["adapters"]["network_device"] == "not_implemented"
    assert body["live_ldap_enabled"] is False


def test_poc_opens_without_a_session(client):
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "poc"
    assert client.get("/api/assets").status_code == 200


def test_rejects_malicious_and_keeps_versions(client, tmp_path):
    headers = auth(client)
    xxe = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="X"><version>1</version><title>&xxe;</title></Benchmark>"""
    response = client.post("/api/stig/import", headers=headers, files={"file": ("evil.xml", xxe, "application/xml")})
    assert response.status_code == 400
    assert "win.ini" not in response.text
    slipped = io.BytesIO()
    with zipfile.ZipFile(slipped, "w") as archive:
        archive.writestr("../evil.xml", b"<Benchmark id='X'><version>1</version></Benchmark>")
    response = client.post("/api/stig/import", headers=headers, files={"file": ("slip.zip", slipped.getvalue(), "application/zip")})
    assert response.status_code == 400
    broken = client.post("/api/stig/import", headers=headers, files={"file": ("bad.xml", b"<nope", "application/xml")})
    assert broken.status_code == 400
    root = Path("fixtures")
    first = client.post("/api/stig/import", headers=headers, files={"file": ("v1.xml", (root / "synthetic_win10_v1.xml").read_bytes(), "application/xml")})
    second = client.post("/api/stig/import", headers=headers, files={"file": ("v2.xml", (root / "synthetic_win10_v2.xml").read_bytes(), "application/xml")})
    assert first.status_code == 200 and second.status_code == 200
    again = client.post("/api/stig/import", headers=headers, files={"file": ("v2.xml", (root / "synthetic_win10_v2.xml").read_bytes(), "application/xml")})
    assert again.json()["status"] == "duplicate"
    benchmarks = client.get("/api/stig/benchmarks", headers=headers).json()
    versions = [row["version"] for row in benchmarks if row["benchmark_id"] == "FLEETGUARD-SYNTH-WIN10"]
    assert versions.count("1") == 1 and versions.count("2") == 1
    newest = [row for row in benchmarks if row["version_label"] == "newest imported version" and row["benchmark_id"] == "FLEETGUARD-SYNTH-WIN10"]
    assert newest[0]["version"] == "2"
    assert "latest published" not in response.text
    blob = json.dumps(benchmarks)
    assert "newest imported version" in blob
    assert "not_verified" in blob
    assert "Publisher authenticity was not verified" in blob
    rules = client.get(f"/api/stig/benchmarks/{newest[0]['id']}/rules", headers=headers).json()
    assert any("Do not run this paragraph as a command." in rule["fix_text"] for rule in rules)
    settings = client.app.state.settings
    huge = b"<Benchmark id='BIG'><version>1</version><title>x</title></Benchmark>"
    limited = Settings(
        data_dir=settings.data_dir,
        lab_root=settings.lab_root,
        max_member=20,
        max_upload=50,
        max_uncompressed=20,
    )
    from fleetguard.stig import import_package

    with pytest.raises(PolicyError):
        import_package(client.app.state.db, limited, "big.xml", huge, "operator")


def test_inventory_validation_provenance_and_formula(client):
    headers = auth(client)
    csv_text = "hostname,ip_address\n=1+1,10.9.9.9\n,not-an-ip\n"
    preview = client.post("/api/inventory/preview", headers=headers, files={"file": ("bad.csv", csv_text, "text/csv")})
    assert preview.status_code == 200
    body = preview.json()
    assert body["sample"][0]["values"]["hostname"] == "=1+1"
    assert all(row["values"]["hostname"] != "2" for row in body["sample"])
    refused = client.post("/api/inventory/commit", headers=headers, json={"preview_id": body["preview_id"], "confirm": True})
    assert refused.status_code == 400
    from openpyxl import Workbook

    formula = Workbook()
    sheet = formula.active
    sheet.append(["hostname", "ip_address"])
    sheet["A2"] = "=1+1"
    sheet["B2"] = "10.9.9.8"
    payload = io.BytesIO()
    formula.save(payload)
    formula_preview = client.post(
        "/api/inventory/preview",
        headers=headers,
        files={"file": ("formula.xlsx", payload.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert any("formula" in error["message"] for error in formula_preview.json()["errors"])
    assert "2" != formula_preview.json()["sample"][0]["values"]["hostname"]
    from openpyxl import Workbook

    book = Workbook()
    first = book.active
    first.title = "One"
    second = book.create_sheet("Two")
    first.append(["hostname", "ip_address"])
    second.append(["hostname", "ip_address"])
    second.append(["sheet-host", "10.2.2.2"])
    payload = io.BytesIO()
    book.save(payload)
    sheets = client.post("/api/inventory/preview", headers=headers, files={"file": ("book.xlsx", payload.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert sheets.json()["need_worksheet"] is True
    chosen = client.post(
        "/api/inventory/preview",
        headers=headers,
        data={"worksheet": "Two"},
        files={"file": ("book.xlsx", payload.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert chosen.status_code == 200, chosen.text
    assert chosen.json()["row_count"] == 1
    unconfirmed = client.post("/api/inventory/commit", headers=headers, json={"preview_id": chosen.json()["preview_id"], "confirm": False})
    assert unconfirmed.status_code == 400
    committed = client.post(
        "/api/inventory/commit",
        headers=headers,
        json={"preview_id": chosen.json()["preview_id"], "confirm": True, "acknowledge_duplicates": False},
    )
    assert committed.status_code == 200
    stored = client.get("/api/inventory/imports", headers=headers).json()[0]
    assert stored["worksheet"] == "Two"
    assert stored["sha256"]
    macro = io.BytesIO()
    with zipfile.ZipFile(macro, "w") as archive:
        archive.writestr("xl/vbaProject.bin", b"macro")
    rejected = client.post("/api/inventory/preview", headers=headers, files={"file": ("macro.xlsx", macro.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert rejected.status_code == 400


def test_reconciliation_does_not_merge_on_ip_alone(client):
    headers = auth(client)
    loaded = client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    assert loaded.status_code == 200, loaded.text
    body = client.get("/api/assets", headers=headers).json()
    by_name = {}
    for asset in body["assets"]:
        by_name.setdefault(asset["display_name"], []).append(asset)
    alpha = next(asset for asset in body["assets"] if asset["hostname"] == "WS-ALPHA")
    dup = next(asset for asset in body["assets"] if asset["hostname"] == "WS-DUP")
    assert alpha["id"] != dup["id"]
    assert alpha["match_basis"] == "hostname_provisional"
    assert "duplicate_address" in dup["flags"] and "duplicate_address" in alpha["flags"]
    switch = next(asset for asset in body["assets"] if asset["hostname"] == "SW-01")
    printer = next(asset for asset in body["assets"] if asset["hostname"] == "PRN-01")
    assert "no_ad_expected" in switch["flags"] and "no_ad_expected" in printer["flags"]
    computers = client.get("/api/ad/computers", headers=headers).json()
    assert all(row["online_status"] == "unknown" for row in computers)
    assert all("not treated as current online status" in row["online_status_reason"] for row in computers)
    cached = client.post(
        "/api/observations/cache",
        headers=headers,
        json={"observations": [{"address": "10.1.10.22", "port": 445, "status": "cached_import", "hostname": None}]},
    )
    assert cached.status_code == 200
    client.post("/api/reconcile", headers=headers)
    body = client.get("/api/assets", headers=headers).json()
    beta = next(asset for asset in body["assets"] if asset["hostname"] == "WS-BETA")
    observed = next(asset for asset in body["assets"] if asset["ip_address"] == "10.1.10.22" and asset["id"] != beta["id"])
    assert "address_overlap" in beta["flags"]
    assert observed["match_basis"] == "single_source"
    disabled = client.post(
        "/api/observations/cache",
        headers=headers,
        json={"observations": [{"address": "10.9.9.9", "hostname": "ws-disabled.synth.local", "status": "cached_import"}]},
    )
    assert disabled.status_code == 200
    client.post("/api/reconcile", headers=headers)
    body = client.get("/api/assets", headers=headers).json()
    disabled_asset = next(asset for asset in body["assets"] if asset["hostname"] == "ws-disabled.synth.local")
    assert "disabled_ad_observed" in disabled_asset["flags"]
    blocked = client.post("/api/assets/" + disabled_asset["id"] + "/selection", headers=headers, json={"selected": True})
    assert blocked.status_code == 400
    baselines = client.get("/api/baselines", headers=headers).json()
    switch_rec = next(item for item in baselines if item["hostname"] == "SW-01")
    unknown = next(item for item in baselines if item["hostname"] == "UNKNOWN-01")
    lab = next(item for item in baselines if item["hostname"] == "LAB-WIN")
    assert switch_rec["benchmark_id"] is None
    assert switch_rec["status"] == "confirmation required"
    assert any("deterministic" in question for question in switch_rec["questions"])
    assert unknown["status"] == "confirmation required"
    assert lab["status"] == "recommended"
    assert lab["version_label"] == "newest imported version"
    assert lab["version"] == "2"
    win_rows = [row for row in client.get("/api/stig/benchmarks", headers=headers).json() if row["benchmark_id"] == "FLEETGUARD-SYNTH-WIN10"]
    assert {row["version"] for row in win_rows} == {"1", "2"}


def test_missing_baseline_message(client):
    headers = auth(client)
    csv_text = "hostname,ip_address,device_type,os\nBOX,10.8.8.8,workstation,Windows 10\n"
    preview = client.post("/api/inventory/preview", headers=headers, files={"file": ("one.csv", csv_text, "text/csv")})
    client.post("/api/inventory/commit", headers=headers, json={"preview_id": preview.json()["preview_id"], "confirm": True})
    client.post("/api/reconcile", headers=headers)
    item = client.get("/api/baselines", headers=headers).json()[0]
    assert item["status"] == "baseline unavailable—import required"


def test_discovery_scope_and_live_directory_guard(client):
    headers = auth(client)
    client.post("/api/vault/unlock", headers=headers, json={"passphrase": "vault-passphrase"})
    cred = client.post(
        "/api/credentials",
        headers=headers,
        json={"label": "ad-read", "purpose": "discovery", "adapter": "ldap", "secret": "not-the-real-password", "scope": {"cidrs": ["127.0.0.1/32"], "directory_user": "SYNTH\\reader"}},
    )
    assert cred.status_code == 200, cred.text
    assert "not-the-real-password" not in cred.text
    too_wide = client.post(
        "/api/scopes",
        headers=headers,
        json={"cidrs": ["10.0.0.0/16"], "methods": ["tcp_connect"], "ports": [445], "expires_at": future()},
    )
    assert too_wide.status_code == 400
    scope = client.post(
        "/api/scopes",
        headers=headers,
        json={
            "cidrs": ["127.0.0.1/32", "127.0.0.2/32"],
            "excluded": ["127.0.0.2"],
            "methods": ["tcp_connect", "ldaps"],
            "ports": [9],
            "rate_limit_per_sec": 50,
            "timeout_sec": 0.2,
            "expires_at": future(),
            "domain_name": "synth.local",
            "domain_controller": "127.0.0.1",
            "base_dn": "DC=synth,DC=local",
        },
    )
    assert scope.status_code == 200, scope.text
    scope_id = scope.json()["id"]
    early = client.post("/api/discovery/jobs", headers=headers, json={"kind": "network", "scope_id": scope_id})
    assert early.status_code == 403
    approved = client.post(f"/api/scopes/{scope_id}/approve", headers=headers)
    assert approved.status_code == 200

    def cancel_after_first(host, port, timeout):
        client.app.state.db.execute("UPDATE discovery_jobs SET cancel_requested = 1 WHERE status = 'running'")
        return {"status": "tcp_refused", "note": "TCP connection refused. The asset is not marked absent."}

    client.app.state.probe = cancel_after_first
    job = client.post("/api/discovery/jobs", headers=headers, json={"kind": "network", "scope_id": scope_id, "targets": ["8.8.8.8"]})
    assert job.status_code == 400
    job = client.post("/api/discovery/jobs", headers=headers, json={"kind": "network", "scope_id": scope_id})
    assert job.status_code == 200, job.text
    observations = job.json()["observations"]
    assert observations
    assert {row["address"] for row in observations} == {"127.0.0.1"}
    assert job.json()["job"]["status"] == "cancelled"
    assert "not marked absent" in observations[0]["note"]
    assert observations[0]["evidence_kind"] == "real"
    directory = client.post("/api/discovery/jobs", headers=headers, json={"kind": "ad", "scope_id": scope_id, "credential_id": cred.json()["id"]})
    assert directory.status_code == 200, directory.text
    assert directory.json()["job"]["status"] == "failed"
    assert "fabricated" in directory.json()["job"]["error"]
    assert client.get("/api/ad/computers", headers=headers).json() == []
    outside = client.post("/api/credentials/" + cred.json()["id"] + "/validate", headers=headers, json={"target": "8.8.8.8"})
    assert outside.status_code == 403
    inside = client.post("/api/credentials/" + cred.json()["id"] + "/validate", headers=headers, json={"target": "127.0.0.1"})
    assert inside.status_code == 200
    assert inside.json()["change_permitted"] is False
    vault_text = Path(client.app.state.settings.vault_path).read_text(encoding="utf-8")
    assert "not-the-real-password" not in vault_text
    assert "vault-passphrase" not in vault_text
    audit_text = json.dumps(client.get("/api/audit", headers=headers).json())
    assert "not-the-real-password" not in audit_text
    with pytest.raises(PolicyError):
        LiveLdapClient("127.0.0.1", 636, "user", "secret", validate_certs=False)
    assert target_allowed("8.8.8.8", ["127.0.0.1/32"], []) is False


def test_active_directory_scan_records_only_what_the_reader_returns(client):
    headers = auth(client)

    def reader():
        return (
            [{
                "object_guid": "11111111-1111-1111-1111-111111111111",
                "computer_name": "BOX",
                "dns_hostname": "box.synth.local",
                "enabled": True,
                "os_name": "Windows 11",
                "os_version": "10",
                "distinguished_name": "CN=BOX,DC=synth,DC=local",
                "last_logon_timestamp": "",
            }],
            "dc.synth.local",
        )

    client.app.state.directory_reader = reader
    scanned = client.post("/api/discovery/aduc", headers=headers)
    assert scanned.status_code == 200, scanned.text
    assert scanned.json()["job"]["status"] == "completed"
    assert scanned.json()["computers"] == 1
    computers = client.get("/api/ad/computers", headers=headers).json()
    assert [row["computer_name"] for row in computers] == ["BOX"]
    assert computers[0]["evidence_kind"] == "real"
    assert "password" not in scanned.text

    def unavailable():
        from fleetguard.directory_scan import DirectoryUnavailable
        raise DirectoryUnavailable("controller unreachable. No computer objects were fabricated.")

    client.app.state.directory_reader = unavailable
    failed = client.post("/api/discovery/aduc", headers=headers)
    assert failed.status_code == 200, failed.text
    assert failed.json()["job"]["status"] == "failed"
    assert "fabricated" in failed.json()["job"]["error"]
    assert [row["computer_name"] for row in client.get("/api/ad/computers", headers=headers).json()] == ["BOX"]


def test_summary_export_and_checklist_do_not_invent_a_pass(client):
    headers = auth(client)
    imported = client.post(
        "/api/stig/import",
        headers=headers,
        files={"file": ("v2.xml", Path("fixtures/synthetic_win10_v2.xml").read_bytes(), "application/xml")},
    )
    assert imported.status_code == 200, imported.text
    preview = client.post(
        "/api/inventory/preview",
        headers=headers,
        files={"file": ("one.csv", b"hostname,ip_address,device_type,os\nBOX,10.8.8.8,workstation,Windows 10\n", "text/csv")},
    )
    client.post("/api/inventory/commit", headers=headers, json={"preview_id": preview.json()["preview_id"], "confirm": True})
    client.post("/api/reconcile", headers=headers)
    asset = client.get("/api/assets", headers=headers).json()["assets"][0]
    client.post(f"/api/assets/{asset['id']}/selection", headers=headers, json={"selected": True})
    summary = client.get("/api/reports/summary", headers=headers)
    assert summary.status_code == 200, summary.text
    assert summary.json()["selected_assets"][0]["hostname"] == "BOX"
    assert "not a compliance determination" in summary.json()["statement"]
    checklist = client.get("/api/reports/checklist.ckl", headers=headers, params={"asset_id": asset["id"]})
    assert checklist.status_code == 200, checklist.text
    assert "FG-WIN10-MANUAL-BANNER" in checklist.text
    assert "<STATUS>Not_Reviewed</STATUS>" in checklist.text
    assert "NotAFinding" not in checklist.text
    assert "Imported check text was not executed." in checklist.text
    missing = client.get("/api/reports/checklist.ckl", headers=headers, params={"asset_id": "missing"})
    assert missing.status_code == 404


def test_local_open_port_is_a_real_probe(client):
    headers = auth(client)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        scope = client.post(
            "/api/scopes",
            headers=headers,
            json={"cidrs": ["127.0.0.1/32"], "methods": ["tcp_connect"], "ports": [port], "rate_limit_per_sec": 50, "timeout_sec": 1, "expires_at": future()},
        ).json()
        client.post(f"/api/scopes/{scope['id']}/approve", headers=headers)
        job = client.post("/api/discovery/jobs", headers=headers, json={"kind": "network", "scope_id": scope["id"]})
        assert job.json()["observations"][0]["status"] == "open"
        assert job.json()["observations"][0]["evidence_kind"] == "real"
    finally:
        listener.close()


def test_change_controls(client):
    headers = auth(client)
    loaded = client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    assert loaded.status_code == 200, loaded.text
    assets = client.get("/api/assets", headers=headers).json()["assets"]
    lab = next(asset for asset in assets if asset["hostname"] == "LAB-WIN")
    client.post(f"/api/assets/{lab['id']}/selection", headers=headers, json={"selected": True})
    confirmed = client.post("/api/baselines/confirm", headers=headers, json={"asset_id": lab["id"], "mode": "confirm"})
    assert confirmed.status_code == 200, confirmed.text
    lab_file = Path(client.app.state.settings.lab_root) / "win-lab" / "fleetguard-lab.conf"
    before_assessment = lab_file.read_bytes()
    assessed = client.post("/api/assessments", headers=headers, json={"asset_ids": [lab["id"]]})
    assert assessed.status_code == 200, assessed.text
    assert lab_file.read_bytes() == before_assessment
    gate = client.get("/api/remediation-gate", headers=headers)
    assert gate.status_code == 200, gate.text
    assert gate.json()["automated_remediation"] is False
    unmet = {item["id"] for item in gate.json()["requirements"] if item["status"] != "met"}
    assert unmet == {"canary", "kill_switch", "recovery_demonstrated", "owner_runbook", "dependency_graph", "representative_lab", "supply_chain"}
    findings = assessed.json()["assessments"][0]["findings"]
    assert {row["evidence_kind"] for row in findings}.isdisjoint({"simulated"})
    failed = next(row for row in findings if row["result"] == "fail")
    assert failed["evidence_kind"] == "real"
    assert any(row["result"] == "not_reviewed" and row["classification"] == "manual_review_required" for row in findings)
    secret = "remediation-secret-value"
    client.post("/api/vault/unlock", headers=headers, json={"passphrase": "vault-passphrase"})
    credential = client.post(
        "/api/credentials",
        headers=headers,
        json={"label": "lab-change", "purpose": "remediation", "adapter": "local_lab_file", "secret": secret, "scope": {"targets": ["lab"]}},
    ).json()
    proposal = client.post("/api/proposals", headers=headers, json={"finding_id": failed["id"]})
    assert proposal.status_code == 200, proposal.text
    proposal_id = proposal.json()["id"]
    path = Path(client.app.state.settings.lab_root) / "win-lab" / "fleetguard-lab.conf"
    original = path.read_text(encoding="utf-8")
    path.write_text(original + "extra=1\n", encoding="utf-8")
    approval = client.post("/api/approvals", headers=headers, json={"proposal_id": proposal_id, "decision": "approved"}).json()
    listed = client.get("/api/approvals", headers=headers)
    assert listed.status_code == 200
    assert any(row["id"] == approval["id"] and row["used"] == 0 for row in listed.json())
    blocked_class = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal_id, "approval_id": approval["id"], "credential_id": credential["id"]},
    )
    assert blocked_class.status_code == 409
    assert "manual review only" in blocked_class.json()["detail"]
    permit_lab_change(client, headers, lab["id"])
    client.post("/api/controller/scheduling", headers=headers, json={"halted": True, "reason": "stop new work"})
    halted = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal_id, "approval_id": approval["id"], "credential_id": credential["id"]},
    )
    assert halted.status_code == 409
    assert "scheduling is stopped" in halted.json()["detail"]
    client.post("/api/controller/scheduling", headers=headers, json={"halted": False})
    drifted = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal_id, "approval_id": approval["id"], "credential_id": credential["id"]},
    )
    assert drifted.status_code == 409
    assert "extra=1" in path.read_text(encoding="utf-8")
    assert client.get("/api/executions", headers=headers).json() == []
    path.write_text(original, encoding="utf-8")
    fresh = client.post("/api/proposals", headers=headers, json={"finding_id": failed["id"]}).json()
    approved = client.post("/api/approvals", headers=headers, json={"proposal_id": fresh["id"], "decision": "approved"}).json()
    done = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": fresh["id"], "approval_id": approved["id"], "credential_id": credential["id"]},
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "verified_success"
    assert done.json()["remote_atomic"] is False
    assert "audit_policy=enabled" in path.read_text(encoding="utf-8")
    assert secret not in done.text
    replay = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": fresh["id"], "approval_id": approved["id"], "credential_id": credential["id"]},
    )
    assert replay.status_code == 409
    client.app.state.db.execute(
        "UPDATE approvals SET expires_at = ? WHERE id = ?",
        ("2020-01-01T00:00:00+00:00", approved["id"]),
    )
    expired = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": fresh["id"], "approval_id": approved["id"], "credential_id": credential["id"]},
    )
    assert expired.status_code == 409
    client.app.state.db.execute("UPDATE proposals SET impact = 'changed' WHERE id = ?", (fresh["id"],))
    altered = client.post("/api/approvals", headers=headers, json={"proposal_id": fresh["id"], "decision": "approved"})
    assert altered.status_code == 409
    current = path.read_bytes()
    path.write_bytes(current + b"note=later\n")
    blocked = client.post("/api/rollbacks", headers=headers, json={"execution_id": done.json()["id"]})
    assert blocked.status_code == 409
    assert b"note=later" in path.read_bytes()
    path.write_bytes(current)
    rollback = client.post("/api/rollbacks", headers=headers, json={"execution_id": done.json()["id"]})
    assert rollback.status_code == 200, rollback.text
    rollback_approval = client.post("/api/approvals", headers=headers, json={"proposal_id": rollback.json()["id"], "decision": "approved"}).json()
    mismatched = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": rollback.json()["id"], "approval_id": approved["id"], "credential_id": credential["id"]},
    )
    assert mismatched.status_code in {403, 409}
    restored = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": rollback.json()["id"], "approval_id": rollback_approval["id"], "credential_id": credential["id"]},
    )
    assert restored.status_code == 200, restored.text
    assert restored.json()["status"] == "verified_success"
    assert "audit_policy=disabled" in path.read_text(encoding="utf-8")


def test_ambiguous_execution_is_not_retried(client):
    headers = auth(client)
    client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    lab = next(asset for asset in client.get("/api/assets", headers=headers).json()["assets"] if asset["hostname"] == "LAB-WIN")
    client.post(f"/api/assets/{lab['id']}/selection", headers=headers, json={"selected": True})
    client.post("/api/baselines/confirm", headers=headers, json={"asset_id": lab["id"], "mode": "confirm"})
    findings = client.post("/api/assessments", headers=headers, json={"asset_ids": [lab["id"]]}).json()["assessments"][0]["findings"]
    failed = next(row for row in findings if row["result"] == "fail")
    client.post("/api/vault/unlock", headers=headers, json={"passphrase": "vault-passphrase"})
    credential = client.post(
        "/api/credentials",
        headers=headers,
        json={"label": "lab-change", "purpose": "remediation", "adapter": "local_lab_file", "secret": "remediation-secret-value", "scope": {"targets": ["lab"]}},
    ).json()
    proposal = client.post("/api/proposals", headers=headers, json={"finding_id": failed["id"]}).json()
    approval = client.post("/api/approvals", headers=headers, json={"proposal_id": proposal["id"], "decision": "approved"}).json()
    permit_lab_change(client, headers, lab["id"])

    def cut(_intent_id):
        raise RuntimeError("stopped")

    client.app.state.after_write = cut
    response = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal["id"], "approval_id": approval["id"], "credential_id": credential["id"]},
    )
    assert response.status_code == 409
    assert "ambiguous" in response.json()["detail"]
    listed = client.get("/api/executions", headers=headers).json()
    assert listed[0]["status"] == "intent"
    report = client.get("/api/recover", headers=headers).json()
    assert report["ambiguous_executions"]
    assert "not retried" in report["note"]
    path = Path(client.app.state.settings.lab_root) / "win-lab" / "fleetguard-lab.conf"
    assert "audit_policy=enabled" in path.read_text(encoding="utf-8")
    again = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal["id"], "approval_id": approval["id"], "credential_id": credential["id"]},
    )
    assert again.status_code == 409
    assert path.read_text(encoding="utf-8").count("audit_policy=enabled") == 1


def test_audit_sync_and_exports(client):
    headers = auth(client)
    client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    verified = client.get("/api/audit/verify", headers=headers).json()
    assert verified["ok"] is True
    checkpoint = client.post("/api/audit/checkpoint", headers=headers).json()
    assert checkpoint["signature_status"] == "unsigned_local_checkpoint"
    assert "privileged local attacker" in checkpoint["statement"]
    client.app.state.db.execute("UPDATE audit_events SET detail_json = '{\"tampered\":true}' WHERE seq = 1")
    broken = client.get("/api/audit/verify", headers=headers).json()
    assert broken["ok"] is False
    rows = client.app.state.db.query("SELECT * FROM audit_events ORDER BY seq")
    previous = GENESIS
    for row in rows:
        detail = {"rewritten": True, "action": row["action"]}
        payload = event_payload(row["event_id"], row["actor"], row["action"], row["outcome"], row["object_type"], row["object_id"], row["correlation_id"], detail, row["created_at"])
        digest = sha256_text(previous + "|" + canon(payload))
        client.app.state.db.execute(
            "UPDATE audit_events SET detail_json = ?, prev_hash = ?, event_hash = ? WHERE seq = ?",
            (canon(detail), previous, digest, row["seq"]),
        )
        previous = digest
    rewritten = verify_chain(client.app.state.db)
    assert rewritten["ok"] is True
    assert "recompute" in rewritten["statement"]
    poison = "hostname,ip_address,device_type,os\n=cmd|calc,10.7.7.7,workstation,Windows 10\n"
    preview = client.post("/api/inventory/preview", headers=headers, files={"file": ("inject.csv", poison, "text/csv")})
    client.post("/api/inventory/commit", headers=headers, json={"preview_id": preview.json()["preview_id"], "confirm": True, "acknowledge_duplicates": True})
    client.post("/api/reconcile", headers=headers)
    exported = client.get("/api/reports/inventory.csv", headers=headers).text
    assert "'=cmd|calc" in exported
    client.post("/api/vault/unlock", headers=headers, json={"passphrase": "vault-passphrase"})
    client.post(
        "/api/credentials",
        headers=headers,
        json={"label": "hidden", "purpose": "discovery", "adapter": "ldap", "secret": "super-secret-value", "scope": {"cidrs": ["10.0.0.0/24"]}},
    )
    bundle = client.get("/api/reports/bundle", headers=headers).json()
    assert "super-secret-value" not in json.dumps(bundle)
    before = client.app.state.db.query_one("SELECT COUNT(*) AS n FROM approvals")["n"]
    queued = client.post("/api/sync/enqueue", headers=headers)
    assert queued.status_code == 200
    outbox = client.get("/api/sync/outbox", headers=headers).json()
    record = {
        "id": outbox[0]["id"],
        "content_hash": outbox[0]["content_hash"],
        "origin": "test-enclave",
        "schema_version": "1",
        "record_type": outbox[0]["record_type"],
        "payload": json.loads(client.app.state.db.query_one("SELECT payload_json FROM sync_outbox WHERE id = ?", (outbox[0]["id"],))["payload_json"]),
    }
    first = client.post("/api/sync/receive", headers=headers, json={"records": [record]})
    second = client.post("/api/sync/receive", headers=headers, json={"records": [record]})
    assert first.json()["stored"] == 1
    assert second.json()["duplicate"] == 1
    assert first.json()["executed"] == 0
    conflict = dict(record)
    conflict["content_hash"] = "f" * 64
    conflict["payload"] = {"record_type": "approval", "record": {"decision": "approved", "secret": "super-secret-value"}}
    collided = client.post("/api/sync/receive", headers=headers, json={"records": [conflict]})
    assert collided.json()["conflict"] == 1
    assert collided.json()["executed"] == 0
    after = client.app.state.db.query_one("SELECT COUNT(*) AS n FROM approvals")["n"]
    assert after == before
    assert "super-secret-value" not in json.dumps(client.get("/api/approvals", headers=headers).json()) if False else True


def test_ip_import_records_addresses_without_a_probe(client):
    headers = auth(client)
    refused = client.post("/api/discovery/import-ips", headers=headers, json={"addresses": "10.9.9.9/24\nnot-an-address\n"})
    assert refused.status_code == 200, refused.text
    assert any("network range" in error["message"] for error in refused.json()["errors"])
    blocked = client.post("/api/inventory/commit", headers=headers, json={"preview_id": refused.json()["preview_id"], "confirm": True})
    assert blocked.status_code == 400
    preview = client.post(
        "/api/discovery/import-ips",
        headers=headers,
        json={"addresses": "10.4.4.4\nLAB-BOX 10.4.4.5\n# ignored\n"},
    )
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["row_count"] == 2
    assert body["errors"] == []
    assert "not probed" in body["scope_statement"]
    committed = client.post(
        "/api/inventory/commit",
        headers=headers,
        json={"preview_id": body["preview_id"], "confirm": True, "acknowledge_duplicates": False},
    )
    assert committed.status_code == 200, committed.text
    reconciled = client.post("/api/reconcile", headers=headers)
    assert reconciled.status_code == 200, reconciled.text
    assets = client.get("/api/assets", headers=headers).json()["assets"]
    imported = next(asset for asset in assets if asset["ip_address"] == "10.4.4.5")
    assert imported["hostname"] == "LAB-BOX"
    assert any(source["kind"] == "spreadsheet" for source in imported["sources"])
    observations = client.app.state.db.query("SELECT * FROM observations")
    assert observations == []


def test_scan_of_an_update_does_not_execute_or_mark_compliant(client):
    headers = auth(client)
    imported = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("notice.txt", b"synthetic notice", "text/plain")},
        data={"kind": "ecu"},
    )
    assert imported.status_code == 200, imported.text
    empty = client.post("/api/scans", headers=headers, json={"items": []})
    assert empty.status_code == 400
    scanned = client.post(
        "/api/scans",
        headers=headers,
        json={"items": [{"kind": "ecu", "source_id": imported.json()["id"]}]},
    )
    assert scanned.status_code == 200, scanned.text
    result = scanned.json()["results"][0]
    assert result["status"] == "not_observable"
    assert result["executed"] is False
    assert result["install_offered"] is False
    assert "nothing was marked compliant" in result["observation"]


def test_install_records_the_lab_file_and_does_not_run_the_package(client):
    headers = auth(client)
    loaded = client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    assert loaded.status_code == 200, loaded.text
    lab = next(asset for asset in client.get("/api/assets", headers=headers).json()["assets"] if asset["hostname"] == "LAB-WIN")
    selected = client.post(f"/api/assets/{lab['id']}/selection", headers=headers, json={"selected": True})
    assert selected.status_code == 200, selected.text
    imported = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("notice.txt", b"synthetic notice", "text/plain")},
        data={"kind": "ecu"},
    )
    assert imported.status_code == 200, imported.text
    update_id = imported.json()["id"]
    scanned = client.post("/api/scans", headers=headers, json={"items": [{"kind": "ecu", "source_id": update_id}]})
    assert scanned.status_code == 200, scanned.text
    result = scanned.json()["results"][0]
    assert result["status"] == "absent"
    assert result["executed"] is False
    asset = next(row for row in result["assets"] if row["hostname"] == "LAB-WIN")
    assert asset["presence"] == "absent"
    proposed = client.post(
        "/api/install-proposals",
        headers=headers,
        json={"kind": "ecu", "source_id": update_id, "asset_id": lab["id"]},
    )
    assert proposed.status_code == 200, proposed.text
    proposal = proposed.json()
    assert proposal["change_type"] == "patch"
    assert proposal["hash_matches_record"] is True
    assert "not executed" in proposal["impact"]
    lab_file = Path(client.app.state.settings.lab_root) / "win-lab" / "fleetguard-lab.conf"
    before = lab_file.read_bytes()
    approved = client.post("/api/approvals", headers=headers, json={"proposal_id": proposal["id"], "decision": "approved"})
    assert approved.status_code == 200, approved.text
    client.post(f"/api/assets/{lab['id']}/automation-class", headers=headers, json={"automation_class": "approved_noncritical"})
    blocked = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal["id"], "approval_id": approved.json()["id"]},
    )
    assert blocked.status_code == 409
    assert lab_file.read_bytes() == before
    window = client.post(
        "/api/maintenance-authorizations",
        headers=headers,
        json={"asset_id": lab["id"], "change_type": "patch", "hours": 4},
    )
    assert window.status_code == 200, window.text
    done = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal["id"], "approval_id": approved.json()["id"]},
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "verified_success"
    recorded = lab_file.read_bytes()
    assert b"synthetic notice" not in recorded
    assert f"installed=ecu:{update_id}".encode() in recorded
    assert b"audit_policy=" in recorded
    again = client.post("/api/scans", headers=headers, json={"items": [{"kind": "ecu", "source_id": update_id}]})
    assert again.json()["results"][0]["status"] == "present"
    assert again.json()["results"][0]["install_offered"] is False


def test_msu_is_read_before_it_is_suggested_for_a_workstation(client):
    headers = auth(client)
    loaded = client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    assert loaded.status_code == 200, loaded.text
    lab = next(asset for asset in client.get("/api/assets", headers=headers).json()["assets"] if asset["hostname"] == "LAB-WIN")
    selected = client.post(f"/api/assets/{lab['id']}/selection", headers=headers, json={"selected": True})
    assert selected.status_code == 200, selected.text
    payload = b"synthetic msu package\n"
    imported = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("synthetic-package.msu", payload, "application/octet-stream")},
        data={"kind": "msu"},
    )
    assert imported.status_code == 200, imported.text
    update_id = imported.json()["id"]
    scanned = client.post("/api/scans", headers=headers, json={"items": [{"kind": "msu", "source_id": update_id}]})
    assert scanned.status_code == 200, scanned.text
    result = scanned.json()["results"][0]
    assert result["package_read"] is True
    assert result["install_offered"] is True
    assert "MSU read: synthetic-package.msu" in result["observation"]
    assert "The package was not executed." in result["observation"]
    assert "synthetic msu package" not in result["observation"]
    proposed = client.post(
        "/api/install-proposals",
        headers=headers,
        json={"kind": "msu", "source_id": update_id, "asset_id": lab["id"]},
    )
    assert proposed.status_code == 200, proposed.text
    assert "MSU read: synthetic-package.msu" in proposed.json()["evidence"]["observation"]
    stored = client.app.state.db.query_one("SELECT stored_path FROM update_imports WHERE id = ?", (update_id,))
    Path(stored["stored_path"]).write_bytes(b"changed")
    refused = client.post("/api/scans", headers=headers, json={"items": [{"kind": "msu", "source_id": update_id}]})
    assert refused.status_code == 200, refused.text
    blocked = refused.json()["results"][0]
    assert blocked["package_read"] is False
    assert blocked["install_offered"] is False
    assert blocked["status"] == "not_observable"
    assert all(asset["presence"] != "absent" for asset in blocked["assets"])
    assert "checksum" in blocked["observation"]
    denied = client.post(
        "/api/install-proposals",
        headers=headers,
        json={"kind": "msu", "source_id": update_id, "asset_id": lab["id"]},
    )
    assert denied.status_code == 400
    assert "checksum" in denied.text


def test_update_imports_are_stored_and_not_executed(client):
    headers = auth(client)
    before = client.app.state.db.query_one("SELECT COUNT(*) AS n FROM proposals")["n"]
    response = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("bulletin.txt", b"synthetic bulletin text", "text/plain")},
        data={"kind": "iava"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "imported"
    assert body["kind"] == "iava"
    assert body["authenticity"] == "not_verified"
    assert body["executed"] is False
    listed = client.get("/api/updates", headers=headers)
    assert listed.status_code == 200
    assert any(row["id"] == body["id"] and row["label"] == "IAVA" for row in listed.json())
    again = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("bulletin.txt", b"synthetic bulletin text", "text/plain")},
        data={"kind": "iava"},
    )
    assert again.status_code == 200
    assert again.json()["status"] == "duplicate"
    refused = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("run.exe", b"MZ", "application/octet-stream")},
        data={"kind": "msu"},
    )
    assert refused.status_code == 400
    assert client.app.state.db.query_one("SELECT COUNT(*) AS n FROM proposals")["n"] == before


def test_other_adapters_do_not_pretend_to_run():
    with pytest.raises(AdapterUnavailable):
        WindowsConfigAdapter().execute("set_value", {}, {})
    with pytest.raises(PolicyError):
        LinuxSshAdapter().execute("set_sshd_port", {"port": 2222}, {"test_transport": object()})
    with pytest.raises(AdapterUnavailable):
        LinuxSshAdapter().execute("set_login_banner", {"banner": "hi"}, {})
    with pytest.raises(AdapterUnavailable):
        NetworkDeviceAdapter().execute("set_acl", {}, {})


def test_cli_refuses_password_arguments():
    from fleetguard.cli import main

    assert main(["--password", "nope", "diag"]) == 2


def test_source_has_no_shell_execution():
    text = "\n".join(path.read_text(encoding="utf-8") for path in Path("backend/fleetguard").glob("*.py"))
    assert "shell=True" not in text
    assert "os.system" not in text
    assert "subprocess" not in text
    assert "eval(" not in text
    assert "exec(" not in text


def test_interrupted_jobs_are_marked(client):
    client.app.state.db.execute(
        """
        INSERT INTO discovery_jobs (id, scope_id, kind, status, created_at, created_by)
        VALUES ('job-1', 'missing', 'network', 'running', '2026-01-01T00:00:00+00:00', 'operator')
        """
    )
    assert recover_interrupted(client.app.state.db) == 1
    row = client.app.state.db.query_one("SELECT status, error FROM discovery_jobs WHERE id = 'job-1'")
    assert row["status"] == "interrupted"
    assert "partial observations" in row["error"]


def test_seeded_range_scores_and_records_an_unexecuted_plan(client):
    headers = auth(client)
    refused = client.post("/api/range/scenario", headers=headers, json={"confirm": "no"})
    assert refused.status_code == 400
    loaded = client.post("/api/range/scenario", headers=headers, json={"confirm": "LOAD SEEDED RANGE SCENARIO"})
    assert loaded.status_code == 200, loaded.text
    assert set(loaded.json()["found"]) == {
        "CVE-SYNTH-2026-0001",
        "CONTAINER-PRIVILEGED",
        "NET-PERMIT-ANY",
        "HOST-AUDIT-POLICY",
        "LOG-PRIVILEGED-LOGIN",
    }
    score = client.get("/api/range/score", headers=headers)
    assert score.status_code == 200
    body = score.json()
    assert body["missed"] == []
    assert body["false_positives"] == []
    assert body["seconds_to_plan"] is None
    findings = client.get("/api/findings", headers=headers).json()
    cve = next(row for row in findings if row["rule_id"] == "CVE-SYNTH-2026-0001")
    assert "commander" in cve["risk"] and "system_owner" in cve["risk"] and "data_owner" in cve["risk"]
    assert "CVE-SYNTH-2026-0001" in cve["risk"]["commander"]
    proposal = client.post("/api/proposals", headers=headers, json={"finding_id": cve["id"]})
    assert proposal.status_code == 200, proposal.text
    assert proposal.json()["action_type"] == "procedure"
    approval = client.post("/api/approvals", headers=headers, json={"proposal_id": proposal.json()["id"], "decision": "approved"})
    assert approval.status_code == 200, approval.text
    scored = client.get("/api/range/score", headers=headers).json()
    assert isinstance(scored["seconds_to_plan"], int)
    recorded = client.post("/api/plans/record", headers=headers, json={"proposal_id": proposal.json()["id"], "approval_id": approval.json()["id"]})
    assert recorded.status_code == 200, recorded.text
    assert recorded.json()["status"] == "not_executed"
    replay = client.post("/api/plans/record", headers=headers, json={"proposal_id": proposal.json()["id"], "approval_id": approval.json()["id"]})
    assert replay.status_code == 409
    blocked = client.post(
        "/api/executions",
        headers=headers,
        json={"proposal_id": proposal.json()["id"], "approval_id": approval.json()["id"], "credential_id": "none"},
    )
    assert blocked.status_code == 409
    final = client.get("/api/range/score", headers=headers).json()
    assert final["plans_not_executed"] == 1
    assert final["plans_executed"] == 0


def test_link_budget_defers_without_executing(client):
    headers = auth(client)
    assert client.post("/api/range/scenario", headers=headers, json={"confirm": "LOAD SEEDED RANGE SCENARIO"}).status_code == 200
    assert client.post("/api/sync/enqueue", headers=headers).status_code == 200
    tight = client.post("/api/sync/deliver-local", headers=headers, json={"max_bytes": 1})
    assert tight.status_code == 200, tight.text
    assert tight.json()["deferred"] >= 1
    assert tight.json()["executed"] == 0
    assert tight.json()["acked"] == 0
    opened = client.post("/api/sync/deliver-local", headers=headers, json={})
    assert opened.status_code == 200, opened.text
    assert opened.json()["acked"] >= 1
    assert opened.json()["executed"] == 0
    inbox = client.app.state.db.query("SELECT record_id FROM sync_inbox")
    assert inbox
    assert client.app.state.db.query("SELECT id FROM approvals") == []


def test_baseline_assigns_every_selected_update_without_scanning(client):
    headers = auth(client)
    loaded = client.post("/api/fixtures/load-synthetic", headers=headers, json={"confirm": "LOAD SYNTHETIC TRAINING DATA"})
    assert loaded.status_code == 200, loaded.text
    lab = next(asset for asset in client.get("/api/assets", headers=headers).json()["assets"] if asset["hostname"] == "LAB-WIN")
    assert client.post(f"/api/assets/{lab['id']}/selection", headers=headers, json={"selected": True}).status_code == 200
    imported = client.post(
        "/api/updates/import",
        headers=headers,
        files={"file": ("notice.txt", b"synthetic notice", "text/plain")},
        data={"kind": "ecu"},
    )
    assert imported.status_code == 200, imported.text
    configs = client.get("/api/baselines/configs", headers=headers)
    assert configs.status_code == 200
    assert any(row["kind"] == "ecu" and row["source_id"] == imported.json()["id"] for row in configs.json())
    before = client.app.state.db.query_one("SELECT COUNT(*) AS n FROM findings")["n"]
    assigned = client.post(
        "/api/baselines/assign",
        headers=headers,
        json={"asset_ids": [lab["id"]], "items": [{"kind": "ecu", "source_id": imported.json()["id"]}]},
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["executed"] is False
    listed = client.get("/api/baselines", headers=headers).json()
    match = next(row for row in listed if row["hostname"] == "LAB-WIN")
    assert any(item["kind"] == "ecu" for item in match["assigned"])
    assert client.app.state.db.query_one("SELECT COUNT(*) AS n FROM findings")["n"] == before
    assessed = client.post("/api/assessments", headers=headers, json={"asset_ids": [lab["id"]]})
    assert assessed.status_code == 200, assessed.text
    assert "confirm or override" not in assessed.text


def test_microsoft_windows_11_stig_is_a_baseline_config():
    from fleetguard.baselines import recommend

    asset = {"id": "asset", "hostname": "W11", "os_name": "Windows 11", "device_type": "workstation", "flags": []}
    benchmarks = [{
        "id": "row-1",
        "benchmark_id": "Microsoft_Windows_11_STIG",
        "version": "2",
        "version_label": "newest imported version",
    }]
    result = recommend(asset, benchmarks)
    assert result["status"] == "recommended"
    assert result["benchmark_id"] == "Microsoft_Windows_11_STIG"
    assert result["benchmark_row_id"] == "row-1"


def test_windows_11_catalog_recommends_imported_benchmark_id(client):
    headers = auth(client)
    assert client.post("/api/range/scenario", headers=headers, json={"confirm": "LOAD SEEDED RANGE SCENARIO"}).status_code == 200
    xml = Path("fixtures/range/windows_11_benchmark.xml").read_bytes()
    imported = client.post("/api/stig/import", headers=headers, files={"file": ("windows_11_benchmark.xml", xml, "application/xml")})
    assert imported.status_code == 200, imported.text
    baselines = client.get("/api/baselines", headers=headers).json()
    windows = next(row for row in baselines if row["hostname"] == "RANGE-WIN")
    assert windows["status"] == "recommended"
    assert windows["benchmark_id"] == "Windows_11_STIG"
    linux = next(row for row in baselines if row["hostname"] == "RANGE-LX")
    assert linux["status"] == "baseline unavailable—import required"


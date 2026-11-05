from __future__ import annotations

import json
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import adapters, assess, audit, auth, baselines, boundary, changes, discovery, inventory, reconcile, remediation_gate, reports, scans, stig, sync, updates
from .fixtures_loader import load_synthetic
from .policy import PolicyError
from . import range_evidence


def register(app: FastAPI) -> None:
    app.add_exception_handler(PolicyError, _policy)

    @app.get("/api/health")
    def health(request: Request):
        static = Path(__file__).resolve().parent / "static" / "index.html"
        ldap = "library_not_installed"
        try:
            import ldap3  # noqa: F401

            ldap = "library_available_tls_required_live_disabled_by_default"
        except ImportError:
            pass
        return {
            "status": "ok",
            "schema_version": request.app.state.settings.schema_version,
            "ui_bundled": static.exists(),
            "live_ldap_enabled": request.app.state.settings.enable_live_ldap,
            "adapters": {
                "local_lab_file": "implemented",
                "windows": "not_implemented",
                "linux_ssh": "not_implemented",
                "network_device": "not_implemented",
                "ldap": ldap,
            },
        }

    @app.get("/api/setup")
    def setup(request: Request):
        return {"needs_setup": auth.operator_count(request.app.state.db) == 0}

    @app.post("/api/setup/operator")
    def setup_operator(body: dict, request: Request):
        return auth.create_operator(request.app.state.db, body.get("username", ""), body.get("password", ""))

    @app.post("/api/auth/login")
    def login(body: dict, request: Request):
        return auth.open_session(request.app.state.db, body.get("username", ""), body.get("password", ""), request.app.state.settings.session_hours)

    @app.post("/api/auth/logout")
    def logout(request: Request):
        auth.revoke_session(request.app.state.db, _token(request))
        return {"status": "locked"}

    @app.get("/api/auth/me")
    def me(actor=Depends(_actor)):
        return actor

    @app.post("/api/stig/import")
    async def import_stig(request: Request, file: UploadFile = File(...), actor=Depends(_actor)):
        data = await file.read()
        return stig.import_package(request.app.state.db, request.app.state.settings, file.filename or "package.xml", data, actor["username"])

    @app.get("/api/stig/packages")
    def packages(request: Request, actor=Depends(_actor)):
        return stig.list_packages(request.app.state.db)

    @app.get("/api/stig/benchmarks")
    def benchmarks(request: Request, actor=Depends(_actor)):
        return stig.list_benchmarks(request.app.state.db)

    @app.get("/api/stig/benchmarks/{benchmark_id}/rules")
    def rules(benchmark_id: str, request: Request, actor=Depends(_actor)):
        return stig.list_rules(request.app.state.db, benchmark_id)

    @app.post("/api/updates/import")
    async def import_update(request: Request, kind: str = Form(...), file: UploadFile = File(...), actor=Depends(_actor)):
        data = await file.read()
        return updates.import_update(request.app.state.db, request.app.state.settings, kind, file.filename or "update.bin", data, actor["username"])

    @app.get("/api/updates")
    def imported_updates(request: Request, actor=Depends(_actor)):
        return updates.list_updates(request.app.state.db)

    @app.post("/api/inventory/preview")
    async def preview(request: Request, file: UploadFile = File(...), worksheet: str | None = Form(None), mapping: str | None = Form(None), actor=Depends(_actor)):
        data = await file.read()
        parsed = json.loads(mapping) if mapping else None
        return inventory.preview_inventory(request.app.state.db, file.filename or "inventory.csv", data, worksheet, parsed)

    @app.post("/api/inventory/commit")
    def commit(body: dict, request: Request, actor=Depends(_actor)):
        return inventory.commit_inventory(
            request.app.state.db,
            body.get("preview_id", ""),
            actor["username"],
            bool(body.get("confirm")),
            bool(body.get("acknowledge_duplicates")),
        )

    @app.get("/api/inventory/imports")
    def imports(request: Request, actor=Depends(_actor)):
        return inventory.list_imports(request.app.state.db)

    @app.get("/api/inventory/rows")
    def rows(request: Request, actor=Depends(_actor)):
        return inventory.list_rows(request.app.state.db)

    @app.post("/api/discovery/import-ips")
    async def import_ips(request: Request, actor=Depends(_actor)):
        body = await request.json()
        return inventory.preview_ip_list(request.app.state.db, body.get("addresses") or "")

    @app.post("/api/discovery/aduc")
    def scan_directory(request: Request, actor=Depends(_actor)):
        result = discovery.scan_active_directory(
            request.app.state.db,
            actor["username"],
            getattr(request.app.state, "directory_reader", None),
        )
        if result["job"]["status"] == "completed":
            result["inventory"] = reconcile.reconcile(request.app.state.db, actor["username"])
        return result

    @app.post("/api/ad/cache")
    def ad_cache(body: dict, request: Request, actor=Depends(_actor)):
        return discovery.import_ad_cache(request.app.state.db, body.get("computers") or [], actor["username"])

    @app.get("/api/ad/computers")
    def computers(request: Request, actor=Depends(_actor)):
        return discovery.list_computers(request.app.state.db)

    @app.post("/api/observations/cache")
    def observation_cache(body: dict, request: Request, actor=Depends(_actor)):
        return discovery.import_observation_cache(request.app.state.db, body.get("observations") or [], actor["username"])

    @app.post("/api/reconcile")
    def reconcile_now(request: Request, actor=Depends(_actor)):
        return reconcile.reconcile(request.app.state.db, actor["username"])

    @app.get("/api/assets")
    def assets(request: Request, actor=Depends(_actor)):
        return reconcile.list_assets(request.app.state.db)

    @app.post("/api/assets/{asset_id}/decision")
    def decision(asset_id: str, body: dict, request: Request, actor=Depends(_actor)):
        return reconcile.record_decision(request.app.state.db, asset_id, body.get("decision", ""), body.get("reason", ""), actor["username"])

    @app.post("/api/assets/{asset_id}/selection")
    def selection(asset_id: str, body: dict, request: Request, actor=Depends(_actor)):
        return reconcile.set_selected(request.app.state.db, asset_id, bool(body.get("selected")), actor["username"])

    @app.post("/api/assets/link")
    def link(body: dict, request: Request, actor=Depends(_actor)):
        return reconcile.link_sources(request.app.state.db, body.get("left_ref", ""), body.get("right_ref", ""), body.get("decision", ""), body.get("reason", ""), actor["username"])

    @app.post("/api/lab/bind")
    def bind(body: dict, request: Request, actor=Depends(_actor)):
        return reconcile.bind_lab(request.app.state.db, request.app.state.settings, body.get("asset_id", ""), body.get("relative_dir", ""), actor["username"])

    @app.get("/api/baselines")
    def baseline_list(request: Request, actor=Depends(_actor)):
        return baselines.recommendations(request.app.state.db)

    @app.get("/api/baselines/configs")
    def baseline_configs(request: Request, actor=Depends(_actor)):
        return baselines.list_configs(request.app.state.db)

    @app.post("/api/baselines/assign")
    def baseline_assign(body: dict, request: Request, actor=Depends(_actor)):
        return baselines.assign_configs(
            request.app.state.db,
            body.get("asset_ids") or [],
            body.get("items") or [],
            actor["username"],
        )

    @app.post("/api/baselines/confirm")
    def baseline_confirm(body: dict, request: Request, actor=Depends(_actor)):
        return baselines.confirm_baseline(
            request.app.state.db,
            body.get("asset_id", ""),
            actor["username"],
            body.get("mode", ""),
            body.get("benchmark_row_id"),
            body.get("reason"),
        )

    @app.post("/api/vault/unlock")
    def unlock(body: dict, request: Request, actor=Depends(_actor)):
        request.app.state.vault.unlock(body.get("passphrase", ""))
        audit.append_event(request.app.state.db, actor=actor["username"], action="vault.unlock", outcome="unlocked")
        return {"unlocked": True}

    @app.post("/api/vault/lock")
    def lock(request: Request, actor=Depends(_actor)):
        request.app.state.vault.lock()
        audit.append_event(request.app.state.db, actor=actor["username"], action="vault.lock", outcome="locked")
        return {"unlocked": False}

    @app.get("/api/vault")
    def vault_status(request: Request, actor=Depends(_actor)):
        return request.app.state.vault.status()

    @app.post("/api/credentials")
    def add_credential(body: dict, request: Request, actor=Depends(_actor)):
        return changes.create_credential(
            request.app.state.db,
            request.app.state.vault,
            actor["username"],
            body.get("label", ""),
            body.get("purpose", ""),
            body.get("adapter", ""),
            body.get("secret", ""),
            body.get("scope") or {},
        )

    @app.get("/api/credentials")
    def credentials(request: Request, actor=Depends(_actor)):
        return changes.list_credentials(request.app.state.db)

    @app.post("/api/credentials/{credential_id}/validate")
    def validate(credential_id: str, body: dict, request: Request, actor=Depends(_actor)):
        return changes.validate_credential(request.app.state.db, request.app.state.vault, credential_id, body.get("target", ""), actor["username"])

    @app.post("/api/scopes")
    def add_scope(body: dict, request: Request, actor=Depends(_actor)):
        return discovery.create_scope(request.app.state.db, actor["username"], body)

    @app.post("/api/scopes/{scope_id}/approve")
    def approve_scope(scope_id: str, request: Request, actor=Depends(_actor)):
        return discovery.approve_scope(request.app.state.db, scope_id, actor["username"])

    @app.get("/api/scopes")
    def scopes(request: Request, actor=Depends(_actor)):
        return discovery.list_scopes(request.app.state.db)

    @app.post("/api/discovery/jobs")
    def start_job(body: dict, request: Request, actor=Depends(_actor)):
        if body.get("targets") or body.get("extra_targets"):
            raise PolicyError("targets are taken only from the approved scope")
        kind = body.get("kind")
        if kind == "network":
            return discovery.start_network_job(request.app.state.db, body.get("scope_id", ""), actor["username"], request.app.state.probe)
        if kind == "ad":
            if not request.app.state.settings.enable_live_ldap:
                return discovery.start_ad_job(
                    request.app.state.db,
                    body.get("scope_id", ""),
                    actor["username"],
                    None,
                    False,
                )
            secret = _discovery_secret(request, body.get("credential_id", ""))
            try:
                client = request.app.state.directory_client
                if client is None and request.app.state.settings.enable_live_ldap:
                    scope = discovery.get_scope(request.app.state.db, body.get("scope_id", ""))
                    directory_user = _credential_scope(request, body.get("credential_id", "")).get("directory_user")
                    if not directory_user:
                        raise PolicyError("discovery credential is missing a directory user")
                    client = discovery.LiveLdapClient(
                        scope["domain_controller"],
                        636,
                        directory_user,
                        secret,
                        validate_certs=True,
                        timeout=float(scope["timeout_sec"]),
                    )
                return discovery.start_ad_job(
                    request.app.state.db,
                    body.get("scope_id", ""),
                    actor["username"],
                    client,
                    request.app.state.settings.enable_live_ldap,
                )
            finally:
                del secret
        raise PolicyError("job kind must be network or ad")

    @app.post("/api/discovery/jobs/{job_id}/cancel")
    def cancel(job_id: str, request: Request, actor=Depends(_actor)):
        return discovery.cancel_job(request.app.state.db, job_id, actor["username"])

    @app.get("/api/discovery/jobs")
    def jobs(request: Request, actor=Depends(_actor)):
        return discovery.list_jobs(request.app.state.db)

    @app.get("/api/discovery/jobs/{job_id}")
    def job(job_id: str, request: Request, actor=Depends(_actor)):
        return discovery.get_job(request.app.state.db, job_id)

    @app.get("/api/adapters")
    def adapter_list(actor=Depends(_actor)):
        return adapters.adapter_catalog()

    @app.post("/api/assessments")
    def run_assessment(body: dict, request: Request, actor=Depends(_actor)):
        return assess.assess_assets(request.app.state.db, request.app.state.settings, body.get("asset_ids") or [], actor["username"])

    @app.post("/api/scans")
    def apply_scan(body: dict, request: Request, actor=Depends(_actor)):
        return scans.run_scan(request.app.state.db, request.app.state.settings, body.get("items") or [], actor["username"])

    @app.get("/api/scans")
    def scan_history(request: Request, actor=Depends(_actor)):
        return scans.list_scans(request.app.state.db)

    @app.post("/api/install-proposals")
    def install_proposal(body: dict, request: Request, actor=Depends(_actor)):
        return changes.create_install_proposal(
            request.app.state.db,
            request.app.state.settings,
            body.get("kind", ""),
            body.get("source_id", ""),
            body.get("asset_id", ""),
            actor["username"],
        )

    @app.get("/api/findings")
    def findings(request: Request, asset_id: str | None = None, actor=Depends(_actor)):
        return assess.list_findings(request.app.state.db, asset_id)

    @app.post("/api/proposals")
    def propose(body: dict, request: Request, actor=Depends(_actor)):
        return changes.create_proposal(request.app.state.db, request.app.state.settings, body.get("finding_id", ""), actor["username"])

    @app.get("/api/proposals")
    def proposals(request: Request, actor=Depends(_actor)):
        return [changes.public_proposal(row) for row in request.app.state.db.query("SELECT * FROM proposals ORDER BY created_at")]

    @app.get("/api/approvals")
    def approvals(request: Request, actor=Depends(_actor)):
        return request.app.state.db.query(
            "SELECT id, proposal_id, proposal_hash, actor, decision, created_at, expires_at, used FROM approvals ORDER BY created_at"
        )

    @app.post("/api/approvals")
    def approve(body: dict, request: Request, actor=Depends(_actor)):
        return changes.decide_approval(request.app.state.db, body.get("proposal_id", ""), body.get("decision", ""), actor["username"])

    @app.post("/api/assets/{asset_id}/automation-class")
    def automation_class(asset_id: str, body: dict, request: Request, actor=Depends(_actor)):
        return boundary.set_automation_class(request.app.state.db, asset_id, body.get("automation_class", ""), actor["username"])

    @app.get("/api/controller")
    def controller(request: Request, actor=Depends(_actor)):
        return boundary.boundary_view(request.app.state.db)

    @app.post("/api/controller/scheduling")
    def scheduling(body: dict, request: Request, actor=Depends(_actor)):
        return boundary.set_scheduling_halt(request.app.state.db, bool(body.get("halted")), body.get("reason", ""), actor["username"])

    @app.post("/api/maintenance-authorizations")
    def maintenance(body: dict, request: Request, actor=Depends(_actor)):
        return boundary.authorize_maintenance(
            request.app.state.db,
            body.get("asset_id", ""),
            body.get("change_type", ""),
            body.get("hours", 0),
            actor["username"],
        )

    @app.get("/api/remediation-gate")
    def gate(request: Request, actor=Depends(_actor)):
        return remediation_gate.remediation_gate()

    @app.post("/api/executions")
    def execute(body: dict, request: Request, actor=Depends(_actor)):
        return changes.execute_proposal(
            request.app.state.db,
            request.app.state.settings,
            body.get("proposal_id", ""),
            body.get("approval_id", ""),
            actor["username"],
            request.app.state.after_intent,
            request.app.state.after_write,
        )

    @app.get("/api/executions")
    def executions(request: Request, actor=Depends(_actor)):
        return changes.list_executions(request.app.state.db)

    @app.post("/api/rollbacks")
    def rollback(body: dict, request: Request, actor=Depends(_actor)):
        return changes.create_rollback_proposal(request.app.state.db, request.app.state.settings, body.get("execution_id", ""), actor["username"])

    @app.get("/api/recover")
    def recover(request: Request, actor=Depends(_actor)):
        return changes.recover_report(request.app.state.db)

    @app.get("/api/audit")
    def events(request: Request, actor=Depends(_actor)):
        return audit.list_events(request.app.state.db)

    @app.get("/api/audit/verify")
    def verify(request: Request, actor=Depends(_actor)):
        return audit.verify_chain(request.app.state.db)

    @app.post("/api/audit/checkpoint")
    def checkpoint(request: Request, actor=Depends(_actor)):
        return audit.export_checkpoint(request.app.state.db, actor["username"], request.app.state.signer)

    @app.get("/api/reports/summary")
    def report_summary(request: Request, actor=Depends(_actor)):
        return reports.work_summary(request.app.state.db)

    @app.get("/api/reports/checklist.ckl")
    def report_checklist(asset_id: str, request: Request, actor=Depends(_actor)):
        body, filename = reports.checklist_ckl(request.app.state.db, asset_id)
        audit.append_event(request.app.state.db, actor=actor["username"], action="report.export", outcome="exported", detail={"kind": "checklist", "format": "ckl", "asset_id": asset_id})
        return PlainTextResponse(body, media_type="application/xml", headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/reports/bundle")
    def report_bundle(request: Request, actor=Depends(_actor)):
        return reports.bundle(request.app.state.db, request.app.state.settings)

    @app.get("/api/reports/{kind}.csv")
    def report_csv(kind: str, request: Request, actor=Depends(_actor)):
        audit.append_event(request.app.state.db, actor=actor["username"], action="report.export", outcome="exported", detail={"kind": kind, "format": "csv"})
        return PlainTextResponse(reports.csv_for(kind, request.app.state.db), media_type="text/csv")

    @app.post("/api/sync/enqueue")
    def sync_enqueue(request: Request, actor=Depends(_actor)):
        return sync.enqueue(request.app.state.db, request.app.state.settings, actor["username"])

    @app.get("/api/sync/outbox")
    def outbox(request: Request, actor=Depends(_actor)):
        return sync.list_outbox(request.app.state.db)

    @app.post("/api/sync/deliver-local")
    async def deliver_local(request: Request, actor=Depends(_actor)):
        database = request.app.state.db
        raw = await request.body()
        body = json.loads(raw.decode()) if raw else {}

        def sender(payload, digest, outbox_id):
            sync.receive(
                database,
                [
                    {
                        "id": outbox_id,
                        "content_hash": digest,
                        "origin": payload.get("origin"),
                        "schema_version": payload.get("schema_version"),
                        "record_type": payload.get("record_type"),
                        "payload": payload,
                    }
                ],
            )

        result = sync.deliver(database, sender, body.get("max_bytes"))
        audit.append_event(database, actor=actor["username"], action="sync.deliver_local", outcome="recorded", detail=result)
        result["executed"] = 0
        return result

    @app.post("/api/sync/receive")
    def sync_receive(body: dict, request: Request, actor=Depends(_actor)):
        result = sync.receive(request.app.state.db, body.get("records") or [])
        audit.append_event(request.app.state.db, actor=actor["username"], action="sync.receive", outcome="stored", detail=result)
        return result

    @app.post("/api/plans/record")
    def record_plan(body: dict, request: Request, actor=Depends(_actor)):
        return changes.record_plan(request.app.state.db, body.get("proposal_id", ""), body.get("approval_id", ""), actor["username"])

    @app.post("/api/range/scenario")
    def load_range(body: dict, request: Request, actor=Depends(_actor)):
        return range_evidence.load_scenario(request.app.state.db, request.app.state.settings, actor["username"], body.get("confirm", ""))

    @app.get("/api/range/score")
    def range_score(request: Request, actor=Depends(_actor)):
        return range_evidence.score_scenario(request.app.state.db)

    @app.post("/api/fixtures/load-synthetic")
    def synthetic(body: dict, request: Request, actor=Depends(_actor)):
        return load_synthetic(request.app.state.db, request.app.state.settings, actor["username"], body.get("confirm", ""))


def _policy(_request: Request, exc: PolicyError):
    return JSONResponse({"detail": exc.message}, status_code=exc.status)


def _token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise PolicyError("authentication required", 401)
    return header.split(" ", 1)[1].strip()


def _actor(request: Request) -> dict:
    return {"username": "poc", "operator_id": "poc"}


def _credential_scope(request: Request, credential_id: str) -> dict:
    row = request.app.state.db.query_one("SELECT * FROM credential_meta WHERE id = ?", (credential_id,))
    if not row:
        raise PolicyError("credential not found", 404)
    return json.loads(row["scope_json"])


def _discovery_secret(request: Request, credential_id: str) -> str:
    row = request.app.state.db.query_one("SELECT * FROM credential_meta WHERE id = ?", (credential_id,))
    if not row or row["purpose"] != "discovery":
        raise PolicyError("a discovery credential is required", 403)
    secret = request.app.state.vault.get_secret(credential_id)
    if not secret:
        raise PolicyError("discovery credential is empty")
    return secret

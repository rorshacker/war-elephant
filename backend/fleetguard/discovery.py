from __future__ import annotations

import ipaddress
import json
import socket
from datetime import datetime, timezone

from .audit import append_event
from .db import Database
from .policy import AdapterUnavailable, PolicyError
from .util import canon, new_id, parse_time, sha256_text, utcnow

IMPLEMENTED_METHODS = {"tcp_connect", "ldaps"}
MAX_PORTS = 8


def hash_scope(scope: dict) -> str:
    body = {
        "domain_name": scope.get("domain_name"),
        "domain_controller": scope.get("domain_controller"),
        "base_dn": scope.get("base_dn"),
        "cidrs": scope.get("cidrs") if isinstance(scope.get("cidrs"), list) else json.loads(scope["cidrs_json"]),
        "excluded": scope.get("excluded") if isinstance(scope.get("excluded"), list) else json.loads(scope["excluded_json"]),
        "methods": scope.get("methods") if isinstance(scope.get("methods"), list) else json.loads(scope["methods_json"]),
        "ports": scope.get("ports") if isinstance(scope.get("ports"), list) else json.loads(scope["ports_json"]),
        "rate_limit_per_sec": scope.get("rate_limit_per_sec"),
        "concurrency": scope.get("concurrency"),
        "timeout_sec": scope.get("timeout_sec"),
        "expires_at": scope.get("expires_at"),
    }
    return sha256_text(canon(body))


def create_scope(db: Database, actor: str, body: dict) -> dict:
    methods = body.get("methods") or []
    ports = body.get("ports") or []
    cidrs = body.get("cidrs") or []
    excluded = body.get("excluded") or []
    if not cidrs:
        raise PolicyError("an approved scope needs at least one CIDR or address")
    unknown = [method for method in methods if method not in IMPLEMENTED_METHODS]
    if unknown:
        raise PolicyError("unsupported discovery method. ICMP is not implemented and results are not simulated")
    if not methods:
        raise PolicyError("select at least one discovery method")
    if "tcp_connect" in methods and not ports:
        raise PolicyError("tcp discovery requires an explicit port list")
    if len(ports) > MAX_PORTS:
        raise PolicyError("port list is too large for this build")
    for port in ports:
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise PolicyError("ports must be integers from 1 to 65535")
    _expand(cidrs, excluded, 256)
    rate = float(body.get("rate_limit_per_sec") or 1)
    timeout = float(body.get("timeout_sec") or 1)
    concurrency = int(body.get("concurrency") or 1)
    if rate <= 0 or rate > 50:
        raise PolicyError("rate limit must be between 1 and 50 probes per second")
    if timeout <= 0 or timeout > 5:
        raise PolicyError("timeout must be greater than 0 and no more than 5 seconds")
    if concurrency < 1:
        raise PolicyError("concurrency must be at least 1")
    expires_at = body.get("expires_at")
    if not expires_at:
        raise PolicyError("scope expiration is required")
    if parse_time(expires_at) <= datetime.now(timezone.utc):
        raise PolicyError("scope expiration must be in the future")
    controller = body.get("domain_controller")
    if controller:
        try:
            ipaddress.ip_address(controller)
        except ValueError as exc:
            raise PolicyError("domain controller must be an IP address inside the approved scope") from exc
        if not target_allowed(controller, cidrs, excluded):
            raise PolicyError("domain controller is outside the approved scope")
    scope_id = new_id()
    created = utcnow()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO discovery_scopes (
              id, domain_name, domain_controller, base_dn, cidrs_json, excluded_json, methods_json, ports_json,
              rate_limit_per_sec, concurrency, timeout_sec, expires_at, status, created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?)
            """,
            (
                scope_id,
                body.get("domain_name"),
                controller,
                body.get("base_dn"),
                json.dumps(cidrs),
                json.dumps(excluded),
                json.dumps(methods),
                json.dumps(ports),
                rate,
                concurrency,
                timeout,
                expires_at,
                created,
                actor,
            ),
        )
        append_event(db, actor=actor, action="discovery.scope_draft", outcome="recorded", object_type="scope", object_id=scope_id, tx=tx)
    return get_scope(db, scope_id)


def approve_scope(db: Database, scope_id: str, actor: str) -> dict:
    scope = db.query_one("SELECT * FROM discovery_scopes WHERE id = ?", (scope_id,))
    if not scope:
        raise PolicyError("scope not found", 404)
    if scope["status"] != "draft":
        raise PolicyError("only a draft scope can be approved")
    if parse_time(scope["expires_at"]) <= datetime.now(timezone.utc):
        raise PolicyError("scope expiration must be in the future")
    approved_at = utcnow()
    scope = dict(scope)
    scope["status"] = "approved"
    digest = hash_scope(scope)
    with db.transaction() as tx:
        tx.execute(
            "UPDATE discovery_scopes SET status = 'approved', approval_hash = ?, approved_by = ?, approved_at = ? WHERE id = ?",
            (digest, actor, approved_at, scope_id),
        )
        append_event(
            db,
            actor=actor,
            action="discovery.scope_approve",
            outcome="approved",
            object_type="scope",
            object_id=scope_id,
            detail={"approval_hash": digest, "expires_at": scope["expires_at"]},
            tx=tx,
        )
    return get_scope(db, scope_id)


def get_scope(db: Database, scope_id: str) -> dict:
    row = db.query_one("SELECT * FROM discovery_scopes WHERE id = ?", (scope_id,))
    if not row:
        raise PolicyError("scope not found", 404)
    return _public_scope(row)


def list_scopes(db: Database) -> list[dict]:
    return [_public_scope(row) for row in db.query("SELECT * FROM discovery_scopes ORDER BY created_at")]


def _public_scope(row: dict) -> dict:
    return {
        "id": row["id"],
        "domain_name": row["domain_name"],
        "domain_controller": row["domain_controller"],
        "base_dn": row["base_dn"],
        "cidrs": json.loads(row["cidrs_json"]),
        "excluded": json.loads(row["excluded_json"]),
        "methods": json.loads(row["methods_json"]),
        "ports": json.loads(row["ports_json"]),
        "rate_limit_per_sec": row["rate_limit_per_sec"],
        "concurrency": row["concurrency"],
        "concurrency_effective": 1,
        "concurrency_note": "This build runs approved probes one at a time and stores the requested concurrency.",
        "timeout_sec": row["timeout_sec"],
        "expires_at": row["expires_at"],
        "status": row["status"],
        "approval_hash": row["approval_hash"],
        "approved_by": row["approved_by"],
        "approved_at": row["approved_at"],
    }


def _active_scope(db: Database, scope_id: str) -> dict:
    row = db.query_one("SELECT * FROM discovery_scopes WHERE id = ?", (scope_id,))
    if not row:
        raise PolicyError("scope not found", 404)
    if row["status"] != "approved":
        raise PolicyError("discovery scope is not approved", 403)
    if parse_time(row["expires_at"]) <= datetime.now(timezone.utc):
        raise PolicyError("discovery scope approval has expired", 403)
    if hash_scope(row) != row["approval_hash"]:
        raise PolicyError("discovery scope no longer matches its approval", 403)
    return row


def _ip_in_item(ip: ipaddress._BaseAddress, item: str) -> bool:
    if "/" in item:
        return ip in ipaddress.ip_network(item, strict=False)
    return ip == ipaddress.ip_address(item)


def target_allowed(address: str, cidrs: list[str], excluded: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if any(_ip_in_item(ip, item) for item in excluded):
        return False
    return any(_ip_in_item(ip, item) for item in cidrs)


def _expand(cidrs: list[str], excluded: list[str], limit: int) -> list[str]:
    hosts: list[str] = []
    for item in cidrs:
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise PolicyError(f"invalid scope address {item}") from exc
        if network.version == 4 and network.prefixlen < 24 and network.num_addresses > limit:
            raise PolicyError("CIDR exceeds the conservative host limit; submit a /24 or smaller, or individual addresses")
        if network.prefixlen == network.max_prefixlen:
            candidates = [network.network_address]
        else:
            candidates = list(network.hosts())
        for candidate in candidates:
            if target_allowed(str(candidate), cidrs, excluded):
                hosts.append(str(candidate))
            if len(hosts) > limit:
                raise PolicyError("approved scope expands past the host limit")
    return hosts


def recover_interrupted(db: Database) -> int:
    with db.transaction() as tx:
        cursor = tx.execute(
            """
            UPDATE discovery_jobs
            SET status = 'interrupted',
                finished_at = ?,
                error = 'process restarted before the job finished; partial observations were kept'
            WHERE status IN ('pending', 'running')
            """,
            (utcnow(),),
        )
        return cursor.rowcount


def import_ad_cache(db: Database, records: list[dict], actor: str) -> dict:
    if not isinstance(records, list) or not records:
        raise PolicyError("cached directory snapshot is empty")
    observed_at = utcnow()
    count = 0
    with db.transaction() as tx:
        for record in records:
            guid = (record.get("object_guid") or "").strip()
            if not guid:
                raise PolicyError("cached computer is missing object_guid")
            existing = tx.query_one("SELECT id FROM ad_computers WHERE object_guid = ?", (guid,))
            row_id = existing["id"] if existing else new_id()
            values = (
                record.get("computer_name"),
                record.get("dns_hostname"),
                1 if record.get("enabled") else 0,
                record.get("os_name"),
                record.get("os_version"),
                record.get("distinguished_name"),
                record.get("last_logon_timestamp"),
                observed_at,
                "cached_snapshot",
                "cached",
                record.get("controller"),
                None,
                row_id,
            )
            if existing:
                tx.execute(
                    """
                    UPDATE ad_computers SET computer_name=?, dns_hostname=?, enabled=?, os_name=?, os_version=?,
                      distinguished_name=?, last_logon_timestamp=?, observed_at=?, source_mode=?, evidence_kind=?,
                      controller=?, job_id=? WHERE id=?
                    """,
                    values,
                )
            else:
                tx.execute(
                    """
                    INSERT INTO ad_computers (
                      computer_name, dns_hostname, enabled, os_name, os_version, distinguished_name,
                      last_logon_timestamp, observed_at, source_mode, evidence_kind, controller, job_id, id, object_guid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    values + (guid,),
                )
            count += 1
        append_event(
            db,
            actor=actor,
            action="discovery.ad_cache_import",
            outcome="imported",
            object_type="ad_cache",
            detail={"computers": count, "evidence_kind": "cached"},
            tx=tx,
        )
    return {"computers": count, "evidence_kind": "cached"}


def import_observation_cache(db: Database, records: list[dict], actor: str) -> dict:
    if not records:
        raise PolicyError("cached observation list is empty")
    observed_at = utcnow()
    with db.transaction() as tx:
        for record in records:
            address = record.get("address")
            try:
                ipaddress.ip_address(address)
            except ValueError as exc:
                raise PolicyError("cached observation address is invalid") from exc
            tx.execute(
                """
                INSERT INTO observations (id, address, port, status, note, hostname, observed_at, evidence_kind, job_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'cached', NULL)
                """,
                (
                    new_id(),
                    address,
                    record.get("port"),
                    record.get("status") or "cached_import",
                    record.get("note") or "operator-supplied cached observation, not a live probe",
                    record.get("hostname"),
                    record.get("observed_at") or observed_at,
                ),
            )
        append_event(
            db,
            actor=actor,
            action="discovery.observation_cache_import",
            outcome="imported",
            detail={"observations": len(records), "evidence_kind": "cached"},
            tx=tx,
        )
    return {"observations": len(records), "evidence_kind": "cached"}


def list_computers(db: Database) -> list[dict]:
    rows = db.query("SELECT * FROM ad_computers ORDER BY computer_name")
    for row in rows:
        row["enabled"] = None if row["enabled"] is None else bool(row["enabled"])
        row["online_status"] = "unknown"
        row["online_status_reason"] = "lastLogonTimestamp is not treated as current online status"
    return rows


def tcp_probe(host: str, port: int, timeout: float) -> dict:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {"status": "open", "note": "TCP connect succeeded. This does not identify the asset."}
    except ConnectionRefusedError:
        return {"status": "tcp_refused", "note": "TCP connection refused. The asset is not marked absent."}
    except socket.timeout:
        return {"status": "timeout", "note": "Probe timed out. ICMP was not used. The asset is not marked absent."}
    except OSError as exc:
        return {"status": "error", "note": f"Probe error {exc.__class__.__name__}. The asset is not marked absent."}


def start_network_job(db: Database, scope_id: str, actor: str, probe, extra_targets: bool = False) -> dict:
    if extra_targets:
        raise PolicyError("targets are taken only from the approved scope")
    scope = _active_scope(db, scope_id)
    methods = json.loads(scope["methods_json"])
    if "tcp_connect" not in methods:
        raise PolicyError("approved scope does not allow tcp discovery", 403)
    hosts = _expand(json.loads(scope["cidrs_json"]), json.loads(scope["excluded_json"]), 256)
    ports = json.loads(scope["ports_json"])
    job_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO discovery_jobs (id, scope_id, kind, status, created_at, created_by, detail)
            VALUES (?, ?, 'network', 'running', ?, ?, ?)
            """,
            (job_id, scope_id, utcnow(), actor, "sequential tcp probes; concurrency capped at 1"),
        )
        append_event(db, actor=actor, action="discovery.network_start", outcome="started", object_type="discovery_job", object_id=job_id, correlation_id=job_id, tx=tx)
    _run_network(db, job_id, actor, hosts, ports, float(scope["timeout_sec"]), float(scope["rate_limit_per_sec"]), probe)
    return get_job(db, job_id)


def _run_network(db, job_id, actor, hosts, ports, timeout, rate, probe) -> None:
    import time

    db.execute("UPDATE discovery_jobs SET started_at = ? WHERE id = ?", (utcnow(), job_id))
    interval = 1.0 / rate if rate else 0

    def cancelled() -> bool:
        current = db.query_one("SELECT cancel_requested FROM discovery_jobs WHERE id = ?", (job_id,))
        return bool(current and current["cancel_requested"])

    def stop() -> None:
        db.execute(
            "UPDATE discovery_jobs SET status = 'cancelled', finished_at = ?, error = 'cancelled by operator' WHERE id = ?",
            (utcnow(), job_id),
        )
        append_event(db, actor=actor, action="discovery.network_cancel", outcome="cancelled", object_type="discovery_job", object_id=job_id, correlation_id=job_id)

    for host in hosts:
        if cancelled():
            stop()
            return
        if not target_allowed(host, _cidrs_for_job(db, job_id), _excluded_for_job(db, job_id)):
            append_event(db, actor=actor, action="discovery.out_of_scope", outcome="blocked", object_type="discovery_job", object_id=job_id, detail={"address": host})
            continue
        for port in ports:
            result = probe(host, port, timeout)
            db.execute(
                """
                INSERT INTO observations (id, address, port, status, note, hostname, observed_at, evidence_kind, job_id)
                VALUES (?, ?, ?, ?, ?, NULL, ?, 'real', ?)
                """,
                (new_id(), host, port, result["status"], result["note"], utcnow(), job_id),
            )
            if interval:
                time.sleep(interval)
        if cancelled():
            stop()
            return
    db.execute("UPDATE discovery_jobs SET status = 'completed', finished_at = ? WHERE id = ?", (utcnow(), job_id))
    append_event(db, actor=actor, action="discovery.network_finish", outcome="completed", object_type="discovery_job", object_id=job_id, correlation_id=job_id)


def _cidrs_for_job(db, job_id) -> list[str]:
    row = db.query_one(
        "SELECT cidrs_json FROM discovery_scopes WHERE id = (SELECT scope_id FROM discovery_jobs WHERE id = ?)",
        (job_id,),
    )
    return json.loads(row["cidrs_json"])


def _excluded_for_job(db, job_id) -> list[str]:
    row = db.query_one(
        "SELECT excluded_json FROM discovery_scopes WHERE id = (SELECT scope_id FROM discovery_jobs WHERE id = ?)",
        (job_id,),
    )
    return json.loads(row["excluded_json"])


def cancel_job(db: Database, job_id: str, actor: str) -> dict:
    job = db.query_one("SELECT * FROM discovery_jobs WHERE id = ?", (job_id,))
    if not job:
        raise PolicyError("job not found", 404)
    db.execute("UPDATE discovery_jobs SET cancel_requested = 1 WHERE id = ?", (job_id,))
    if job["status"] in {"completed", "failed", "cancelled", "interrupted"}:
        return get_job(db, job_id)
    db.execute(
        "UPDATE discovery_jobs SET status = 'cancelled', finished_at = ?, error = 'cancelled by operator' WHERE id = ?",
        (utcnow(), job_id),
    )
    append_event(db, actor=actor, action="discovery.job_cancel", outcome="cancelled", object_type="discovery_job", object_id=job_id)
    return get_job(db, job_id)


def start_ad_job(db: Database, scope_id: str, actor: str, client, live_enabled: bool) -> dict:
    scope = _active_scope(db, scope_id)
    methods = json.loads(scope["methods_json"])
    if "ldaps" not in methods:
        raise PolicyError("approved scope does not allow directory query", 403)
    if not scope["domain_controller"] or not scope["base_dn"]:
        raise PolicyError("directory query needs a controller address and base DN inside the approved scope")
    job_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO discovery_jobs (id, scope_id, kind, status, created_at, started_at, created_by)
            VALUES (?, ?, 'ad', 'running', ?, ?, ?)
            """,
            (job_id, scope_id, utcnow(), utcnow(), actor),
        )
    if client is None:
        if not live_enabled:
            _finish_failed(db, job_id, actor, "live directory adapter is disabled; import a cached snapshot or set FLEETGUARD_ENABLE_LIVE_LDAP=1. No directory results were fabricated.")
            return get_job(db, job_id)
        _finish_failed(db, job_id, actor, "live directory client is not configured. No directory results were fabricated.")
        return get_job(db, job_id)
    try:
        computers = client.search_computers(scope["base_dn"])
    except AdapterUnavailable as exc:
        _finish_failed(db, job_id, actor, str(exc))
        return get_job(db, job_id)
    except Exception:
        _finish_failed(db, job_id, actor, "directory controller was unavailable. Cached observations were left unchanged. No results were fabricated.")
        return get_job(db, job_id)
    evidence = getattr(client, "evidence_kind", "real")
    source_mode = getattr(client, "source_mode", "live_query")
    observed_at = utcnow()
    with db.transaction() as tx:
        for record in computers:
            guid = record["object_guid"]
            existing = tx.query_one("SELECT id FROM ad_computers WHERE object_guid = ?", (guid,))
            row_id = existing["id"] if existing else new_id()
            payload = (
                record.get("computer_name"),
                record.get("dns_hostname"),
                1 if record.get("enabled") else 0,
                record.get("os_name"),
                record.get("os_version"),
                record.get("distinguished_name"),
                record.get("last_logon_timestamp"),
                observed_at,
                source_mode,
                evidence,
                scope["domain_controller"],
                job_id,
            )
            if existing:
                tx.execute(
                    """
                    UPDATE ad_computers SET computer_name=?, dns_hostname=?, enabled=?, os_name=?, os_version=?,
                      distinguished_name=?, last_logon_timestamp=?, observed_at=?, source_mode=?, evidence_kind=?,
                      controller=?, job_id=? WHERE id=?
                    """,
                    payload + (row_id,),
                )
            else:
                tx.execute(
                    """
                    INSERT INTO ad_computers (
                      computer_name, dns_hostname, enabled, os_name, os_version, distinguished_name,
                      last_logon_timestamp, observed_at, source_mode, evidence_kind, controller, job_id, id, object_guid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    payload + (row_id, guid),
                )
        tx.execute("UPDATE discovery_jobs SET status='completed', finished_at=? WHERE id=?", (utcnow(), job_id))
        append_event(db, actor=actor, action="discovery.ad_finish", outcome="completed", object_type="discovery_job", object_id=job_id, detail={"computers": len(computers), "evidence_kind": evidence}, tx=tx)
    return get_job(db, job_id)


def scan_active_directory(db: Database, actor: str, reader=None) -> dict:
    from .directory_scan import DirectoryUnavailable, read_joined_computers

    job_id = new_id()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO discovery_jobs (id, scope_id, kind, status, created_at, started_at, created_by)
            VALUES (?, 'active-directory', 'ad', 'running', ?, ?, ?)
            """,
            (job_id, utcnow(), utcnow(), actor),
        )
    try:
        computers, controller = (reader or read_joined_computers)()
    except DirectoryUnavailable as exc:
        message = str(exc)
        if "fabricated" not in message:
            message = f"{message} No computer objects were fabricated."
        _finish_failed(db, job_id, actor, message)
        return get_job(db, job_id) | {"computers": 0}
    except Exception:
        _finish_failed(db, job_id, actor, "directory controller was unavailable. Cached observations were left unchanged. No computer objects were fabricated.")
        return get_job(db, job_id) | {"computers": 0}
    if not isinstance(computers, list):
        _finish_failed(db, job_id, actor, "directory returned no computer list. No computer objects were fabricated.")
        return get_job(db, job_id) | {"computers": 0}
    observed_at = utcnow()
    with db.transaction() as tx:
        for record in computers:
            if not isinstance(record, dict) or not record.get("object_guid"):
                continue
            guid = str(record["object_guid"])
            existing = tx.query_one("SELECT id FROM ad_computers WHERE object_guid = ?", (guid,))
            row_id = existing["id"] if existing else new_id()
            payload = (
                record.get("computer_name"),
                record.get("dns_hostname"),
                1 if record.get("enabled") else 0,
                record.get("os_name"),
                record.get("os_version"),
                record.get("distinguished_name"),
                record.get("last_logon_timestamp") or "",
                observed_at,
                "live_query",
                "real",
                controller,
                job_id,
            )
            if existing:
                tx.execute(
                    """
                    UPDATE ad_computers SET computer_name=?, dns_hostname=?, enabled=?, os_name=?, os_version=?,
                      distinguished_name=?, last_logon_timestamp=?, observed_at=?, source_mode=?, evidence_kind=?,
                      controller=?, job_id=? WHERE id=?
                    """,
                    payload + (row_id,),
                )
            else:
                tx.execute(
                    """
                    INSERT INTO ad_computers (
                      computer_name, dns_hostname, enabled, os_name, os_version, distinguished_name,
                      last_logon_timestamp, observed_at, source_mode, evidence_kind, controller, job_id, id, object_guid
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    payload + (row_id, guid),
                )
        tx.execute("UPDATE discovery_jobs SET status='completed', finished_at=? WHERE id=?", (utcnow(), job_id))
        append_event(
            db,
            actor=actor,
            action="discovery.ad_finish",
            outcome="completed",
            object_type="discovery_job",
            object_id=job_id,
            detail={"computers": len(computers), "evidence_kind": "real", "password_stored": False},
            tx=tx,
        )
    return get_job(db, job_id) | {"computers": len(computers)}


def _finish_failed(db, job_id, actor, message: str) -> None:
    with db.transaction() as tx:
        tx.execute("UPDATE discovery_jobs SET status='failed', finished_at=?, error=? WHERE id=?", (utcnow(), message, job_id))
        append_event(db, actor=actor, action="discovery.ad_finish", outcome="failed", object_type="discovery_job", object_id=job_id, detail={"error": message}, tx=tx)


def get_job(db: Database, job_id: str) -> dict:
    job = db.query_one("SELECT * FROM discovery_jobs WHERE id = ?", (job_id,))
    if not job:
        raise PolicyError("job not found", 404)
    observations = db.query("SELECT * FROM observations WHERE job_id = ? ORDER BY observed_at", (job_id,))
    return {"job": job, "observations": observations}


def list_jobs(db: Database) -> list[dict]:
    return db.query("SELECT * FROM discovery_jobs ORDER BY created_at")


class LiveLdapClient:
    evidence_kind = "real"
    source_mode = "live_query"

    def __init__(self, host: str, port: int, user: str, password: str, validate_certs: bool = True, timeout: float = 5):
        if not validate_certs:
            raise PolicyError("Refusing to disable TLS certificate validation")
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.timeout = timeout

    def search_computers(self, base_dn: str) -> list[dict]:
        try:
            import ssl
            from ldap3 import ALL, SUBTREE, Connection, Server, Tls
        except ImportError as exc:
            raise AdapterUnavailable("ldap3 is not installed; live AD query is unavailable and no results were fabricated") from exc
        tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT)
        server = Server(self.host, port=self.port, use_ssl=True, tls=tls, get_info=ALL, connect_timeout=self.timeout)
        connection = Connection(server, user=self.user, password=self.password, auto_bind=True, receive_timeout=self.timeout)
        connection.search(
            search_base=base_dn,
            search_filter="(&(objectCategory=computer)(objectClass=computer))",
            search_scope=SUBTREE,
            attributes=["cn", "dNSHostName", "operatingSystem", "operatingSystemVersion", "distinguishedName", "lastLogonTimestamp", "userAccountControl", "objectGUID"],
        )
        computers = []
        for entry in connection.entries:
            uac = int(entry.userAccountControl.value or 0)
            guid = entry.objectGUID.value
            guid_text = str(guid)
            computers.append(
                {
                    "object_guid": guid_text,
                    "computer_name": str(entry.cn.value or ""),
                    "dns_hostname": str(entry.dNSHostName.value or ""),
                    "enabled": not bool(uac & 2),
                    "os_name": str(entry.operatingSystem.value or ""),
                    "os_version": str(entry.operatingSystemVersion.value or ""),
                    "distinguished_name": str(entry.entry_dn),
                    "last_logon_timestamp": str(entry.lastLogonTimestamp.value or ""),
                }
            )
        connection.unbind()
        return computers

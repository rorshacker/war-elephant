from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from .audit import append_event
from .db import Database
from .policy import PolicyError
from .util import new_id, sha256_text, utcnow

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
SCRYPT_N = 2**14


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=8, p=1, dklen=32)
    return f"scrypt${SCRYPT_N}$8$1${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algo != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


def _dummy_verify(password: str) -> None:
    hashlib.scrypt(password.encode("utf-8"), salt=b"fleetguard-dummy-salt", n=SCRYPT_N, r=8, p=1, dklen=32)


def operator_count(db: Database) -> int:
    row = db.query_one("SELECT COUNT(*) AS n FROM operators")
    return int(row["n"] if row else 0)


def create_operator(db: Database, username: str, password: str) -> dict:
    if operator_count(db) > 0:
        raise PolicyError("an operator already exists", 409)
    if not USERNAME_RE.match(username or ""):
        raise PolicyError("username must be 3-32 characters of letters, numbers, dot, underscore, or hyphen")
    if len(password or "") < 12:
        raise PolicyError("password must be at least 12 characters")
    operator_id = new_id()
    created_at = utcnow()
    with db.transaction() as tx:
        tx.execute(
            "INSERT INTO operators (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (operator_id, username, _hash_password(password), created_at),
        )
        append_event(
            db,
            actor=username,
            action="operator.create",
            outcome="created",
            object_type="operator",
            object_id=operator_id,
            detail={"username": username},
            tx=tx,
        )
    return open_session(db, username, password)


def open_session(db: Database, username: str, password: str, hours: int = 12) -> dict:
    operator = db.query_one("SELECT * FROM operators WHERE username = ? AND disabled = 0", (username,))
    if not operator:
        _dummy_verify(password)
        append_event(db, actor="unknown", action="auth.login", outcome="denied", detail={"username": username})
        raise PolicyError("invalid credentials", 401)
    if not _verify_password(password, operator["password_hash"]):
        append_event(db, actor=username, action="auth.login", outcome="denied", object_type="operator", object_id=operator["id"])
        raise PolicyError("invalid credentials", 401)
    token = secrets.token_urlsafe(32)
    session_id = new_id()
    created_at = utcnow()
    from datetime import datetime, timedelta, timezone

    expires = (datetime.now(timezone.utc) + timedelta(hours=hours)).replace(microsecond=0).isoformat()
    with db.transaction() as tx:
        tx.execute(
            """
            INSERT INTO sessions (id, operator_id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, operator["id"], sha256_text(token), created_at, expires),
        )
        append_event(
            db,
            actor=username,
            action="auth.login",
            outcome="accepted",
            object_type="session",
            object_id=session_id,
            tx=tx,
        )
    return {"token": token, "username": username, "expires_at": expires, "operator_id": operator["id"]}


def resolve_session(db: Database, token: str) -> dict:
    if not token:
        raise PolicyError("authentication required", 401)
    row = db.query_one(
        """
        SELECT sessions.id AS session_id, sessions.expires_at, sessions.revoked,
               operators.id AS operator_id, operators.username, operators.disabled
        FROM sessions JOIN operators ON operators.id = sessions.operator_id
        WHERE sessions.token_hash = ?
        """,
        (sha256_text(token),),
    )
    if not row or row["revoked"] or row["disabled"]:
        raise PolicyError("authentication required", 401)
    from .util import parse_time
    from datetime import datetime, timezone

    if parse_time(row["expires_at"]) <= datetime.now(timezone.utc):
        raise PolicyError("session expired", 401)
    return {"session_id": row["session_id"], "operator_id": row["operator_id"], "username": row["username"]}


def revoke_session(db: Database, token: str) -> None:
    actor = resolve_session(db, token)
    with db.transaction() as tx:
        tx.execute("UPDATE sessions SET revoked = 1 WHERE id = ?", (actor["session_id"],))
        append_event(
            db,
            actor=actor["username"],
            action="auth.logout",
            outcome="revoked",
            object_type="session",
            object_id=actor["session_id"],
            tx=tx,
        )

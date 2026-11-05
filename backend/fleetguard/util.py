from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


SECRET_KEY_PARTS = (
    "password",
    "passphrase",
    "secret",
    "token",
    "authorization",
    "credential",
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if any(part in str(key).lower() for part in SECRET_KEY_PARTS):
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = redact(item)
        return cleaned
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value)

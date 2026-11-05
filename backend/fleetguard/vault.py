from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .policy import PolicyError

VERIFIER = b"fleetguard-vault-ok"


def _derive(passphrase: str, salt: bytes) -> bytes:
    import hashlib

    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def _encrypt(key: bytes, payload: bytes, associated: bytes) -> dict:
    import secrets

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, associated)
    return {"nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode()}


def _decrypt(key: bytes, blob: dict, associated: bytes) -> bytes:
    return AESGCM(key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ciphertext"]), associated)


class Vault:
    def __init__(self, path: Path):
        self.path = path
        self._key: bytes | None = None

    def status(self) -> dict:
        return {"initialized": self.path.exists(), "unlocked": self._key is not None}

    def unlock(self, passphrase: str) -> None:
        if len(passphrase or "") < 10:
            raise PolicyError("vault passphrase must be at least 10 characters")
        if not self.path.exists():
            self._create(passphrase)
            return
        data = json.loads(self.path.read_text(encoding="utf-8"))
        key = _derive(passphrase, base64.b64decode(data["salt"]))
        try:
            plain = _decrypt(key, data["verifier"], b"verifier")
        except Exception as exc:
            raise PolicyError("vault unlock failed", 401) from exc
        if plain != VERIFIER:
            raise PolicyError("vault unlock failed", 401)
        self._key = key

    def lock(self) -> None:
        if self._key is not None:
            buffer = bytearray(self._key)
            for index in range(len(buffer)):
                buffer[index] = 0
        self._key = None

    def put_secret(self, credential_id: str, secret: str) -> None:
        key = self._require()
        data = self._load()
        data["secrets"][credential_id] = _encrypt(key, secret.encode("utf-8"), credential_id.encode("utf-8"))
        self._save(data)

    def get_secret(self, credential_id: str) -> str:
        key = self._require()
        data = self._load()
        blob = data["secrets"].get(credential_id)
        if not blob:
            raise PolicyError("credential secret is not in the vault", 404)
        try:
            return _decrypt(key, blob, credential_id.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            raise PolicyError("credential secret could not be decrypted", 409) from exc

    def delete_secret(self, credential_id: str) -> None:
        data = self._load()
        data["secrets"].pop(credential_id, None)
        self._save(data)

    def _require(self) -> bytes:
        if self._key is None:
            raise PolicyError("vault is locked", 401)
        return self._key

    def _create(self, passphrase: str) -> None:
        import secrets

        salt = secrets.token_bytes(16)
        key = _derive(passphrase, salt)
        data = {
            "kdf": "scrypt",
            "salt": base64.b64encode(salt).decode(),
            "verifier": _encrypt(key, VERIFIER, b"verifier"),
            "secrets": {},
        }
        self._save(data)
        self._key = key

    def _load(self) -> dict:
        if not self.path.exists():
            raise PolicyError("vault is not initialized", 409)
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data), encoding="utf-8")

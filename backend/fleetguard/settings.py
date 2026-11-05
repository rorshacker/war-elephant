from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    lab_root: Path
    enclave: str = "synthetic-lab"
    schema_version: str = "1"
    host: str = "127.0.0.1"
    port: int = 8000
    enable_live_ldap: bool = False
    max_upload: int = 30 * 1024 * 1024
    max_zip_files: int = 40
    max_member: int = 5 * 1024 * 1024
    max_uncompressed: int = 20 * 1024 * 1024
    max_ratio: int = 100
    max_discovery_hosts: int = 256
    session_hours: int = 12

    @classmethod
    def from_env(cls) -> Settings:
        data = Path(os.environ.get("FLEETGUARD_DATA_DIR", "data")).resolve()
        lab = Path(os.environ.get("FLEETGUARD_LAB_ROOT", str(data / "lab"))).resolve()
        return cls(
            data_dir=data,
            lab_root=lab,
            enclave=os.environ.get("FLEETGUARD_ENCLAVE", "synthetic-lab"),
            host=os.environ.get("FLEETGUARD_HOST", "127.0.0.1"),
            port=int(os.environ.get("FLEETGUARD_PORT", "8000")),
            enable_live_ldap=_flag("FLEETGUARD_ENABLE_LIVE_LDAP"),
        )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "fleetguard.db"

    @property
    def vault_path(self) -> Path:
        return self.data_dir / "vault.json"

    @property
    def stig_dir(self) -> Path:
        return self.data_dir / "stig"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

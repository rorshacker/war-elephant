from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .policy import AdapterUnavailable, PolicyError
from .settings import Settings

ADAPTER_VERSION = "local-file-1"
LAB_FILENAME = "fleetguard-lab.conf"
INSTALL_TOKEN = re.compile(r"^(stig|ecu|fam|msu|iava):[0-9a-fA-F-]{36}$")


def lab_file(settings: Settings, relative_dir: str) -> Path:
    relative = Path(relative_dir)
    if relative.is_absolute() or ".." in relative.parts:
        raise PolicyError("lab directory must stay inside the lab root")
    root = settings.lab_root.resolve()
    candidate = (root / relative / LAB_FILENAME).resolve()
    if not candidate.is_relative_to(root):
        raise PolicyError("lab path escapes the lab root")
    return candidate


def read_config(path: Path) -> tuple[dict, str, bytes]:
    if not path.is_file():
        raise PolicyError("prior configuration is missing")
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    data = {}
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        data[key.strip()] = value.strip()
    return data, digest, raw


def write_config(path: Path, data: dict) -> None:
    lines = [f"{key}={value}" for key, value in data.items()]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


class LocalFileAdapter:
    name = "local_lab_file"
    version = ADAPTER_VERSION

    def capabilities(self) -> dict:
        return {
            "implemented": True,
            "actions": ["set_audit_policy", "record_lab_install"],
            "rollback": "automatic",
            "connectivity_risk": False,
            "note": "Changes allowlisted keys in a lab configuration file. This is not a Windows, Linux, or network-device management adapter.",
        }

    def read(self, settings: Settings, relative_dir: str) -> tuple[dict, str, bytes]:
        return read_config(lab_file(settings, relative_dir))

    def apply(self, settings: Settings, relative_dir: str, value: str) -> str:
        if value not in {"enabled", "disabled"}:
            raise PolicyError("audit_policy value is not allowlisted")
        path = lab_file(settings, relative_dir)
        data, _digest, _raw = read_config(path)
        data["audit_policy"] = value
        write_config(path, data)
        _data, digest, _raw = read_config(path)
        return digest

    def record_installed(self, settings: Settings, relative_dir: str, token: str) -> str:
        if not INSTALL_TOKEN.match(token):
            raise PolicyError("install token is not allowlisted")
        path = lab_file(settings, relative_dir)
        data, _digest, _raw = read_config(path)
        recorded = [part for part in data.get("installed", "").split(",") if part]
        if token not in recorded:
            recorded.append(token)
        data["installed"] = ",".join(recorded)
        write_config(path, data)
        _data, digest, _raw = read_config(path)
        return digest

    def restore(self, settings: Settings, relative_dir: str, prior_bytes: bytes) -> str:
        path = lab_file(settings, relative_dir)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(prior_bytes)
        temporary.replace(path)
        _data, digest, _raw = read_config(path)
        return digest


class WindowsConfigAdapter:
    name = "windows"

    def capabilities(self) -> dict:
        return {"implemented": False, "note": "No Windows management interface is implemented in this build."}

    def execute(self, action: str, params: dict, context: dict) -> dict:
        raise AdapterUnavailable("Windows configuration changes are not implemented")


class LinuxSshAdapter:
    name = "linux_ssh"

    def capabilities(self) -> dict:
        return {
            "implemented": False,
            "note": "SSH execution is not enabled. Allowlisted actions can be rejected in unit tests with a fake transport.",
        }

    def execute(self, action: str, params: dict, context: dict) -> dict:
        if action == "set_sshd_port":
            raise PolicyError("connectivity-affecting change blocked; no platform-supported safe recovery strategy is configured")
        if action != "set_login_banner":
            raise PolicyError("action is not allowlisted")
        transport = (context or {}).get("test_transport")
        if transport is None:
            raise AdapterUnavailable("live SSH execution is not enabled")
        if not isinstance(params.get("banner"), str) or "\n" in params["banner"]:
            raise PolicyError("banner parameter is not allowlisted")
        return transport.run(argv=["set-login-banner", params["banner"]])


class NetworkDeviceAdapter:
    name = "network_device"

    def capabilities(self) -> dict:
        return {"implemented": False, "note": "No vendor device adapter is implemented. Generic device support is not claimed."}

    def execute(self, action: str, params: dict, context: dict) -> dict:
        raise AdapterUnavailable("network-device configuration changes are not implemented")


def adapter_catalog() -> list[dict]:
    return [
        LocalFileAdapter().capabilities() | {"name": LocalFileAdapter.name},
        WindowsConfigAdapter().capabilities() | {"name": WindowsConfigAdapter.name},
        LinuxSshAdapter().capabilities() | {"name": LinuxSshAdapter.name},
        NetworkDeviceAdapter().capabilities() | {"name": NetworkDeviceAdapter.name},
    ]

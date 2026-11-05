from __future__ import annotations

import json
from pathlib import Path

from .discovery import import_ad_cache
from .inventory import commit_inventory, preview_inventory
from .reconcile import bind_lab, reconcile
from .stig import import_package

ROOT = Path(__file__).resolve().parents[2] / "fixtures"
CONFIRM = "LOAD SYNTHETIC TRAINING DATA"


def load_synthetic(db, settings, actor: str, confirmation: str) -> dict:
    if confirmation != CONFIRM:
        from .policy import PolicyError

        raise PolicyError("confirm synthetic training data before loading it")
    packages = []
    for path in sorted(ROOT.glob("*.xml")):
        packages.append(import_package(db, settings, path.name, path.read_bytes(), actor))
    inventory = (ROOT / "synthetic_inventory.csv").read_bytes()
    preview = preview_inventory(db, "synthetic_inventory.csv", inventory, None, None)
    committed = commit_inventory(db, preview["preview_id"], actor, True, True)
    ad = import_ad_cache(db, json.loads((ROOT / "synthetic_ad_cache.json").read_text(encoding="utf-8")), actor)
    reconcile(db, actor)
    lab_dir = settings.lab_root / "win-lab"
    lab_dir.mkdir(parents=True, exist_ok=True)
    target = lab_dir / "fleetguard-lab.conf"
    if not target.exists():
        target.write_text("audit_policy=disabled\n", encoding="utf-8")
    asset = db.query_one("SELECT id FROM assets WHERE hostname = ?", ("LAB-WIN",))
    if not asset:
        from .policy import PolicyError

        raise PolicyError("synthetic lab asset was not created")
    bound = bind_lab(db, settings, asset["id"], "win-lab", actor)
    return {
        "label": "synthetic training fixtures",
        "evidence": "imported",
        "packages": len(packages),
        "inventory_rows": committed["row_count"],
        "ad_computers": ad["computers"],
        "lab_asset": None if not bound else bound["id"],
        "statement": "These fixtures are synthetic. They are not scan results and they do not approve any change.",
    }

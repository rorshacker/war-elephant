from __future__ import annotations

import argparse
import sys

from .app import create_app
from .audit import export_checkpoint, verify_chain
from .changes import recover_report
from .db import Database
from .inventory import commit_inventory, preview_inventory
from .settings import Settings
from .stig import import_package


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(arg == "--password" or arg.startswith("--password=") or arg == "--secret" or arg.startswith("--secret=") for arg in argv):
        print("Refusing to accept credentials on the command line.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(prog="fleetguard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("diag")
    sub.add_parser("serve")
    stig = sub.add_parser("import-stig")
    stig.add_argument("path")
    inventory = sub.add_parser("import-inventory")
    inventory.add_argument("path")
    inventory.add_argument("--worksheet", default=None)
    inventory.add_argument("--commit", action="store_true")
    inventory.add_argument("--acknowledge-duplicates", action="store_true")
    sub.add_parser("verify-audit")
    export = sub.add_parser("checkpoint")
    export.add_argument("path")
    sub.add_parser("recover")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    if args.command == "serve":
        import uvicorn

        uvicorn.run(create_app(settings), host=settings.host, port=settings.port)
        return 0
    app = create_app(settings)
    db: Database = app.state.db
    try:
        if args.command == "init":
            print(f"database={settings.db_path}")
            print(f"lab_root={settings.lab_root}")
            return 0
        if args.command == "diag":
            chain = verify_chain(db)
            print(f"python={sys.version.split()[0]}")
            print(f"database={settings.db_path}")
            print(f"audit_ok={chain['ok']} events={chain['count']}")
            print(f"vault_initialized={app.state.vault.status()['initialized']}")
            print(f"live_ldap={settings.enable_live_ldap}")
            print(f"bind={settings.host}:{settings.port}")
            return 0 if chain["ok"] else 1
        if args.command == "import-stig":
            from pathlib import Path

            file = Path(args.path)
            result = import_package(db, settings, file.name, file.read_bytes(), "cli")
            print(result["status"], result["sha256"], result["authenticity"])
            return 0
        if args.command == "import-inventory":
            from pathlib import Path

            file = Path(args.path)
            preview = preview_inventory(db, file.name, file.read_bytes(), args.worksheet, None)
            if preview.get("need_worksheet"):
                print("worksheets:", ", ".join(preview["worksheets"]))
                return 1
            print(f"rows={preview['row_count']} errors={len(preview['errors'])} duplicates={len(preview['duplicates'])}")
            if args.commit:
                result = commit_inventory(db, preview["preview_id"], "cli", True, args.acknowledge_duplicates)
                print(f"committed={result['import_id']}")
            return 0 if not preview["errors"] else 1
        if args.command == "verify-audit":
            chain = verify_chain(db)
            print(chain["statement"])
            print(f"ok={chain['ok']} events={chain['count']}")
            return 0 if chain["ok"] else 1
        if args.command == "checkpoint":
            from pathlib import Path

            payload = export_checkpoint(db, "cli", app.state.signer)
            Path(args.path).write_text(__import__("json").dumps(payload, indent=2), encoding="utf-8")
            print(payload["signature_status"])
            return 0
        if args.command == "recover":
            report = recover_report(db)
            print(f"ambiguous={len(report['ambiguous_executions'])} interrupted={len(report['interrupted_discovery_jobs'])}")
            print(report["note"])
            return 0
    finally:
        db.close()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from .util import utcnow


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")

    def migrate(self, migrations: Path) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
              id TEXT PRIMARY KEY,
              applied_at TEXT NOT NULL
            )
            """
        )
        self._conn.commit()
        applied = {row[0] for row in self._conn.execute("SELECT id FROM schema_migrations")}
        for path in sorted(migrations.glob("*.sql")):
            if path.name in applied:
                continue
            self._conn.executescript(path.read_text(encoding="utf-8"))
            self._conn.execute(
                "INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?)",
                (path.name, utcnow()),
            )
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            cursor = self._conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return cursor.lastrowid or 0

    def transaction(self) -> Transaction:
        return Transaction(self)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class Transaction:
    def __init__(self, db: Database):
        self.db = db

    def __enter__(self) -> Transaction:
        self.db._lock.acquire()
        self.db._conn.execute("BEGIN IMMEDIATE")
        return self

    def execute(self, sql: str, params: tuple = ()):
        return self.db._conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        cursor = self.db._conn.execute(sql, params)
        return [dict(row) for row in cursor.fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if exc_type:
                self.db._conn.rollback()
            else:
                self.db._conn.commit()
        finally:
            self.db._lock.release()

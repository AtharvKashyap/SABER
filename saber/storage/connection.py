"""SQLite storage connection and migration runner for SABER."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class StorageConnection:
    """Small SQLite wrapper for SABER storage.

    Security notes:
    - Migrations are static SQL files controlled by the application.
    - Runtime stores should use parameterized SQL only.
    - check_same_thread=False is required for FastAPI/TestClient thread usage.
    - A re-entrant lock serializes access through this wrapper.
    """

    def __init__(
        self,
        db_path: str | Path,
        migrations_dir: str | Path | None = None,
    ) -> None:
        """Initialize storage connection."""

        self.db_path = Path(db_path)
        self.migrations_dir = (
            Path(migrations_dir)
            if migrations_dir is not None
            else Path(__file__).parent / "migrations"
        )
        self._connection: sqlite3.Connection | None = None
        self._lock = threading.RLock()
        self._in_transaction = False

    def connect(self) -> sqlite3.Connection:
        """Return SQLite connection, creating it if needed."""

        with self._lock:
            if self._connection is None:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                self._connection = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                )
                self._connection.row_factory = sqlite3.Row
                self._connection.execute("PRAGMA foreign_keys = ON")
            return self._connection

    def close(self) -> None:
        """Close connection."""

        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def initialize(self) -> None:
        """Initialize database and apply migrations."""

        with self._lock:
            self.connect()
            self._ensure_schema_migrations_table()
            self.apply_migrations()

    def apply_migrations(self) -> list[str]:
        """Apply unapplied migrations and return applied migration versions."""

        with self._lock:
            self._ensure_schema_migrations_table()

            if not self.migrations_dir.exists():
                raise FileNotFoundError(
                    f"Migrations directory does not exist: {self.migrations_dir}"
                )

            applied = self._applied_versions()
            newly_applied: list[str] = []

            for migration_path in sorted(self.migrations_dir.glob("*.sql")):
                version = migration_path.name
                if version in applied:
                    continue

                sql = migration_path.read_text(encoding="utf-8")
                conn = self.connect()

                try:
                    conn.executescript(sql)
                    conn.execute(
                        "INSERT INTO schema_migrations (version) VALUES (?)",
                        (version,),
                    )
                    conn.commit()
                    newly_applied.append(version)
                except Exception:
                    conn.rollback()
                    raise

            return newly_applied

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run operations inside a transaction."""

        with self._lock:
            conn = self.connect()
            previous = self._in_transaction
            self._in_transaction = True
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                self._in_transaction = previous

    def execute(self, sql: str, parameters: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        """Execute one parameterized statement."""

        with self._lock:
            conn = self.connect()
            cursor = conn.execute(sql, parameters)
            if not self._in_transaction:
                conn.commit()
            return cursor

    def query_one(
        self,
        sql: str,
        parameters: tuple[Any, ...] = (),
    ) -> sqlite3.Row | None:
        """Return one row."""

        with self._lock:
            return self.connect().execute(sql, parameters).fetchone()

    def query_all(
        self,
        sql: str,
        parameters: tuple[Any, ...] = (),
    ) -> list[sqlite3.Row]:
        """Return all rows."""

        with self._lock:
            return list(self.connect().execute(sql, parameters).fetchall())

    def _ensure_schema_migrations_table(self) -> None:
        """Create schema migration table."""

        self.connect().execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.connect().commit()

    def _applied_versions(self) -> set[str]:
        """Return applied migration versions."""

        rows = self.query_all("SELECT version FROM schema_migrations")
        return {str(row["version"]) for row in rows}

    def __enter__(self) -> StorageConnection:
        """Context manager enter."""

        self.initialize()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Context manager exit."""

        self.close()

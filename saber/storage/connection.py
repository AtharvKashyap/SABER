"""SQLite storage connection and migration support for SABER."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class StorageConnection:
    """SQLite connection wrapper for SABER stores."""

    def __init__(
        self,
        db_path: str | Path,
        migrations_dir: str | Path | None = None,
    ) -> None:
        """Initialize storage connection."""

        self.db_path = Path(db_path)
        self.migrations_dir = Path(migrations_dir) if migrations_dir else Path(__file__).parent / "migrations"
        self._connection: sqlite3.Connection | None = None

    def connect(self) -> sqlite3.Connection:
        """Return active SQLite connection."""

        if self._connection is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(str(self.db_path))
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
        return self._connection

    def close(self) -> None:
        """Close active connection."""

        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def initialize(self) -> None:
        """Initialize database and apply migrations."""

        self.connect()
        self._ensure_schema_migrations_table()
        self.apply_migrations()

    def apply_migrations(self) -> list[str]:
        """Apply unapplied SQL migrations and return applied versions."""

        self._ensure_schema_migrations_table()

        if not self.migrations_dir.exists():
            raise FileNotFoundError(f"Migrations directory does not exist: {self.migrations_dir}")

        applied_versions = self._applied_versions()
        newly_applied: list[str] = []

        for migration_path in sorted(self.migrations_dir.glob("*.sql")):
            version = migration_path.name
            if version in applied_versions:
                continue

            sql = migration_path.read_text(encoding="utf-8").strip()
            if not sql:
                continue

            with self.transaction() as connection:
                connection.executescript(sql)
                connection.execute(
                    """
                    INSERT INTO schema_migrations (version, applied_at)
                    VALUES (?, datetime('now'))
                    """,
                    (version,),
                )

            newly_applied.append(version)

        return newly_applied

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run SQL in a transaction."""

        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        """Execute SQL and commit immediately."""

        connection = self.connect()
        cursor = connection.execute(sql, params)
        connection.commit()
        return cursor

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        """Return one row."""

        return self.connect().execute(sql, params).fetchone()

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        """Return all rows."""

        return list(self.connect().execute(sql, params).fetchall())

    def _ensure_schema_migrations_table(self) -> None:
        """Create schema migration tracking table."""

        self.connect().execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        self.connect().commit()

    def _applied_versions(self) -> set[str]:
        """Return applied migration versions."""

        rows = self.query_all("SELECT version FROM schema_migrations", ())
        return {row["version"] for row in rows}

    def __enter__(self) -> StorageConnection:
        """Context manager enter."""

        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        """Context manager exit."""

        self.close()

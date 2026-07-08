"""Tests for StorageConnection."""

from __future__ import annotations

import sqlite3

import pytest

from saber.storage.connection import StorageConnection


def write_migration(directory, name: str, sql: str) -> None:
    """Write migration file."""

    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_text(sql)


class TestStorageConnection:
    """Validate StorageConnection."""

    def test_connect_creates_database_file(self, tmp_path) -> None:
        """connect should create parent directory and db file."""

        db_path = tmp_path / "nested" / "saber.db"
        migrations = tmp_path / "migrations"
        migrations.mkdir()

        storage = StorageConnection(db_path=db_path, migrations_dir=migrations)
        storage.connect()

        assert db_path.exists()

        storage.close()

    def test_initialize_applies_migrations(self, tmp_path) -> None:
        """initialize should apply sorted migrations."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            """
            CREATE TABLE items (
                item_id TEXT PRIMARY KEY,
                name TEXT NOT NULL
            );
            """,
        )
        write_migration(
            migrations,
            "002_more.sql",
            """
            INSERT INTO items (item_id, name) VALUES ('item_1', 'First');
            """,
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        storage.initialize()

        row = storage.query_one("SELECT name FROM items WHERE item_id = ?", ("item_1",))
        versions = storage.query_all("SELECT version FROM schema_migrations ORDER BY version")

        assert row["name"] == "First"
        assert [version["version"] for version in versions] == ["001_initial.sql", "002_more.sql"]

    def test_apply_migrations_does_not_rerun_applied_migrations(self, tmp_path) -> None:
        """Applied migrations should not run twice."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            """
            CREATE TABLE counter (
                value INTEGER NOT NULL
            );
            INSERT INTO counter (value) VALUES (1);
            """,
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        first = storage.apply_migrations()
        second = storage.apply_migrations()

        rows = storage.query_all("SELECT value FROM counter")

        assert first == ["001_initial.sql"]
        assert second == []
        assert len(rows) == 1
        assert rows[0]["value"] == 1

    def test_missing_migrations_dir_raises(self, tmp_path) -> None:
        """Missing migration directory should raise."""

        storage = StorageConnection(tmp_path / "saber.db", tmp_path / "missing")

        with pytest.raises(FileNotFoundError, match="Migrations directory does not exist"):
            storage.apply_migrations()

    def test_execute_query_one_and_query_all(self, tmp_path) -> None:
        """Query helpers should work."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            "CREATE TABLE items (item_id TEXT PRIMARY KEY, name TEXT NOT NULL);",
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        storage.initialize()
        storage.execute("INSERT INTO items (item_id, name) VALUES (?, ?)", ("a", "Alpha"))
        storage.execute("INSERT INTO items (item_id, name) VALUES (?, ?)", ("b", "Beta"))

        one = storage.query_one("SELECT * FROM items WHERE item_id = ?", ("a",))
        all_rows = storage.query_all("SELECT * FROM items ORDER BY item_id")

        assert one["name"] == "Alpha"
        assert [row["name"] for row in all_rows] == ["Alpha", "Beta"]

    def test_transaction_commits(self, tmp_path) -> None:
        """Transaction should commit on success."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            "CREATE TABLE items (item_id TEXT PRIMARY KEY, name TEXT NOT NULL);",
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        storage.initialize()

        with storage.transaction() as connection:
            connection.execute("INSERT INTO items (item_id, name) VALUES (?, ?)", ("a", "Alpha"))

        row = storage.query_one("SELECT * FROM items WHERE item_id = ?", ("a",))
        assert row["name"] == "Alpha"

    def test_transaction_rolls_back(self, tmp_path) -> None:
        """Transaction should roll back on exception."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            "CREATE TABLE items (item_id TEXT PRIMARY KEY, name TEXT NOT NULL);",
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        storage.initialize()

        with pytest.raises(RuntimeError, match="boom"):
            with storage.transaction() as connection:
                connection.execute("INSERT INTO items (item_id, name) VALUES (?, ?)", ("a", "Alpha"))
                raise RuntimeError("boom")

        row = storage.query_one("SELECT * FROM items WHERE item_id = ?", ("a",))
        assert row is None

    def test_foreign_keys_are_enabled(self, tmp_path) -> None:
        """Foreign key constraints should be enabled."""

        migrations = tmp_path / "migrations"
        write_migration(
            migrations,
            "001_initial.sql",
            """
            CREATE TABLE parent (
                parent_id TEXT PRIMARY KEY
            );
            CREATE TABLE child (
                child_id TEXT PRIMARY KEY,
                parent_id TEXT NOT NULL,
                FOREIGN KEY(parent_id) REFERENCES parent(parent_id)
            );
            """,
        )

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        storage.initialize()

        with pytest.raises(sqlite3.IntegrityError):
            storage.execute("INSERT INTO child (child_id, parent_id) VALUES (?, ?)", ("child", "missing"))

    def test_context_manager_closes_connection(self, tmp_path) -> None:
        """StorageConnection should support context manager."""

        migrations = tmp_path / "migrations"
        migrations.mkdir()

        storage = StorageConnection(tmp_path / "saber.db", migrations)
        with storage as active:
            assert active.connect() is not None

        assert storage._connection is None

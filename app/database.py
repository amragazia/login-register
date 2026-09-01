from pathlib import Path
from typing import Any
import sqlite3

DATABASE_PATH = Path(__file__).resolve().parent.parent / "users.db"


class DataBase:
    def _connect(self) -> sqlite3.Connection:
        """Return a short-lived connection safe for FastAPI worker threads."""
        connection = sqlite3.connect(DATABASE_PATH, timeout=15.0)
        return connection

    def create_table_users(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL
                )
                """)

    def insert_user(self, username: str, password_hash: str) -> bool:
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash),
                )
                return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            return False

    def get_all_users(self) -> list[tuple[Any, ...]]:
        with self._connect() as connection:
            return connection.execute(
                "SELECT id, username, password_hash FROM users"
            ).fetchall()

    def get_user(self, username: str) -> tuple[Any, ...] | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?",
                (username,),
            ).fetchone()

    def update_user(
        self, username: str, new_username: str, new_password_hash: str
    ) -> bool:
        try:
            with self._connect() as connection:
                cursor = connection.execute(
                    "UPDATE users SET username = ?, password_hash = ? WHERE username = ?",
                    (new_username, new_password_hash, username),
                )
                return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            return False

    def delete_user(self, username: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM users WHERE username = ?", (username,)
            )
            return cursor.rowcount > 0

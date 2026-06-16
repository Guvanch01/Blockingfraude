"""
Database — Groups, subscriptions, and ban log.
SQLite (easy to migrate to PostgreSQL later).
"""

import sqlite3
import logging
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = "guardbot.db"


class Database:
    def __init__(self):
        self._init_tables()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"DB error: {e}")
            raise
        finally:
            conn.close()

    def _init_tables(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS groups (
                    chat_id        INTEGER PRIMARY KEY,
                    title          TEXT NOT NULL,
                    registered_by  INTEGER NOT NULL,
                    registered_at  TEXT DEFAULT (datetime('now')),
                    is_active      INTEGER DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    chat_id     INTEGER PRIMARY KEY,
                    plan        TEXT DEFAULT 'free',
                    started_at  TEXT DEFAULT (datetime('now')),
                    expires_at  TEXT,
                    is_active   INTEGER DEFAULT 1,
                    FOREIGN KEY (chat_id) REFERENCES groups(chat_id)
                );

                CREATE TABLE IF NOT EXISTS ban_log (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id          INTEGER NOT NULL,
                    user_id          INTEGER NOT NULL,
                    username         TEXT,
                    reason           TEXT,
                    category         TEXT DEFAULT 'unknown',
                    confidence       REAL,
                    message_preview  TEXT,
                    banned_at        TEXT DEFAULT (datetime('now'))
                );
            """)
            # Migration: add category column if it doesn't exist yet
            try:
                conn.execute("ALTER TABLE ban_log ADD COLUMN category TEXT DEFAULT 'unknown'")
            except Exception:
                pass  # Column already exists

    # ── Groups ──────────────────────────────────────

    def register_group(self, chat_id: int, chat_title: str, registered_by: int) -> bool:
        try:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT chat_id FROM groups WHERE chat_id = ?", (chat_id,)
                ).fetchone()
                if existing:
                    return False
                conn.execute(
                    "INSERT INTO groups (chat_id, title, registered_by) VALUES (?, ?, ?)",
                    (chat_id, chat_title, registered_by)
                )
            return True
        except Exception:
            return False

    def get_group(self, chat_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM groups WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_user_groups(self, user_id: int) -> list:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM groups WHERE registered_by = ? AND is_active = 1",
                (user_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ── Subscriptions ────────────────────────────────

    def set_subscription(self, chat_id: int, plan: str, expires_at: str):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO subscriptions (chat_id, plan, expires_at, is_active)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(chat_id) DO UPDATE SET
                    plan=excluded.plan,
                    expires_at=excluded.expires_at,
                    is_active=1
            """, (chat_id, plan, expires_at))

    def get_subscription(self, chat_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM subscriptions WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            return dict(row) if row else None

    def deactivate_subscription(self, chat_id: int):
        with self._conn() as conn:
            conn.execute(
                "UPDATE subscriptions SET is_active = 0 WHERE chat_id = ?",
                (chat_id,)
            )

    # ── Ban log ──────────────────────────────────────

    def log_action(self, chat_id: int, user_id: int, username: str,
                   reason: str, confidence: float, message_preview: str,
                   category: str = "unknown"):
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO ban_log
                    (chat_id, user_id, username, reason, category, confidence, message_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (chat_id, user_id, username, reason, category, confidence, message_preview))

    def get_stats(self, chat_id: int) -> dict:
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM ban_log WHERE chat_id = ?", (chat_id,)
            ).fetchone()[0]
            scam = conn.execute(
                "SELECT COUNT(*) FROM ban_log WHERE chat_id = ? AND category = 'scam'",
                (chat_id,)
            ).fetchone()[0]
            sexual = conn.execute(
                "SELECT COUNT(*) FROM ban_log WHERE chat_id = ? AND category = 'sexual'",
                (chat_id,)
            ).fetchone()[0]
            phishing = conn.execute(
                "SELECT COUNT(*) FROM ban_log WHERE chat_id = ? AND category = 'phishing'",
                (chat_id,)
            ).fetchone()[0]
            manual = conn.execute(
                "SELECT COUNT(*) FROM ban_log WHERE chat_id = ? AND category = 'manual_block'",
                (chat_id,)
            ).fetchone()[0]
        return {
            "total_bans": total,
            "scam_bans": scam,
            "sexual_bans": sexual,
            "phishing_bans": phishing,
            "manual_bans": manual,
        }

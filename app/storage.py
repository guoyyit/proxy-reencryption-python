"""SQLite persistence.

Durability notes:
* WAL journaling plus ``synchronous=NORMAL`` (commit fsyncs the WAL) gives
  crash-safe atomic multi-statement transactions without torn writes.
* Every state-changing service operation runs inside one transaction and may
  carry a client ``Idempotency-Key``; the stored response is replayed after a
  crash or a retry instead of applying the change twice.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    verify_key  TEXT NOT NULL,
    pub_key     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS delegations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id         TEXT NOT NULL,
    delegatee_id     TEXT NOT NULL,
    current_version  INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    revoked_at       TEXT,
    revoke_reason    TEXT,
    UNIQUE(owner_id, delegatee_id)
);

CREATE TABLE IF NOT EXISTS rekey_versions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    delegation_id INTEGER NOT NULL REFERENCES delegations(id),
    version       INTEGER NOT NULL,
    rk_json       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE(delegation_id, version)
);

CREATE TABLE IF NOT EXISTS ciphertexts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ciphertext_id TEXT NOT NULL UNIQUE,
    owner_id      TEXT NOT NULL,
    enc_version   INTEGER NOT NULL DEFAULT 1,
    data_hash     TEXT NOT NULL,
    raw_ref       TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    revoked_at    TEXT
);

CREATE TABLE IF NOT EXISTS revocations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,
    owner_id     TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    not_before   TEXT,
    not_after    TEXT,
    reason       TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revocations ON revocations(owner_id, target_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor_id   TEXT NOT NULL,
    action     TEXT NOT NULL,
    result     TEXT NOT NULL,
    request_id TEXT NOT NULL,
    details    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    seen_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS idempotency (
    idem_key    TEXT PRIMARY KEY,
    actor_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    body        TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self.path = str(db_path)
        parent = Path(self.path).parent
        if parent != Path("."):
            parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        with self._conn:
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @contextmanager
    def abortable_transaction(self) -> Iterator[tuple[sqlite3.Connection, dict[str, Any]]]:
        """Yield ``(conn, state)``. Set ``state['abort']`` to True to roll back
        while returning normally (used when a denial must be audited afterwards
        in a separate transaction rather than raised and lost)."""
        state: dict[str, Any] = {"abort": False}
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn, state
                if state.get("abort"):
                    self._conn.execute("ROLLBACK")
                else:
                    self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    # ---------------------------------------------------------------- users
    def create_user(self, user_id: str, verify_key: str, pub_key: str, created_at: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO users(user_id, verify_key, pub_key, created_at) VALUES (?,?,?,?)",
                (user_id, verify_key, pub_key, created_at),
            )

    def get_user(self, user_id: str) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM users WHERE user_id=?", (user_id,))
            return cur.fetchone()

    def list_users(self) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute("SELECT * FROM users ORDER BY user_id"))

    # ---------------------------------------------------------------- delegations
    def create_delegation(self, owner_id: str, delegatee_id: str, created_at: str) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO delegations(owner_id, delegatee_id, current_version, created_at)"
                " VALUES (?,?,1,?)",
                (owner_id, delegatee_id, created_at),
            )
            return int(cur.lastrowid)

    def get_delegation_by_pair(self, owner_id: str, delegatee_id: str) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM delegations WHERE owner_id=? AND delegatee_id=?",
                (owner_id, delegatee_id),
            )
            return cur.fetchone()

    def get_delegation(self, delegation_id: int) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM delegations WHERE id=?", (delegation_id,))
            return cur.fetchone()

    def add_rekey_version(self, delegation_id: int, version: int, rk_json: str, created_at: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO rekey_versions(delegation_id, version, rk_json, created_at)"
                " VALUES (?,?,?,?)",
                (delegation_id, version, rk_json, created_at),
            )
            conn.execute(
                "UPDATE delegations SET current_version=? WHERE id=?",
                (version, delegation_id),
            )

    def get_rekey_version(self, delegation_id: int, version: int) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM rekey_versions WHERE delegation_id=? AND version=?",
                (delegation_id, version),
            )
            return cur.fetchone()

    def revoke_delegation(self, delegation_id: int, revoked_at: str, reason: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE delegations SET revoked_at=?, revoke_reason=? WHERE id=?",
                (revoked_at, reason, delegation_id),
            )

    # ---------------------------------------------------------------- ciphertexts
    def register_ciphertext(
        self,
        ciphertext_id: str,
        owner_id: str,
        enc_version: int,
        data_hash: str,
        raw_ref: str,
        created_at: str,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO ciphertexts(ciphertext_id, owner_id, enc_version, data_hash,"
                " raw_ref, created_at) VALUES (?,?,?,?,?,?)",
                (ciphertext_id, owner_id, enc_version, data_hash, raw_ref, created_at),
            )

    def get_ciphertext(self, ciphertext_id: str) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM ciphertexts WHERE ciphertext_id=?", (ciphertext_id,)
            )
            return cur.fetchone()

    def revoke_ciphertext(self, ciphertext_id: str, revoked_at: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE ciphertexts SET revoked_at=? WHERE ciphertext_id=?",
                (revoked_at, ciphertext_id),
            )

    # ---------------------------------------------------------------- revocations
    def add_revocation(
        self,
        kind: str,
        owner_id: str,
        target_id: str,
        not_before: str | None,
        not_after: str | None,
        reason: str,
        created_at: str,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO revocations(kind, owner_id, target_id, not_before, not_after,"
                " reason, created_at) VALUES (?,?,?,?,?,?,?)",
                (kind, owner_id, target_id, not_before, not_after, reason, created_at),
            )

    def list_windows(self, owner_id: str, target_id: str | None = None) -> list[sqlite3.Row]:
        with self._lock:
            if target_id is None:
                cur = self._conn.execute(
                    "SELECT * FROM revocations WHERE owner_id=? AND kind='window' ORDER BY id",
                    (owner_id,),
                )
            else:
                cur = self._conn.execute(
                    "SELECT * FROM revocations WHERE owner_id=? AND kind='window'"
                    " AND (target_id=? OR target_id='*') ORDER BY id",
                    (owner_id, target_id),
                )
            return list(cur)

    # ---------------------------------------------------------------- audit
    @staticmethod
    def write_audit_tx(
        conn: sqlite3.Connection,
        ts: str,
        actor_id: str,
        action: str,
        result: str,
        request_id: str,
        details: dict[str, Any],
    ) -> None:
        conn.execute(
            "INSERT INTO audit_log(ts, actor_id, action, result, request_id, details)"
            " VALUES (?,?,?,?,?,?)",
            (ts, actor_id, action, result, request_id, json.dumps(details, sort_keys=True)),
        )

    def write_audit(
        self,
        ts: str,
        actor_id: str,
        action: str,
        result: str,
        request_id: str,
        details: dict[str, Any],
    ) -> None:
        with self.transaction() as conn:
            self.write_audit_tx(conn, ts, actor_id, action, result, request_id, details)

    def list_audit(
        self, actor_id: str | None = None, action: str | None = None, limit: int = 200
    ) -> list[sqlite3.Row]:
        clauses: list[str] = []
        params: list[Any] = []
        if actor_id:
            clauses.append("actor_id=?")
            params.append(actor_id)
        if action:
            clauses.append("action=?")
            params.append(action)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._lock:
            return list(
                self._conn.execute(
                    f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?", params
                )
            )

    # ---------------------------------------------------------------- nonces
    def check_and_store_nonce(self, nonce: str, seen_at: str) -> bool:
        """Return True if fresh (and record it), False if already seen."""
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO nonces(nonce, seen_at) VALUES (?,?)", (nonce, seen_at)
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def purge_nonces(self, before_ts: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM nonces WHERE seen_at < ?", (before_ts,))

    # ----------------------------------------------------------- idempotency
    def store_idempotent(
        self, idem_key: str, actor_id: str, created_at: str, status_code: int, body: str
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO idempotency(idem_key, actor_id, created_at,"
                " status_code, body) VALUES (?,?,?,?,?)",
                (idem_key, actor_id, created_at, status_code, body),
            )

    def get_idempotent(self, idem_key: str) -> sqlite3.Row | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM idempotency WHERE idem_key=?", (idem_key,)
            )
            return cur.fetchone()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

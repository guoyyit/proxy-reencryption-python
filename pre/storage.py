"""Durable SQLite-backed storage with crash-recovery semantics.

Durability model
----------------
* The database runs in WAL mode with ``synchronous=FULL``; every logical
  state change is committed inside one SQLite transaction, which is atomic
  on disk.  A process crash therefore cannot leave partial writes.
* Re-encryption requests are idempotent through a client supplied request id.
  The first transformation's result is stored; a retried (duplicate) request
  returns the stored output and is recorded as a replay in the audit log, so a
  request interrupted by a crash is applied at most once.
* Delegations carry an explicit monotonically increasing key version, so
  rotation and concurrent transformations always resolve to one definite
  version (enforced by a unique constraint and transactional locking).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id      TEXT PRIMARY KEY,
    public_key   BLOB NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS delegations (
    delegator   TEXT NOT NULL,
    delegatee   TEXT NOT NULL,
    version     INTEGER NOT NULL,
    rekey       BLOB NOT NULL,
    created_at  REAL NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    revoked_at  REAL,
    revoke_not_before REAL,
    PRIMARY KEY (delegator, delegatee, version)
);

CREATE TABLE IF NOT EXISTS ciphertext_revocations (
    delegator  TEXT NOT NULL,
    ciphertext_id TEXT NOT NULL,
    delegatee TEXT,
    revoked_at REAL NOT NULL,
    PRIMARY KEY (delegator, ciphertext_id)
);

CREATE TABLE IF NOT EXISTS transforms (
    request_id   TEXT PRIMARY KEY,
    delegator    TEXT NOT NULL,
    delegatee    TEXT NOT NULL,
    version      INTEGER NOT NULL,
    ciphertext_id TEXT,
    result       BLOB,
    status       TEXT NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    delegator   TEXT,
    delegatee   TEXT,
    version     INTEGER,
    request_id  TEXT,
    detail      TEXT NOT NULL,
    result      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_del_lookup
    ON delegations(delegator, delegatee, revoked, version);
"""


class Storage:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._conn:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.commit()
            self._conn.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Serialize writers and expose an atomic transaction boundary."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # -- users ------------------------------------------------------------

    def create_user(self, user_id: str, public_key: bytes) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO users(user_id, public_key, created_at) VALUES (?,?,?)",
                (user_id, public_key, time.time()),
            )

    def get_user(self, user_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM users WHERE user_id=?", (user_id,)
            ).fetchone()

    # -- audit ------------------------------------------------------------

    def append_audit(
        self,
        actor: str,
        action: str,
        detail: str,
        result: str,
        delegator: str | None = None,
        delegatee: str | None = None,
        version: int | None = None,
        request_id: str | None = None,
    ) -> int:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT INTO audit_log(ts, actor, action, delegator, "
                "delegatee, version, request_id, detail, result) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    time.time(), actor, action, delegator, delegatee,
                    version, request_id, detail, result,
                ),
            )
            return int(cur.lastrowid)

    def list_audit(
        self, limit: int = 200, actor: str | None = None
    ) -> list[sqlite3.Row]:
        with self._lock:
            if actor is not None:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log WHERE actor=? "
                    "ORDER BY id DESC LIMIT ?",
                    (actor, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return list(rows)

    # -- delegations / rotation ------------------------------------------

    def latest_delegation_version(self, delegator: str, delegatee: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM delegations "
                "WHERE delegator=? AND delegatee=?",
                (delegator, delegatee),
            ).fetchone()
            return int(row["v"])

    def insert_delegation(
        self, delegator: str, delegatee: str, version: int, rekey: bytes
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO delegations(delegator, delegatee, version, "
                "rekey, created_at, revoked) VALUES (?,?,?,?,?,0)",
                (delegator, delegatee, version, rekey, time.time()),
            )

    def get_delegation_version(
        self, delegator: str, delegatee: str, version: int
    ) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM delegations WHERE delegator=? AND delegatee=? "
                "AND version=?",
                (delegator, delegatee, version),
            ).fetchone()

    def get_active_delegation(
        self, delegator: str, delegatee: str
    ) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM delegations WHERE delegator=? AND delegatee=? "
                "AND revoked=0 ORDER BY version DESC LIMIT 1",
                (delegator, delegatee),
            ).fetchone()

    def revoke_delegation(
        self,
        delegator: str,
        delegatee: str,
        version: int | None = None,
        not_before: float | None = None,
    ) -> bool:
        """Revoke a version (default: the latest) or schedule a time-window
        revocation starting at ``not_before`` (epoch seconds)."""
        with self.transaction() as conn:
            if version is None:
                row = conn.execute(
                    "SELECT version FROM delegations WHERE delegator=? "
                    "AND delegatee=? ORDER BY version DESC LIMIT 1",
                    (delegator, delegatee),
                ).fetchone()
                if row is None:
                    return False
                version = int(row["version"])
            cur = conn.execute(
                "UPDATE delegations SET revoked=1, revoked_at=?, "
                "revoke_not_before=? WHERE delegator=? AND delegatee=? "
                "AND version=? AND revoked=0",
                (
                    time.time() if not_before is None else None,
                    not_before,
                    delegator,
                    delegatee,
                    version,
                ),
            )
            return cur.rowcount == 1

    def delegation_usable(
        self,
        delegator: str,
        delegatee: str,
        version: int,
        now: float,
        ciphertext_id: str | None = None,
    ) -> tuple[bool, str]:
        """Decide whether a transform is allowed right now."""
        if ciphertext_id is not None:
            row = self._conn_cipher_revoked(delegator, ciphertext_id, delegatee)
            if row is not None:
                return False, "ciphertext revoked"
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM delegations WHERE delegator=? AND delegatee=? "
                "AND version=?",
                (delegator, delegatee, version),
            ).fetchone()
        if row is None:
            return False, "delegation version not found"
        if row["revoked"] == 1:
            if row["revoke_not_before"] is not None:
                if now >= float(row["revoke_not_before"]):
                    return False, "time-window revocation active"
                return True, "ok"
            return False, "delegation revoked"
        return True, "ok"

    def _conn_cipher_revoked(
        self, delegator: str, ciphertext_id: str, delegatee: str | None
    ) -> sqlite3.Row | None:
        with self._lock:
            if delegatee is None:
                return self._conn.execute(
                    "SELECT * FROM ciphertext_revocations WHERE delegator=? "
                    "AND ciphertext_id=?",
                    (delegator, ciphertext_id),
                ).fetchone()
            return self._conn.execute(
                "SELECT * FROM ciphertext_revocations WHERE delegator=? "
                "AND ciphertext_id=? AND (delegatee IS NULL OR delegatee=?)",
                (delegator, ciphertext_id, delegatee),
            ).fetchone()

    def revoke_ciphertext(
        self, delegator: str, ciphertext_id: str, delegatee: str | None = None
    ) -> bool:
        with self.transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO ciphertext_revocations"
                "(delegator, ciphertext_id, delegatee, revoked_at) "
                "VALUES (?,?,?,?)",
                (delegator, ciphertext_id, delegatee, time.time()),
            )
            return cur.rowcount == 1

    # -- idempotent transforms -------------------------------------------

    def get_transform(self, request_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM transforms WHERE request_id=?", (request_id,)
            ).fetchone()

    def save_transform(
        self,
        request_id: str,
        delegator: str,
        delegatee: str,
        version: int,
        ciphertext_id: str | None,
        result: bytes,
        status: str = "done",
        conn: sqlite3.Connection | None = None,
    ) -> None:
        def _insert(c: sqlite3.Connection) -> None:
            c.execute(
                "INSERT OR IGNORE INTO transforms(request_id, delegator, "
                "delegatee, version, ciphertext_id, result, status, "
                "created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    request_id, delegator, delegatee, version,
                    ciphertext_id, result, status, time.time(),
                ),
            )

        if conn is not None:
            _insert(conn)
        else:
            with self.transaction() as owned:
                _insert(owned)

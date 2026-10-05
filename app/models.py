"""Typed records mirroring the SQLite schema (documentation / typing aid).

Runtime queries return ``sqlite3.Row``; these frozen dataclasses describe the
shape of each persisted record for readers and future typed adapters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class User:
    user_id: str
    verify_key: str
    pub_key: str
    created_at: str


@dataclass(frozen=True)
class Delegation:
    id: int
    owner_id: str
    delegatee_id: str
    current_version: int
    created_at: str
    revoked_at: str | None
    revoke_reason: str | None


@dataclass(frozen=True)
class RekeyVersion:
    id: int
    delegation_id: int
    version: int
    rk_json: str
    created_at: str


@dataclass(frozen=True)
class CiphertextRecord:
    id: int
    ciphertext_id: str
    owner_id: str
    enc_version: int
    data_hash: str
    raw_ref: str
    created_at: str
    revoked_at: str | None


@dataclass(frozen=True)
class AuditRecord:
    id: int
    ts: str
    actor_id: str
    action: str
    result: str
    request_id: str
    details: str

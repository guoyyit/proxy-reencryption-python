"""Revocation policy: per-ciphertext and time-window granularity.

Semantics:
* A per-ciphertext revocation permanently blocks conversion of that one
  ciphertext. Already completed conversions are untouched (nothing is recalled).
* Time-window revocations block conversion only while the current instant is
  inside [not_before, not_after]. Open endpoints (``None``) are allowed. Once a
  window passes, conversion becomes available again automatically.
* A delegation-level permanent revocation supersedes every window.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class WindowRow(Protocol):
    def __getitem__(self, key: str) -> Any: ...


@dataclass
class Window:
    target_id: str
    not_before: datetime | None
    not_after: datetime | None

    @classmethod
    def from_row(cls, row: WindowRow) -> "Window":
        return cls(
            target_id=str(row["target_id"]),
            not_before=parse_iso(row["not_before"]) if row["not_before"] else None,
            not_after=parse_iso(row["not_after"]) if row["not_after"] else None,
        )

    def covers(self, target_id: str) -> bool:
        return self.target_id == "*" or self.target_id == target_id

    def active_at(self, moment: datetime) -> bool:
        if self.not_before is not None and moment < self.not_before:
            return False
        if self.not_after is not None and moment > self.not_after:
            return False
        return True


def active_window(
    windows: list[Window],
    target_id: str,
    moment: datetime | None = None,
) -> Window | None:
    moment = moment or utc_now()
    for window in windows:
        if window.covers(target_id) and window.active_at(moment):
            return window
    return None


@dataclass
class RevocationDecision:
    allowed: bool
    reason_code: str | None = None
    detail: str | None = None


def evaluate_conversion(
    *,
    delegation_revoked: bool,
    ciphertext_revoked: bool,
    windows: list[Window],
    target_id: str,
    moment: datetime | None = None,
) -> RevocationDecision:
    if delegation_revoked:
        return RevocationDecision(False, "delegation_revoked", "delegation is permanently revoked")
    if ciphertext_revoked:
        return RevocationDecision(False, "ciphertext_revoked", "ciphertext has been revoked")
    window = active_window(windows, target_id, moment)
    if window is not None:
        return RevocationDecision(False, "revocation_window_active", "inside an active revocation window")
    return RevocationDecision(True)

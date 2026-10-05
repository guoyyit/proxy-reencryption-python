"""Business logic over durable storage and the PRE crypto layer."""

from __future__ import annotations

import time

from . import auth, crypto
from .errors import (
    AuthError,
    ConflictError,
    NotFoundError,
    RevokedError,
)
from .storage import Storage


class Service:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    # -- users ------------------------------------------------------------

    def register_user(self, user_id: str, public_key: bytes) -> None:
        try:
            crypto.PublicKey(public_key)
            g1, g2 = public_key[:97], public_key[97:]
            from . import bls12_381 as curve

            curve.g1_decode(g1)
            curve.g2_decode(g2)
        except Exception as exc:  # malformed/invalid public key
            from .errors import FormatError

            raise FormatError("invalid public key") from exc
        try:
            self.storage.create_user(user_id, public_key)
        except Exception as exc:
            raise ConflictError(f"user {user_id!r} already exists") from exc
        self.storage.append_audit(user_id, "register", "self", "ok")

    def _user(self, user_id: str):
        row = self.storage.get_user(user_id)
        if row is None:
            raise NotFoundError(f"unknown user {user_id!r}")
        return row

    def authenticate(
        self,
        user_id: str,
        method: str,
        path: str,
        timestamp: float,
        nonce: str,
        body: bytes,
        signature: bytes,
    ) -> None:
        row = self._user(user_id)
        auth.check_timestamp(timestamp)
        message = auth.canonical_message(method, path, timestamp, nonce, body)
        if not auth.verify(row["public_key"][:97], message, signature):
            self.storage.append_audit(
                user_id, method, f"path={path}", "denied"
            )
            raise AuthError("signature verification failed")

    # -- delegation -------------------------------------------------------

    def create_delegation(
        self, delegator: str, delegatee: str, rekey: bytes
    ) -> int:
        """Only the delegator calls this (authentication enforced at API).

        Returns the new key version.
        """
        self._user(delegator)
        self._user(delegatee)
        try:
            crypto.ReEncryptionKey(rekey)
            from . import bls12_381 as curve

            curve.g2_decode(rekey)
        except Exception as exc:
            from .errors import FormatError

            raise FormatError("invalid re-encryption key") from exc
        version = self.storage.latest_delegation_version(delegator, delegatee) + 1
        self.storage.insert_delegation(delegator, delegatee, version, rekey)
        self.storage.append_audit(
            delegator,
            "create_delegation",
            f"{delegator}->{delegatee}",
            "ok",
            delegator=delegator,
            delegatee=delegatee,
            version=version,
        )
        return version

    def rotate_rekey(
        self, delegator: str, delegatee: str, new_rekey: bytes
    ) -> int:
        """Insert a new key version; old versions remain for audit but are no
        longer active for new transforms."""
        return self.create_delegation(delegator, delegatee, new_rekey)

    def revoke(
        self,
        delegator: str,
        delegatee: str,
        version: int | None = None,
        not_before: float | None = None,
    ) -> int:
        target_version = version
        if target_version is None:
            target_version = self.storage.latest_delegation_version(
                delegator, delegatee
            )
            if target_version == 0:
                raise NotFoundError("no delegation to revoke")
        changed = self.storage.revoke_delegation(
            delegator, delegatee, version=target_version, not_before=not_before
        )
        if not changed:
            raise ConflictError("delegation already revoked or missing")
        kind = "time_window" if not_before is not None else "full"
        self.storage.append_audit(
            delegator,
            "revoke_delegation",
            f"{kind} {delegator}->{delegatee} v{target_version}",
            "ok",
            delegator=delegator,
            delegatee=delegatee,
            version=target_version,
        )
        return target_version

    def revoke_ciphertext(
        self, delegator: str, ciphertext_id: str, delegatee: str | None = None
    ) -> None:
        self.storage.revoke_ciphertext(delegator, ciphertext_id, delegatee)
        self.storage.append_audit(
            delegator,
            "revoke_ciphertext",
            f"{delegator}:{ciphertext_id}",
            "ok",
            delegator=delegator,
            delegatee=delegatee,
        )

    # -- transform --------------------------------------------------------

    def transform(
        self,
        request_id: str,
        delegator: str,
        delegatee: str,
        ciphertext: bytes,
        ciphertext_id: str | None = None,
        pin_version: int | None = None,
    ) -> bytes:
        """Perform an idempotent, version-pinned re-encryption.

        A concurrent rotation never produces a partially applied result: the
        version is read and the transform executed within one serialized
        critical section, and retries with the same ``request_id`` return
        the stored result.
        """
        existing = self.storage.get_transform(request_id)
        if existing is not None:
            self.storage.append_audit(
                "proxy",
                "transform",
                "duplicate request replay",
                "replay",
                delegator=delegator,
                delegatee=delegatee,
                request_id=request_id,
            )
            return bytes(existing["result"])

        self._user(delegator)
        self._user(delegatee)
        try:
            ct = crypto.Ciphertext(ciphertext)
            # Validate structure before touching delegation state so malformed
            # inputs cannot be reported as revocation/conflict errors.
            if ciphertext.startswith(b"PRE1"):
                crypto._parse_level1(ciphertext)
            else:
                crypto._parse_level2(ciphertext)
        except Exception as exc:
            from .errors import FormatError

            raise FormatError("malformed ciphertext") from exc

        with self.storage.transaction():
            conn = self.storage._conn
            if pin_version is None:
                row = conn.execute(
                    "SELECT * FROM delegations WHERE delegator=? AND "
                    "delegatee=? AND (revoked=0 OR revoke_not_before IS NOT "
                    "NULL) ORDER BY version DESC LIMIT 1",
                    (delegator, delegatee),
                ).fetchone()
                if row is None:
                    raise RevokedError("no active delegation")
                if row["revoked"] == 1 and time.time() >= float(
                    row["revoke_not_before"]
                ):
                    raise RevokedError("time-window revocation active")
                version = int(row["version"])
            else:
                version = pin_version
                row = conn.execute(
                    "SELECT * FROM delegations WHERE delegator=? AND "
                    "delegatee=? AND version=?",
                    (delegator, delegatee, version),
                ).fetchone()
                if row is None:
                    raise RevokedError("delegation version not found")
            now = time.time()
            if ciphertext_id is not None:
                revoked_ct = conn.execute(
                    "SELECT 1 FROM ciphertext_revocations WHERE delegator=? "
                    "AND ciphertext_id=? AND (delegatee IS NULL OR delegatee=?)",
                    (delegator, ciphertext_id, delegatee),
                ).fetchone()
                if revoked_ct is not None:
                    ok, reason = False, "ciphertext revoked"
                else:
                    ok, reason = True, "ok"
            else:
                ok, reason = True, "ok"
            if ok:
                if row["revoked"] == 1:
                    nbf = row["revoke_not_before"]
                    if nbf is None or now >= float(nbf):
                        ok, reason = False, (
                            "delegation revoked"
                            if nbf is None
                            else "time-window revocation active"
                        )
            if not ok:
                conn.execute(
                    "INSERT INTO audit_log(ts, actor, action, delegator, "
                    "delegatee, version, request_id, detail, result) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        time.time(), "proxy", "transform", delegator,
                        delegatee, version, request_id, reason, "denied",
                    ),
                )
                raise RevokedError(reason)
            rk = crypto.ReEncryptionKey(bytes(row["rekey"]))
            try:
                transformed = crypto.re_encrypt(rk, ct)
            except Exception as exc:
                from .errors import FormatError

                raise FormatError(str(exc)) from exc
            result = transformed.raw
            self.storage.save_transform(
                request_id,
                delegator,
                delegatee,
                version,
                ciphertext_id,
                result,
                conn=conn,
            )
        self.storage.append_audit(
            "proxy",
            "transform",
            f"v{version} ct={ciphertext_id}",
            "ok",
            delegator=delegator,
            delegatee=delegatee,
            version=version,
            request_id=request_id,
        )
        return result

    def audit_trail(self, limit: int = 200, actor: str | None = None):
        return [dict(row) for row in self.storage.list_audit(limit, actor)]

"""Business logic orchestrating crypto, storage, revocation and audit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from app import crypto, revocation
from app.errors import (
    CiphertextRevokedError,
    ConflictError,
    ForbiddenError,
    MalformedCiphertextError,
    NotFoundError,
    RevocationWindowActiveError,
    RevokedError,
    StaleVersionError,
    ValidationError,
)
from app.revocation import Window, evaluate_conversion, to_iso, utc_now
from app.storage import Store

PROXY_ACTOR = "proxy"


@dataclass
class PREService:
    store: Store

    # ------------------------------------------------------------------ users
    def register_user(
        self,
        *,
        user_id: str,
        verify_key: str,
        public_key: str,
        request_id: str,
    ) -> dict[str, Any]:
        if not user_id or len(user_id) > 128:
            raise ValidationError("user_id required (max 128 chars)")
        # public key must parse and match the declared scheme before storing
        crypto.deserialize_public_key(public_key)
        if self.store.get_user(user_id) is not None:
            raise ConflictError("user already registered")
        created = to_iso(utc_now())
        self.store.create_user(user_id, verify_key, public_key, created)
        self.store.write_audit(
            to_iso(utc_now()), user_id, "register", "success", request_id, {}
        )
        return {"user_id": user_id, "created_at": created}

    def _require_user(self, user_id: str) -> Any:
        row = self.store.get_user(user_id)
        if row is None:
            raise NotFoundError(f"unknown user: {user_id}")
        return row

    # ------------------------------------------------------------- delegations
    def create_delegation(
        self,
        *,
        owner_id: str,
        delegatee_id: str,
        rk_json: str,
        request_id: str,
    ) -> dict[str, Any]:
        if owner_id == delegatee_id:
            raise ValidationError("cannot delegate to yourself")
        owner = self._require_user(owner_id)
        delegatee = self._require_user(delegatee_id)
        if self.store.get_delegation_by_pair(owner_id, delegatee_id) is not None:
            raise ConflictError("delegation already exists")
        # the re-encryption key must be well formed for exactly these two users
        pk_owner = crypto.deserialize_public_key(owner["pub_key"])
        pk_delegatee = crypto.deserialize_public_key(delegatee["pub_key"])
        rk = crypto.deserialize_rekey(rk_json)
        if not crypto.verify_rekey(pk_owner, pk_delegatee, rk):
            raise ValidationError("re-encryption key failed public well-formedness check")
        now = to_iso(utc_now())
        with self.store.transaction() as conn:
            delegation_id = conn.execute(
                "INSERT INTO delegations(owner_id, delegatee_id, current_version, created_at)"
                " VALUES (?,?,1,?)",
                (owner_id, delegatee_id, now),
            ).lastrowid
            conn.execute(
                "INSERT INTO rekey_versions(delegation_id, version, rk_json, created_at)"
                " VALUES (?,?,?,?)",
                (delegation_id, 1, rk_json, now),
            )
            Store.write_audit_tx(
                conn, now, owner_id, "create_delegation", "success", request_id,
                {"delegation_id": delegation_id, "delegatee_id": delegatee_id, "version": 1},
            )
        return {
            "delegation_id": delegation_id,
            "owner_id": owner_id,
            "delegatee_id": delegatee_id,
            "version": 1,
            "created_at": now,
        }

    def rotate_rekey(
        self,
        *,
        owner_id: str,
        delegatee_id: str,
        rk_json: str,
        request_id: str,
    ) -> dict[str, Any]:
        owner = self._require_user(owner_id)
        delegatee = self._require_user(delegatee_id)
        delegation = self.store.get_delegation_by_pair(owner_id, delegatee_id)
        if delegation is None:
            raise NotFoundError("delegation not found")
        pk_owner = crypto.deserialize_public_key(owner["pub_key"])
        pk_delegatee = crypto.deserialize_public_key(delegatee["pub_key"])
        rk = crypto.deserialize_rekey(rk_json)
        if not crypto.verify_rekey(pk_owner, pk_delegatee, rk):
            raise ValidationError("rotated re-encryption key failed well-formedness check")
        delegation_id = int(delegation["id"])
        now = to_iso(utc_now())
        # one transaction: the new key version and the pointer flip atomically
        with self.store.transaction() as conn:
            # re-read under the write lock so concurrent rotations allocate
            # distinct, monotonic versions (no duplicate-key torn state)
            locked = conn.execute(
                "SELECT current_version FROM delegations WHERE id=?", (delegation_id,)
            ).fetchone()
            new_version = int(locked["current_version"]) + 1
            conn.execute(
                "INSERT INTO rekey_versions(delegation_id, version, rk_json, created_at)"
                " VALUES (?,?,?,?)",
                (delegation_id, new_version, rk_json, now),
            )
            conn.execute(
                "UPDATE delegations SET current_version=? WHERE id=?",
                (new_version, delegation_id),
            )
            Store.write_audit_tx(
                conn, now, owner_id, "rotate_rekey", "success", request_id,
                {"delegation_id": delegation_id, "version": new_version},
            )
        return {
            "delegation_id": delegation_id,
            "version": new_version,
            "rotated_at": now,
        }

    # ------------------------------------------------------------ ciphertexts
    def register_ciphertext(
        self,
        *,
        owner_id: str,
        ciphertext_id: str | None,
        ciphertext: str,
        request_id: str,
    ) -> dict[str, Any]:
        self._require_user(owner_id)
        parsed = crypto.deserialize_ciphertext(ciphertext)
        if not isinstance(parsed, crypto.LevelTwoCiphertext):
            raise MalformedCiphertextError("only level-2 (owner-directed) ciphertexts can be registered")
        ciphertext_id = ciphertext_id or f"ct-{uuid4()}"
        existing = self.store.get_ciphertext(ciphertext_id)
        if existing is not None:
            if existing["owner_id"] != owner_id:
                raise ForbiddenError("ciphertext id owned by another user")
            if existing["raw_ref"] != ciphertext:
                raise ConflictError("ciphertext id already used with different content")
            return {
                "ciphertext_id": ciphertext_id,
                "owner_id": owner_id,
                "enc_version": int(existing["enc_version"]),
                "registered_at": existing["created_at"],
            }
        import hashlib

        data_hash = hashlib.sha256(ciphertext.encode()).hexdigest()
        now = to_iso(utc_now())
        self.store.register_ciphertext(
            ciphertext_id, owner_id, 1, data_hash, ciphertext, now
        )
        self.store.write_audit(
            now, owner_id, "register_ciphertext", "success", request_id,
            {"ciphertext_id": ciphertext_id},
        )
        return {
            "ciphertext_id": ciphertext_id,
            "owner_id": owner_id,
            "enc_version": 1,
            "registered_at": now,
        }

    def revoke_ciphertext(
        self,
        *,
        owner_id: str,
        ciphertext_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        record = self.store.get_ciphertext(ciphertext_id)
        if record is None:
            raise NotFoundError("ciphertext not registered")
        if record["owner_id"] != owner_id:
            self._denied_audit(owner_id, "revoke_ciphertext", request_id, ciphertext_id)
            raise ForbiddenError("only the data owner can revoke their ciphertext")
        now = to_iso(utc_now())
        with self.store.transaction() as conn:
            if record["revoked_at"] is None:
                conn.execute(
                    "UPDATE ciphertexts SET revoked_at=? WHERE ciphertext_id=?",
                    (now, ciphertext_id),
                )
            Store.write_audit_tx(
                conn, now, owner_id, "revoke_ciphertext", "success", request_id,
                {"ciphertext_id": ciphertext_id},
            )
        return {"ciphertext_id": ciphertext_id, "revoked_at": now}

    def add_revocation_window(
        self,
        *,
        owner_id: str,
        delegatee_id: str | None,
        target: str,
        not_before: str | None,
        not_after: str | None,
        reason: str,
        request_id: str,
    ) -> dict[str, Any]:
        self._require_user(owner_id)
        if not_before is not None:
            revocation.parse_iso(not_before)
        if not_after is not None:
            revocation.parse_iso(not_after)
        if not_before and not_after and revocation.parse_iso(not_before) > revocation.parse_iso(not_after):
            raise ValidationError("not_before must not be after not_after")
        window_id = uuid4().hex
        now = to_iso(utc_now())
        self.store.add_revocation(
            "window", owner_id, target, not_before, not_after, reason, now
        )
        self.store.write_audit(
            now, owner_id, "add_revocation_window", "success", request_id,
            {"window_id": window_id, "target": target, "delegatee_id": delegatee_id},
        )
        return {
            "window_id": window_id,
            "target": target,
            "not_before": not_before,
            "not_after": not_after,
            "created_at": now,
        }

    # ------------------------------------------------------------- re-encrypt
    def _denied_audit(
        self, actor_id: str, action: str, request_id: str, target: str
    ) -> None:
        self.store.write_audit(
            to_iso(utc_now()), actor_id, action, "denied", request_id, {"target": target}
        )

    def revoke_delegation(
        self,
        *,
        owner_id: str,
        delegatee_id: str,
        reason: str,
        request_id: str,
    ) -> dict[str, Any]:
        delegation = self.store.get_delegation_by_pair(owner_id, delegatee_id)
        if delegation is None:
            raise NotFoundError("delegation not found")
        now = to_iso(utc_now())
        with self.store.transaction() as conn:
            if delegation["revoked_at"] is None:
                conn.execute(
                    "UPDATE delegations SET revoked_at=?, revoke_reason=? WHERE id=?",
                    (now, reason, int(delegation["id"])),
                )
            Store.write_audit_tx(
                conn, now, owner_id, "revoke_delegation", "success", request_id,
                {"delegation_id": int(delegation["id"])},
            )
        return {"delegation_id": int(delegation["id"]), "revoked_at": now}

    def reencrypt(
        self,
        *,
        owner_id: str,
        delegatee_id: str,
        ciphertext_id: str,
        request_id: str,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        """Convert one owner ciphertext to the delegatee under the current rk.

        Version pinning and revocation checks happen inside a single serialized
        transaction, so a request racing a rotation is served entirely by one
        fixed key version: never an old key on a post-rotation ciphertext and
        never a partially applied new key.
        """
        delegation = self.store.get_delegation_by_pair(owner_id, delegatee_id)
        if delegation is None:
            self._denied_audit(PROXY_ACTOR, "reencrypt", request_id, ciphertext_id)
            raise NotFoundError("delegation not found")
        record = self.store.get_ciphertext(ciphertext_id)
        if record is None:
            raise NotFoundError("ciphertext not registered")
        if record["owner_id"] != owner_id:
            self._denied_audit(PROXY_ACTOR, "reencrypt", request_id, ciphertext_id)
            raise ForbiddenError("ciphertext does not belong to the delegating owner")

        now_dt = utc_now()
        now = to_iso(now_dt)
        denial: dict[str, Any] | None = None
        result_payload: dict[str, Any] = {}
        with self.store.abortable_transaction() as (conn, state):
            locked = conn.execute(
                "SELECT * FROM delegations WHERE id=?", (int(delegation["id"]),)
            ).fetchone()
            locked_ct = conn.execute(
                "SELECT * FROM ciphertexts WHERE ciphertext_id=?", (ciphertext_id,)
            ).fetchone()
            window_rows = conn.execute(
                "SELECT * FROM revocations WHERE owner_id=? AND kind='window'"
                " AND (target_id=? OR target_id=? OR target_id='*') ORDER BY id",
                (owner_id, delegatee_id, ciphertext_id),
            ).fetchall()
            windows = []
            for row in window_rows:
                window = Window.from_row(row)
                if window.target_id == delegatee_id:
                    window = Window(ciphertext_id, window.not_before, window.not_after)
                windows.append(window)
            decision = evaluate_conversion(
                delegation_revoked=locked["revoked_at"] is not None,
                ciphertext_revoked=locked_ct["revoked_at"] is not None,
                windows=windows,
                target_id=ciphertext_id,
                moment=now_dt,
            )

            def deny(code: str, detail: str, **extra: Any) -> None:
                nonlocal denial
                details = {"ciphertext_id": ciphertext_id, "reason": code, **extra}
                denial = {"code": code, "detail": detail, "details": details}
                state["abort"] = True

            if not decision.allowed:
                deny(
                    decision.reason_code or "delegation_revoked",
                    decision.detail or decision.reason_code or "revoked",
                )
            else:
                version = int(locked["current_version"])
                if expected_version is not None and int(expected_version) != version:
                    deny(
                        "stale_reencryption_key_version",
                        f"request pinned to version {expected_version}, current is {version}",
                        expected=int(expected_version),
                        current=version,
                    )
                else:
                    rk_row = conn.execute(
                        "SELECT rk_json FROM rekey_versions"
                        " WHERE delegation_id=? AND version=?",
                        (int(locked["id"]), version),
                    ).fetchone()
                    if rk_row is None:
                        deny(
                            "conflict",
                            "current re-encryption key version is unavailable",
                        )
                    else:
                        rk = crypto.deserialize_rekey(rk_row["rk_json"])
                        ct_lvl2 = crypto.deserialize_ciphertext(locked_ct["raw_ref"])
                        transformed = crypto.re_encrypt(rk, ct_lvl2)
                        transformed_json = crypto.serialize_ciphertext(transformed)
                        Store.write_audit_tx(
                            conn, now, PROXY_ACTOR, "reencrypt", "success", request_id,
                            {
                                "ciphertext_id": ciphertext_id,
                                "owner_id": owner_id,
                                "delegatee_id": delegatee_id,
                                "version": version,
                            },
                        )
                        result_payload = {
                            "ciphertext_id": ciphertext_id,
                            "owner_id": owner_id,
                            "delegatee_id": delegatee_id,
                            "version": version,
                            "ciphertext": transformed_json,
                            "converted_at": now,
                        }

        if denial is not None:
            # business transaction was rolled back with no state change; write
            # the denial audit in its own committed transaction
            self.store.write_audit(
                now, PROXY_ACTOR, "reencrypt", "denied", request_id, denial["details"]
            )
            code = denial["code"]
            if code == "ciphertext_revoked":
                raise CiphertextRevokedError(denial["detail"])
            if code == "revocation_window_active":
                raise RevocationWindowActiveError(denial["detail"])
            if code == "stale_reencryption_key_version":
                raise StaleVersionError(denial["detail"])
            if code == "conflict":
                raise ConflictError(denial["detail"])
            raise RevokedError(denial["detail"])
        return result_payload

    # ------------------------------------------------------------------ audit
    def list_audit(
        self,
        *,
        requester_id: str,
        action: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        # everyone can read their own trail; only the owner can see audit rows
        # involving their delegations. We return rows for the requester only.
        rows = self.store.list_audit(actor_id=requester_id, action=action, limit=limit)
        proxy_rows: list[Any] = []
        if requester_id == PROXY_ACTOR:
            proxy_rows = self.store.list_audit(actor_id=PROXY_ACTOR, action=action, limit=limit)
        import json as _json

        def render(row: Any) -> dict[str, Any]:
            return {
                "id": row["id"],
                "ts": row["ts"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "result": row["result"],
                "request_id": row["request_id"],
                "details": _json.loads(row["details"]),
            }

        out = [render(r) for r in rows]
        out.extend(render(r) for r in proxy_rows if r["actor_id"] != requester_id)
        out.sort(key=lambda item: item["id"], reverse=True)
        return out[:limit]

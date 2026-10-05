"""Local client used by data owners and delegatees.

The private PRE key and the Ed25519 signing key never leave the client. The
re-encryption key is created locally by the data owner (it needs the owner's
private ``x1``) and only its public group-element form is sent to the proxy.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from app import auth, crypto


@dataclass
class KeyMaterial:
    user_id: str
    pre_secret_hex: str  # serialized crypto.SecretKey (kept client side)
    signing_private_hex: str
    signing_public_hex: str
    pre_public_json: str

    def to_dict(self) -> dict[str, str]:
        return {
            "user_id": self.user_id,
            "pre_secret": self.pre_secret_hex,
            "signing_private": self.signing_private_hex,
            "signing_public": self.signing_public_hex,
            "pre_public": self.pre_public_json,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "KeyMaterial":
        return cls(
            user_id=data["user_id"],
            pre_secret_hex=data["pre_secret"],
            signing_private_hex=data["signing_private_hex"],
            signing_public_hex=data["signing_public_hex"],
            pre_public_json=data["pre_public"],
        )


def create_key_material(user_id: str) -> KeyMaterial:
    sk, pk = crypto.generate_keypair()
    priv_hex, pub_hex = auth.generate_signing_keypair()
    return KeyMaterial(
        user_id=user_id,
        pre_secret_hex=crypto.serialize_secret_key(sk),
        signing_private_hex=priv_hex,
        signing_public_hex=pub_hex,
        pre_public_json=crypto.serialize_public_key(pk),
    )


class PREClient:
    def __init__(self, base_url: str, material: KeyMaterial) -> None:
        self.base_url = base_url.rstrip("/")
        self.material = material
        self._http = httpx.Client(timeout=30.0)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "PREClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------- keys
    def register(self) -> dict[str, Any]:
        body = {
            "user_id": self.material.user_id,
            "verify_key": self.material.signing_public_hex,
            "public_key": self.material.pre_public_json,
        }
        return self._signed("POST", "/users", body, authenticate_self=True)

    def _signed_headers(self, method: str, path: str, raw: bytes) -> dict[str, str]:
        signed = auth.sign_request(
            self.material.signing_private_hex, method, path, raw
        )
        return {"X-User-Id": self.material.user_id, **signed, "Content-Type": "application/json"}

    def _signed(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None,
        *,
        authenticate_self: bool = False,
        idem_key: str | None = None,
    ) -> dict[str, Any]:
        raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        headers = self._signed_headers(method, path, raw)
        # /users verifies against the verify key embedded in the body
        if authenticate_self:
            pass
        if idem_key:
            headers["X-Idempotency-Key"] = idem_key
        response = self._http.request(
            method, urljoin(self.base_url + "/", path.lstrip("/")), content=raw, headers=headers
        )
        response.raise_for_status()
        return response.json() if response.content else {}

    # ------------------------------------------------------------- PRE ops
    def make_re_encryption_key(
        self,
        delegatee_public_json: str,
        *,
        k_v: int | None = None,
    ) -> str:
        """Owner-side: create the (optionally versioned) re-encryption key."""
        sk = crypto.deserialize_secret_key(self.material.pre_secret_hex)
        pk_b = crypto.deserialize_public_key(delegatee_public_json)
        blinding = k_v if k_v is not None else crypto.random_blinding_scalar()
        rk = crypto.create_rekey(sk, pk_b, blinding)
        return crypto.serialize_rekey(rk)

    def create_delegation(self, delegatee_id: str, rk_json: str) -> dict[str, Any]:
        return self._signed(
            "POST", "/delegations", {"delegatee_id": delegatee_id, "re_encryption_key": rk_json}
        )

    def rotate(self, delegatee_id: str, rk_json: str, idem_key: str | None = None) -> dict[str, Any]:
        return self._signed(
            "POST", "/delegations/rotate",
            {"delegatee_id": delegatee_id, "re_encryption_key": rk_json},
            idem_key=idem_key,
        )

    def register_ciphertext(self, ciphertext_json: str, ciphertext_id: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"ciphertext": ciphertext_json}
        if ciphertext_id:
            body["ciphertext_id"] = ciphertext_id
        return self._signed("POST", "/ciphertexts", body)

    def revoke_ciphertext(self, ciphertext_id: str) -> dict[str, Any]:
        return self._signed("POST", "/revocations/ciphertext", {"ciphertext_id": ciphertext_id})

    def revoke_delegation(self, delegatee_id: str, reason: str = "") -> dict[str, Any]:
        return self._signed(
            "POST", "/delegations/revoke", {"delegatee_id": delegatee_id, "reason": reason}
        )

    def add_revocation_window(
        self,
        target: str,
        not_before: str | None,
        not_after: str | None,
        reason: str = "",
    ) -> dict[str, Any]:
        return self._signed(
            "POST", "/revocations/window",
            {
                "target": target,
                "delegatee_id": target if not target.startswith("ct-") else None,
                "not_before": not_before,
                "not_after": not_after,
                "reason": reason,
            },
        )

    def decrypt_delegated(self, ciphertext_json: str, associated_data_hex: str = "") -> bytes:
        sk = crypto.deserialize_secret_key(self.material.pre_secret_hex)
        ct = crypto.deserialize_ciphertext(ciphertext_json)
        if not isinstance(ct, crypto.LevelOneCiphertext):
            raise ValueError("delegated decryption expects a level-1 ciphertext")
        return crypto.decrypt_lvl1(sk, ct, bytes.fromhex(associated_data_hex))

    def decrypt_own(self, ciphertext_json: str, associated_data_hex: str = "") -> bytes:
        sk = crypto.deserialize_secret_key(self.material.pre_secret_hex)
        ct = crypto.deserialize_ciphertext(ciphertext_json)
        if not isinstance(ct, crypto.LevelTwoCiphertext):
            raise ValueError("owner decryption expects a level-2 ciphertext")
        return crypto.decrypt_lvl2(sk, ct, bytes.fromhex(associated_data_hex))

    def audit(self) -> dict[str, Any]:
        path = "/audit"
        headers = self._signed_headers("GET", path, b"")
        response = self._http.get(urljoin(self.base_url + "/", path.lstrip("/")), headers=headers)
        response.raise_for_status()
        return response.json()

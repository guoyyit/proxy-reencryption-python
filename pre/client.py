"""Local client SDK.

Key material never leaves the client: key generation, encryption,
decryption and re-encryption-key generation all run locally via
:mod:`pre.crypto`.  Only public keys, re-encryption keys, ciphertexts and
Schnorr signatures are exchanged with the HTTP service.
"""

from __future__ import annotations

import json
import time
import uuid

import httpx

from . import auth, crypto, schemas


class Client:
    def __init__(self, base_url: str, user_id: str, sk: crypto.SecretKey,
                 pk: crypto.PublicKey | None = None,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.user_id = user_id
        self.sk = sk
        self.pk = pk
        self._http = httpx.Client(base_url=self.base_url, transport=transport)

    def close(self) -> None:
        self._http.close()

    # -- crypto helpers (local) ------------------------------------------

    @staticmethod
    def keygen() -> tuple[crypto.SecretKey, crypto.PublicKey]:
        return crypto.keygen()

    def encrypt(self, recipient_pk: crypto.PublicKey, plaintext: bytes) -> bytes:
        return crypto.encrypt(recipient_pk, plaintext).raw

    def decrypt(self, ciphertext: bytes) -> bytes:
        return crypto.decrypt(self.sk, crypto.Ciphertext(ciphertext))

    def make_rekey(self, delegatee_pk: crypto.PublicKey) -> bytes:
        return crypto.make_rekey(self.sk, delegatee_pk).raw

    # -- http helpers -----------------------------------------------------

    def _signed_post(self, path: str, payload: dict) -> httpx.Response:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        nonce = uuid.uuid4().hex
        timestamp = time.time()
        message = auth.canonical_message("POST", path, timestamp, nonce, body)
        signature = auth.sign(self.sk.raw, message)
        headers = {
            "X-User": self.user_id,
            "X-Timestamp": str(int(timestamp)),
            "X-Nonce": nonce,
            "X-Signature": schemas.b64e(signature),
            "Content-Type": "application/json",
        }
        return self._http.post(path, content=body, headers=headers)

    def register(self) -> None:
        if self.pk is None:
            raise ValueError("public key required to register")
        r = self._http.post(
            "/users/register",
            json={"user_id": self.user_id, "public_key": schemas.b64e(self.pk.raw)},
        )
        r.raise_for_status()

    def create_delegation(self, delegatee: str, rekey: bytes) -> int:
        r = self._signed_post(
            "/delegations",
            {
                "delegator": self.user_id,
                "delegatee": delegatee,
                "rekey": schemas.b64e(rekey),
            },
        )
        r.raise_for_status()
        return int(r.json()["version"])

    def rotate_delegation(self, delegatee: str, new_rekey: bytes) -> int:
        r = self._signed_post(
            "/delegations/rotate",
            {
                "delegator": self.user_id,
                "delegatee": delegatee,
                "rekey": schemas.b64e(new_rekey),
            },
        )
        r.raise_for_status()
        return int(r.json()["version"])

    def revoke_delegation(
        self,
        delegatee: str,
        version: int | None = None,
        not_before: float | None = None,
    ) -> int:
        payload = {
            "delegator": self.user_id,
            "delegatee": delegatee,
            "version": version,
            "not_before": not_before,
        }
        r = self._signed_post("/delegations/revoke", payload)
        r.raise_for_status()
        return int(r.json()["version"])

    def revoke_ciphertext(
        self, ciphertext_id: str, delegatee: str | None = None
    ) -> None:
        r = self._signed_post(
            "/ciphertexts/revoke",
            {
                "delegator": self.user_id,
                "ciphertext_id": ciphertext_id,
                "delegatee": delegatee,
            },
        )
        r.raise_for_status()

    def transform(
        self,
        delegator: str,
        delegatee: str,
        ciphertext: bytes,
        ciphertext_id: str | None = None,
        pin_version: int | None = None,
        request_id: str | None = None,
    ) -> tuple[bytes, int, bool]:
        request_id = request_id or uuid.uuid4().hex
        r = self._http.post(
            "/transform",
            json={
                "request_id": request_id,
                "delegator": delegator,
                "delegatee": delegatee,
                "ciphertext": schemas.b64e(ciphertext),
                "ciphertext_id": ciphertext_id,
                "pin_version": pin_version,
            },
        )
        r.raise_for_status()
        data = r.json()
        return schemas.b64d(data["ciphertext"]), int(data["version"]), bool(
            data["replayed"]
        )

    def audit(self, limit: int = 200, actor: str | None = None) -> list[dict]:
        params: dict = {"limit": limit}
        if actor is not None:
            params["actor"] = actor
        r = self._http.get("/audit", params=params)
        r.raise_for_status()
        return list(r.json()["entries"])

"""HTTP request/response schemas.

Binary key material and ciphertexts travel as URL-safe base64 strings in
JSON bodies.  Signing headers (``X-User``, ``X-Timestamp``, ``X-Nonce``,
``X-Signature``) authenticate mutating requests.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


def b64e(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    import base64

    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


class RegisterRequest(BaseModel):
    user_id: str = Field(min_length=1, max_length=128)
    public_key: str


class DelegationRequest(BaseModel):
    delegator: str
    delegatee: str
    rekey: str


class RevokeRequest(BaseModel):
    delegator: str
    delegatee: str
    version: int | None = None
    not_before: float | None = None


class CiphertextRevokeRequest(BaseModel):
    delegator: str
    ciphertext_id: str
    delegatee: str | None = None


class TransformRequest(BaseModel):
    request_id: str = Field(min_length=1, max_length=128)
    delegator: str
    delegatee: str
    ciphertext: str
    ciphertext_id: str | None = None
    pin_version: int | None = None


class TransformResponse(BaseModel):
    request_id: str
    version: int
    ciphertext: str
    replayed: bool = False


class VersionResponse(BaseModel):
    delegator: str
    delegatee: str
    version: int


class AuditEntry(BaseModel):
    id: int
    ts: float
    actor: str
    action: str
    delegator: str | None
    delegatee: str | None
    version: int | None
    request_id: str | None
    detail: str
    result: str


class ErrorResponse(BaseModel):
    error: str
    code: str
    detail: str | None = None

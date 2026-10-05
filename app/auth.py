"""Request authentication using Ed25519 signatures.

Every mutating request is signed by the caller's Ed25519 key. The server stores
only the public verification key registered by the user.

Signature string (exact, newline separated)::

    METHOD \\n PATH \\n TIMESTAMP \\n NONCE \\n SHA256_HEX(BODY)

Headers (all required on authenticated routes)::

    X-User-Id, X-Timestamp (unix seconds), X-Nonce, X-Signature (hex)
"""

from __future__ import annotations

import hashlib
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.errors import UnauthorizedError

MAX_SKEW_SECONDS = 300


def generate_signing_keypair() -> tuple[str, str]:
    """Return (private_key_hex, public_key_hex) for client-side request signing."""
    private = Ed25519PrivateKey.generate()
    priv_hex = private.private_bytes_raw().hex()
    pub_hex = private.public_key().public_bytes_raw().hex()
    return priv_hex, pub_hex


def canonical_message(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")


def sign_request(
    private_key_hex: str,
    method: str,
    path: str,
    body: bytes,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    ts = timestamp if timestamp is not None else str(int(time.time()))
    nc = nonce if nonce is not None else hashlib.sha256(body + ts.encode()).hexdigest()[:32]
    message = canonical_message(method, path, ts, nc, body)
    signature = private.sign(message).hex()
    return {
        "X-Timestamp": ts,
        "X-Nonce": nc,
        "X-Signature": signature,
    }


def verify_signature(verify_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(verify_key_hex))
        public.verify(bytes.fromhex(signature_hex), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def authenticate_headers(
    headers: dict[str, str],
    method: str,
    path: str,
    body: bytes,
    verify_key_hex: str | None,
    *,
    now: float | None = None,
) -> str:
    """Validate headers and return the user id; raise UnauthorizedError otherwise."""
    user_id = headers.get("x-user-id") or headers.get("X-User-Id")
    timestamp = headers.get("x-timestamp") or headers.get("X-Timestamp")
    nonce = headers.get("x-nonce") or headers.get("X-Nonce")
    signature = headers.get("x-signature") or headers.get("X-Signature")
    if not all([user_id, timestamp, nonce, signature]):
        raise UnauthorizedError("missing authentication headers")
    try:
        ts_value = int(timestamp)
    except ValueError as exc:
        raise UnauthorizedError("timestamp must be unix seconds") from exc
    current = time.time() if now is None else now
    if abs(current - ts_value) > MAX_SKEW_SECONDS:
        raise UnauthorizedError("timestamp outside allowed skew")
    if verify_key_hex is None:
        raise UnauthorizedError("unknown user")
    message = canonical_message(method, path, timestamp, nonce, body)
    if not verify_signature(verify_key_hex, message, signature):
        raise UnauthorizedError("signature verification failed")
    return user_id

"""Request authentication via Schnorr signatures over BLS12-381 G1.

The service authorizes mutating requests using a signature created by the
user's PRE secret key.  A signed envelope binds the HTTP method, path, a
monotonic timestamp and a one-time nonce, so signatures cannot be replayed
and the acting identity is the registered public-key owner.
"""

from __future__ import annotations

import time

from . import bls12_381 as curve
from .errors import AuthError

SIG_TAG = b"pre-auth-v1"
DEFAULT_SKEW_SECONDS = 300


def signing_pubkey_g1(sk: bytes) -> bytes:
    a = _scalar(sk)
    return curve.g1_encode(curve.g1_generator_mul(a))


def _scalar(sk: bytes) -> int:
    if len(sk) != 32:
        raise AuthError("malformed signing key")
    return int.from_bytes(sk, "big") % curve.R


def challenge(pk_g1: bytes, message: bytes, commitment: bytes) -> int:
    return curve.hash_to_scalar(SIG_TAG, pk_g1, commitment, message)


def sign(sk: bytes, message: bytes) -> bytes:
    """Return ``commitment_g1 (97) || s scalar (32)``."""
    a = _scalar(sk)
    k = curve.random_scalar()
    r_point = curve.g1_generator_mul(k)
    pk_g1 = curve.g1_encode(curve.g1_generator_mul(a))
    commitment = curve.g1_encode(r_point)
    e = challenge(pk_g1, message, commitment)
    s = (k - e * a) % curve.R
    return commitment + s.to_bytes(32, "big")


def verify(pk_g1: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 97 + 32:
        return False
    commitment = signature[:97]
    s = int.from_bytes(signature[97:], "big")
    if s >= curve.R:
        return False
    try:
        r_point = curve.g1_decode(commitment)
        p_point = curve.g1_decode(pk_g1)
    except ValueError:
        return False
    e = challenge(pk_g1, message, commitment)
    lhs = curve.g1_generator_mul(s)
    rhs = curve.point_add(r_point, curve.point_mul(p_point, (-e) % curve.R))
    return curve.normalize_g1(lhs)[:2] == curve.normalize_g1(rhs)[:2]


def canonical_message(
    method: str,
    path: str,
    timestamp: float,
    nonce: str,
    body: bytes,
) -> bytes:
    return b"\x1f".join(
        [
            method.encode(),
            path.encode(),
            str(int(timestamp)).encode(),
            nonce.encode(),
            body,
        ]
    )


def check_timestamp(timestamp: float, skew: int = DEFAULT_SKEW_SECONDS) -> None:
    if abs(time.time() - float(timestamp)) > skew:
        raise AuthError("stale or future request timestamp")

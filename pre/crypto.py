"""Unidirectional, non-transferable proxy re-encryption (AFGH over BLS12-381).

This module implements the data-path cryptography.  Every private operation
(key generation, encryption, decryption, re-encryption-key generation) runs
locally on the data owner / recipient side.  The proxy only ever sees a
re-encryption key and ciphertexts and performs a pairing.

Protocol (Type-3 AFGH)
----------------------
Public parameters are the BLS12-381 generators ``g1`` (G1), ``g2`` (G2)
and ``Z = e(g1, g2)``.  A user with secret scalar ``a`` publishes
``pk1 = a*g1`` and ``pk2 = a*g2``.

* Re-encryption key A -> B:  ``rk = (1/a) * (b*g2) = g2**(b/a)``.
  Only A can create it (needs ``a``); it reveals neither ``a`` nor ``b``.
* Level-2 (re-encryptable) ciphertext for A:
  ``U = r*(a*g1) = g1**(a r)`` plus an authenticated DEM body keyed by
  ``K = KDF(Z**r)``.
* Re-encryption by the proxy (one pairing):
  ``V = e(U, rk) = Z**(b r)``; output is a level-1 ciphertext.
* A decrypts level 2 via ``K = KDF(e(U, g2)**(1/a))``.
* B decrypts level 1 via ``K = KDF(V**(1/b))``.

Security: the scheme is collusion safe in the standard AFGH sense — proxy
plus any delegatee cannot recover the delegator's secret scalar (DL/co-CDH
in the pairing groups), and level-1 ciphertexts cannot be re-encrypted
again.  Tampering is rejected because the DEM is an encrypt-then-MAC AEAD.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from . import bls12_381 as curve
from .errors import FormatError, TamperError


@dataclass(frozen=True)
class SecretKey:
    """Private scalar; must never leave the owner's machine."""

    raw: bytes


@dataclass(frozen=True)
class PublicKey:
    """Public key containing a G1 point and a G2 point (97 + 193 bytes)."""

    raw: bytes


@dataclass(frozen=True)
class ReEncryptionKey:
    """Delegation key; a single G2 point (193 bytes)."""

    raw: bytes


@dataclass(frozen=True)
class Ciphertext:
    """Versioned binary ciphertext envelope."""

    raw: bytes


_CT_LEVEL2 = b"PRE2"  # tag 0x02, re-encryptable
_CT_LEVEL1 = b"PRE1"  # tag 0x01, already transformed

_G1_LEN = 97
_G2_LEN = 193
_FP12_LEN = 576

# Z = e(g1, g2), a fixed public constant (computed once).
_Z = curve.pairing(curve.G2, curve.G1)


def keygen() -> tuple[SecretKey, PublicKey]:
    """Generate a fresh key pair."""
    a = curve.random_scalar()
    pk1 = curve.g1_generator_mul(a)
    pk2 = curve.g2_generator_mul(a)
    sk = SecretKey(a.to_bytes(32, "big"))
    pk = PublicKey(curve.g1_encode(pk1) + curve.g2_encode(pk2))
    return sk, pk


def _sk_scalar(sk: SecretKey) -> int:
    if len(sk.raw) != 32:
        raise FormatError("malformed secret key")
    return int.from_bytes(sk.raw, "big") % curve.R


def _pk_points(pk: PublicKey) -> tuple[curve.G1Point, curve.G2Point]:
    if len(pk.raw) != 97 + 193:
        raise FormatError("malformed public key")
    try:
        return curve.g1_decode(pk.raw[:97]), curve.g2_decode(pk.raw[97:])
    except ValueError as exc:
        raise FormatError("malformed public key") from exc


def _kdf(shared: curve.Fp12, context: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha384(
        b"pre-kdf-v1" + context + b"".join(c.to_bytes(48, "big") for c in shared)
    ).digest()
    return digest[:32], digest[32:]


def _dem_seal(key_enc: bytes, key_mac: bytes, aad: bytes, plaintext: bytes) -> bytes:
    # Encrypt-then-MAC stream cipher based on HMAC-SHA256 keystream.
    stream = bytearray()
    counter = 0
    while len(stream) < len(plaintext):
        stream += hmac.new(
            key_enc, counter.to_bytes(8, "big") + aad, hashlib.sha256
        ).digest()
        counter += 1
    body = bytes(p ^ k for p, k in zip(plaintext, stream))
    tag = hmac.new(key_mac, aad + body, hashlib.sha256).digest()
    return body + tag


def _dem_open(key_enc: bytes, key_mac: bytes, aad: bytes, blob: bytes) -> bytes:
    if len(blob) < 32:
        raise TamperError("ciphertext body too short")
    body, tag = blob[:-32], blob[-32:]
    expected = hmac.new(key_mac, aad + body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise TamperError("ciphertext authentication failed")
    stream = bytearray()
    counter = 0
    while len(stream) < len(body):
        stream += hmac.new(
            key_enc, counter.to_bytes(8, "big") + aad, hashlib.sha256
        ).digest()
        counter += 1
    return bytes(p ^ k for p, k in zip(body, stream))


def encrypt(pk: PublicKey, plaintext: bytes) -> Ciphertext:
    """Encrypt to a public key, producing a re-encryptable (level-2) ciphertext."""
    pk1, _ = _pk_points(pk)
    r = curve.random_scalar()
    u = curve.point_mul(pk1, r)  # g1**(a*r)
    aad = _CT_LEVEL2
    key_enc, key_mac = _kdf(curve.f12_pow(_Z, r), aad)
    blob = _dem_seal(key_enc, key_mac, aad, plaintext)
    return Ciphertext(aad + curve.g1_encode(u) + blob)


def _parse_level2(raw: bytes) -> tuple[curve.G1Point, bytes]:
    if not raw.startswith(_CT_LEVEL2):
        raise FormatError("not a level-2 ciphertext")
    rest = raw[len(_CT_LEVEL2):]
    if len(rest) < _G1_LEN:
        raise FormatError("truncated ciphertext header")
    try:
        u = curve.g1_decode(rest[:_G1_LEN])
    except ValueError as exc:
        raise FormatError("malformed ciphertext header") from exc
    return u, rest[_G1_LEN:]


def _parse_level1(raw: bytes) -> tuple[curve.Fp12, bytes]:
    if not raw.startswith(_CT_LEVEL1):
        raise FormatError("not a level-1 ciphertext")
    rest = raw[len(_CT_LEVEL1):]
    if len(rest) < _FP12_LEN:
        raise FormatError("truncated ciphertext header")
    v = tuple(
        int.from_bytes(rest[i * 48:(i + 1) * 48], "big") for i in range(12)
    )
    return v, rest[_FP12_LEN:]


def _fp12_encode(v: curve.Fp12) -> bytes:
    return b"".join(c.to_bytes(48, "big") for c in v)


def decrypt(sk: SecretKey, ct: Ciphertext) -> bytes:
    """Decrypt either a level-2 ciphertext as its owner or a level-1 one as
    the intended delegatee."""
    a = _sk_scalar(sk)
    raw = ct.raw
    if raw.startswith(_CT_LEVEL2):
        u, body = _parse_level2(raw)
        shared = curve.f12_pow(curve.pairing(curve.G2, u), curve.scalar_inv(a))
        key_enc, key_mac = _kdf(shared, _CT_LEVEL2)
        return _dem_open(key_enc, key_mac, _CT_LEVEL2, body)
    if raw.startswith(_CT_LEVEL1):
        v, body = _parse_level1(raw)
        shared = curve.f12_pow(v, curve.scalar_inv(a))
        key_enc, key_mac = _kdf(shared, _CT_LEVEL2)
        return _dem_open(key_enc, key_mac, _CT_LEVEL2, body)
    raise FormatError("unknown ciphertext version")


def make_rekey(sk_delegator: SecretKey, pk_delegatee: PublicKey) -> ReEncryptionKey:
    """Create rk A->B = (1/a) * pk2_B.  Only the delegator can do this."""
    a_inv = curve.scalar_inv(_sk_scalar(sk_delegator))
    _, pk2_b = _pk_points(pk_delegatee)
    rk_point = curve.point_mul(pk2_b, a_inv)
    return ReEncryptionKey(curve.g2_encode(rk_point))


def re_encrypt(rk: ReEncryptionKey, ct: Ciphertext) -> Ciphertext:
    """Transform a level-2 ciphertext for A into a level-1 one for B.

    Raises FormatError if the input is not a re-encryptable ciphertext.
    """
    raw = ct.raw
    if raw.startswith(_CT_LEVEL1):
        raise FormatError("ciphertext is already transformed (level 1)")
    u, body = _parse_level2(raw)
    try:
        rk_point = curve.g2_decode(rk.raw)
    except ValueError as exc:
        raise FormatError("malformed re-encryption key") from exc
    v = curve.pairing(rk_point, u)  # Z**(b*r)
    return Ciphertext(_CT_LEVEL1 + _fp12_encode(v) + body)

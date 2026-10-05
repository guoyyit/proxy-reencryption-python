"""Proxy re-encryption core.

Construction: the unidirectional, single-hop, non-interactive, collusion-resistant
AFGH06 proxy re-encryption scheme over BLS12-381 (Type-3 pairing e: G1 x G2 -> GT),
combined with a ChaCha20-Poly1305 authenticated DEM.

Keys per user (x1 used in GT, x2 used in G2):
    pk = (Z^x1, g2^x2),  sk = (x1, x2)

Second-level (owner-directed) ciphertext for random r:
    c1 = g1^r,  DEM key K = KDF(Z^(r*x1))

A versioned re-encryption key owner a -> delegatee b uses a per-version blinding
scalar k_v (enables key rotation):
    rk_v  = g2^((x1_a + k_v) * x2_b)   in G2
    blind = g2^k_v                     public correction point

The proxy transforms without learning any secret:
    c1'   = e(c1, rk_v)  = Z^(r*(x1_a+k_v)*x2_b)
    corr = e(c1, blind)  = Z^(r*k_v)

The delegatee removes its x2_b exponent and the public correction:
    (c1')^(1/x2_b) / corr = Z^(r*x1_a) => K

Transformed ciphertexts contain only GT elements, so they cannot be re-encapsulated
again (single-hop) nor redirected to a third party.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from py_ecc.optimized_bls12_381 import (
    FQ,
    FQ2,
    FQ12,
    G1,
    G2,
    add,
    curve_order,
    is_inf,
    multiply,
    normalize,
    pairing,
)

from app.errors import (
    CiphertextTamperedError,
    MalformedCiphertextError,
    ValidationError,
)

Q = curve_order
NONCE_LEN = 12


@dataclass(frozen=True)
class SecretKey:
    x1: int
    x2: int


@dataclass(frozen=True)
class PublicKey:
    pk0: tuple  # g1^x1 in G1
    pk1: FQ12  # Z^x1 in GT
    pk2: tuple  # g2^x2 in G2


@dataclass(frozen=True)
class ReEncryptionKey:
    point: tuple  # g2^((x1_a + k_v) * x2_b) in G2
    blinding: tuple  # g2^k_v in G2
    blinding_g1: tuple  # g1^k_v in G1 (for public well-formedness verification)


@dataclass(frozen=True)
class LevelTwoCiphertext:
    c1: tuple  # g1^r in G1
    nonce: bytes
    ciphertext: bytes  # DEM ciphertext including the 16-byte Poly1305 tag


@dataclass(frozen=True)
class LevelOneCiphertext:
    c1_prime: FQ12  # e(c1, rk_v) in GT
    correction: FQ12  # e(c1, g2^k_v) in GT
    nonce: bytes
    ciphertext: bytes


# --------------------------------------------------------------------------- low level


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(raw: str, field: str) -> bytes:
    if not isinstance(raw, str):
        raise MalformedCiphertextError(f"field {field} must be base64 text")
    try:
        return base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise MalformedCiphertextError(f"field {field} is not valid base64") from exc


def _rand_scalar() -> int:
    while True:
        value = secrets.randbelow(Q)
        if value not in (0, 1):
            return value


def _encode_gt(element: FQ12) -> bytes:
    out = bytearray()
    if len(element.coeffs) != 12:
        raise MalformedCiphertextError("GT element must have 12 coefficients")
    for coeff in element.coeffs:
        out += int(coeff).to_bytes(48, "big")
    return bytes(out)


def _decode_gt(data: bytes, field: str) -> FQ12:
    if len(data) != 12 * 48:
        raise MalformedCiphertextError(f"field {field} is not a GT element")
    try:
        values = [int.from_bytes(data[i:i + 48], "big") for i in range(0, len(data), 48)]
        element = FQ12(tuple(FQ(v) for v in values))
    except MalformedCiphertextError:
        raise
    except Exception as exc:
        raise MalformedCiphertextError(f"field {field} is not a GT element") from exc
    if element ** Q != FQ12.one():
        raise MalformedCiphertextError(f"field {field} is not in the GT subgroup")
    return element


def _in_prime_subgroup(point: tuple) -> bool:
    return is_inf(multiply(point, Q))


def _affine_g1(point: tuple) -> tuple:
    if is_inf(point):
        raise MalformedCiphertextError("point is at infinity")
    x, y = normalize(point)
    return (FQ(int(x)), FQ(int(y)), FQ(1))


def _affine_g2(point: tuple) -> tuple:
    if is_inf(point):
        raise MalformedCiphertextError("point is at infinity")
    x, y = normalize(point)
    return (x, y, FQ2([1, 0]))


def _mul_g1(scalar: int) -> tuple:
    return _affine_g1(multiply(G1, scalar))


def _mul_g2(scalar: int) -> tuple:
    return _affine_g2(multiply(G2, scalar))


def _encode_g1(point: tuple) -> bytes:
    x, y = normalize(point)
    return int(x).to_bytes(48, "big") + int(y).to_bytes(48, "big")


def _decode_g1(data: bytes, field: str) -> tuple:
    if len(data) != 96:
        raise MalformedCiphertextError(f"field {field} is not a G1 point")
    x = FQ(int.from_bytes(data[:48], "big"))
    y = FQ(int.from_bytes(data[48:], "big"))
    point = (FQ(int(x)), FQ(int(y)), FQ(1))
    if y * y != x * x * x + FQ(4):
        raise MalformedCiphertextError(f"field {field} is not on the G1 curve")
    if not _in_prime_subgroup(point):
        raise MalformedCiphertextError(f"field {field} is not in the G1 subgroup")
    return point


_G2_B = FQ2((FQ(4), FQ(4)))  # y^2 = x^3 + 4*(1 + u) over Fp2


def _encode_g2(point: tuple) -> bytes:
    x, y = normalize(point)
    return (
        int(x.coeffs[0]).to_bytes(48, "big")
        + int(x.coeffs[1]).to_bytes(48, "big")
        + int(y.coeffs[0]).to_bytes(48, "big")
        + int(y.coeffs[1]).to_bytes(48, "big")
    )


def _decode_g2(data: bytes, field: str) -> tuple:
    if len(data) != 192:
        raise MalformedCiphertextError(f"field {field} is not a G2 point")
    parts = [int.from_bytes(data[i:i + 48], "big") for i in range(0, 192, 48)]
    x = FQ2((FQ(parts[0]), FQ(parts[1])))
    y = FQ2((FQ(parts[2]), FQ(parts[3])))
    point = (x, y, FQ2([1, 0]))
    if y * y != x * x * x + _G2_B:
        raise MalformedCiphertextError(f"field {field} is not on the G2 curve")
    if not _in_prime_subgroup(point):
        raise MalformedCiphertextError(f"field {field} is not in the G2 subgroup")
    return point


def _kdf(shared: FQ12, level: bytes, associated_data: bytes) -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"local-pre-v1" + level,
        info=associated_data,
    ).derive(_encode_gt(shared))


# --------------------------------------------------------------------------- keys


def generate_keypair() -> tuple[SecretKey, PublicKey]:
    x1 = _rand_scalar()
    x2 = _rand_scalar()
    z = pairing(G2, G1)
    return SecretKey(x1, x2), PublicKey(_mul_g1(x1), z ** x1, _mul_g2(x2))


def serialize_public_key(pk: PublicKey) -> str:
    payload = {
        "v": 1,
        "pk0": _b64e(_encode_g1(pk.pk0)),
        "pk1": _b64e(_encode_gt(pk.pk1)),
        "pk2": _b64e(_encode_g2(pk.pk2)),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def deserialize_public_key(raw: str) -> PublicKey:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValidationError("public key is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ValidationError("unsupported public key version")
    pk0 = _decode_g1(_b64d(payload.get("pk0"), "pk0"), "pk0")
    pk1 = _decode_gt(_b64d(payload.get("pk1"), "pk1"), "pk1")
    pk2 = _decode_g2(_b64d(payload.get("pk2"), "pk2"), "pk2")
    return PublicKey(pk0, pk1, pk2)


def serialize_secret_key(sk: SecretKey) -> str:
    payload = {
        "v": 1,
        "x1": sk.x1.to_bytes(32, "big").hex(),
        "x2": sk.x2.to_bytes(32, "big").hex(),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def deserialize_secret_key(raw: str) -> SecretKey:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ValidationError("secret key is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ValidationError("unsupported secret key version")
    try:
        x1 = int(payload["x1"], 16)
        x2 = int(payload["x2"], 16)
    except Exception as exc:
        raise ValidationError("secret key components must be hex") from exc
    if not (1 <= x1 < Q and 1 <= x2 < Q):
        raise ValidationError("secret key components out of range")
    return SecretKey(x1, x2)


def serialize_rekey(rk: ReEncryptionKey) -> str:
    payload = {
        "v": 1,
        "rk": _b64e(_encode_g2(rk.point)),
        "blind": _b64e(_encode_g2(rk.blinding)),
        "blind1": _b64e(_encode_g1(rk.blinding_g1)),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def deserialize_rekey(raw: str) -> ReEncryptionKey:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise MalformedCiphertextError("re-encryption key is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise MalformedCiphertextError("unsupported re-encryption key version")
    point = _decode_g2(_b64d(payload.get("rk"), "rk"), "rk")
    blinding = _decode_g2(_b64d(payload.get("blind"), "blind"), "blind")
    blinding_g1 = _decode_g1(_b64d(payload.get("blind1"), "blind1"), "blind1")
    return ReEncryptionKey(point, blinding, blinding_g1)


def random_blinding_scalar() -> int:
    """Fresh per-version blinding scalar k_v used when rotating a re-encryption key."""
    return _rand_scalar()


def serialize_blinding_scalar(k_v: int) -> str:
    if not (1 <= k_v < Q):
        raise ValidationError("blinding scalar out of range")
    return k_v.to_bytes(32, "big").hex()


def deserialize_blinding_scalar(raw: str) -> int:
    try:
        value = int(raw, 16)
    except Exception as exc:
        raise ValidationError("blinding scalar must be hex") from exc
    if not (1 <= value < Q):
        raise ValidationError("blinding scalar out of range")
    return value


# --------------------------------------------------------------------------- ciphertexts


def _aad(associated_data: bytes) -> bytes:
    return b"local-pre-aad" + len(associated_data).to_bytes(8, "big") + associated_data


def serialize_ciphertext(ct: LevelTwoCiphertext | LevelOneCiphertext) -> str:
    if isinstance(ct, LevelTwoCiphertext):
        payload = {
            "v": 1,
            "lvl": 2,
            "c1": _b64e(_encode_g1(ct.c1)),
            "nonce": _b64e(ct.nonce),
            "ct": _b64e(ct.ciphertext),
        }
    else:
        payload = {
            "v": 1,
            "lvl": 1,
            "c1p": _b64e(_encode_gt(ct.c1_prime)),
            "corr": _b64e(_encode_gt(ct.correction)),
            "nonce": _b64e(ct.nonce),
            "ct": _b64e(ct.ciphertext),
        }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def deserialize_ciphertext(
    raw: str,
) -> LevelTwoCiphertext | LevelOneCiphertext:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise MalformedCiphertextError("ciphertext is not valid JSON") from exc
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise MalformedCiphertextError("unsupported ciphertext version")
    nonce = _b64d(payload.get("nonce"), "nonce")
    body = _b64d(payload.get("ct"), "ct")
    if len(nonce) != NONCE_LEN or len(body) < 16:
        raise MalformedCiphertextError("nonce or DEM body has wrong length")
    level = payload.get("lvl")
    if level == 2:
        return LevelTwoCiphertext(_decode_g1(_b64d(payload.get("c1"), "c1"), "c1"), nonce, body)
    if level == 1:
        return LevelOneCiphertext(
            _decode_gt(_b64d(payload.get("c1p"), "c1p"), "c1p"),
            _decode_gt(_b64d(payload.get("corr"), "corr"), "corr"),
            nonce,
            body,
        )
    raise MalformedCiphertextError("ciphertext level must be 1 or 2")


# --------------------------------------------------------------------------- operations


def encrypt(pk: PublicKey, plaintext: bytes, associated_data: bytes = b"") -> LevelTwoCiphertext:
    r = _rand_scalar()
    c1 = _mul_g1(r)
    shared = pk.pk1 ** r  # Z^(r*x1)
    key = _kdf(shared, b"lvl2", associated_data)
    nonce = secrets.token_bytes(NONCE_LEN)
    body = ChaCha20Poly1305(key).encrypt(nonce, plaintext, _aad(associated_data))
    return LevelTwoCiphertext(c1, nonce, body)


def decrypt_lvl2(sk: SecretKey, ct: LevelTwoCiphertext, associated_data: bytes = b"") -> bytes:
    shared = pairing(G2, ct.c1) ** sk.x1  # e(g2, g1^r)^x1 = Z^(r*x1)
    key = _kdf(shared, b"lvl2", associated_data)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce=ct.nonce, data=ct.ciphertext, associated_data=_aad(associated_data))
    except Exception as exc:
        raise CiphertextTamperedError("level-2 decryption failed (wrong key or tampered)") from exc


def create_rekey(sk_owner: SecretKey, pk_delegatee: PublicKey, k_v: int) -> ReEncryptionKey:
    if not (1 <= k_v < Q):
        raise ValidationError("blinding scalar out of range")
    # rk = (g2^x2_b)^(x1_a + k_v) since pk_delegatee.pk2 = g2^x2_b
    point = _affine_g2(multiply(pk_delegatee.pk2, (sk_owner.x1 + k_v) % Q))
    return ReEncryptionKey(point, _mul_g2(k_v), _mul_g1(k_v))


def verify_rekey(pk_owner: PublicKey, pk_delegatee: PublicKey, rk: ReEncryptionKey) -> bool:
    """Publicly verify a re-encryption key using only the two public keys.

    Two pairing equations, both equal to Z^((x1_a + k_v) * x2_b) and
    Z^k_v respectively::

        e(rk.point, g1) == e(pk_owner.pk0 + rk.blinding_g1, pk_delegatee.pk2)
        e(rk.blinding, g1) == e(g2, rk.blinding_g1)

    A well-formed key re-encrypts owner ciphertexts to the declared delegatee;
    a tampered or forged key fails this check before it is ever stored.
    """
    owner_pk0 = _affine_g1(pk_owner.pk0)
    delegatee_pk2 = _affine_g2(pk_delegatee.pk2)
    rk_point = _affine_g2(rk.point)
    rk_blind_g2 = _affine_g2(rk.blinding)
    rk_blind_g1 = _affine_g1(rk.blinding_g1)
    owner_target = add(owner_pk0, rk_blind_g1)
    first = pairing(rk_point, G1) == pairing(delegatee_pk2, owner_target)
    second = pairing(rk_blind_g2, G1) == pairing(G2, rk_blind_g1)
    return first and second


def re_encrypt(rk: ReEncryptionKey, ct: LevelTwoCiphertext) -> LevelOneCiphertext:
    if not isinstance(ct, LevelTwoCiphertext):
        raise MalformedCiphertextError("re-encryption requires a level-2 ciphertext")
    c1 = _affine_g1(ct.c1)
    rk_point = _affine_g2(rk.point)
    rk_blind = _affine_g2(rk.blinding)
    c1_prime = pairing(rk_point, c1)  # e(g2^((x1a+kv)*x2b), g1^r)
    correction = pairing(rk_blind, c1)  # e(g2^kv, g1^r)
    return LevelOneCiphertext(c1_prime, correction, ct.nonce, ct.ciphertext)


def decrypt_lvl1(sk: SecretKey, ct: LevelOneCiphertext, associated_data: bytes = b"") -> bytes:
    if not isinstance(ct, LevelOneCiphertext):
        raise MalformedCiphertextError("level-1 decryption requires a level-1 ciphertext")
    unblinded = ct.c1_prime ** pow(sk.x2, -1, Q)
    shared = unblinded / ct.correction  # Z^(r*x1_a)
    key = _kdf(shared, b"lvl2", associated_data)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce=ct.nonce, data=ct.ciphertext, associated_data=_aad(associated_data))
    except Exception as exc:
        raise CiphertextTamperedError("level-1 decryption failed (wrong key or tampered)") from exc

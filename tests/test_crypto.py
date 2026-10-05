"""Tests for the BLS12-381 pairing and the AFGH PRE primitives."""

import pytest

from pre import bls12_381 as curve
from pre import crypto
from pre.errors import FormatError, TamperError


def test_pairing_bilinearity_and_non_degeneracy():
    a, k = 123456789, 987654321
    e = curve.pairing(curve.G2, curve.G1)
    assert e != curve.FP12_ONE
    assert curve.f12_pow(e, curve.R) == curve.FP12_ONE
    assert curve.pairing(curve.point_mul(curve.G2, a), curve.G1) == (
        curve.f12_pow(e, a)
    )
    assert curve.pairing(curve.G2, curve.point_mul(curve.G1, a)) == (
        curve.f12_pow(e, a)
    )
    assert curve.pairing(
        curve.point_mul(curve.G2, a), curve.point_mul(curve.G1, k)
    ) == curve.f12_pow(e, a * k)


def test_scalar_mul_matches_generators_for_many_scalars():
    for n in range(1, 40):
        p = curve.normalize_g1(curve.g1_generator_mul(n))
        assert curve.is_on_curve_g1(p)
        q = curve.normalize_g2(curve.g2_generator_mul(n))
        assert curve.is_on_curve_g2(q)


def test_point_encoding_roundtrip_and_tamper_rejection():
    n = curve.random_scalar()
    g1 = curve.g1_generator_mul(n)
    g2 = curve.g2_generator_mul(n)
    assert curve.g1_decode(curve.g1_encode(g1)) == curve.normalize_g1(g1)
    assert curve.g2_decode(curve.g2_encode(g2)) == curve.normalize_g2(g2)
    for good, decoder in (
        (bytearray(curve.g1_encode(g1)), curve.g1_decode),
        (bytearray(curve.g2_encode(g2)), curve.g2_decode),
    ):
        good[5] ^= 0x01
        with pytest.raises(ValueError):
            decoder(bytes(good))


def test_owner_encrypt_decrypt_roundtrip():
    sk, pk = crypto.keygen()
    message = b"owner only message" * 8
    ct = crypto.encrypt(pk, message)
    assert crypto.decrypt(sk, ct) == message


def test_re_encryption_correctness():
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    message = b"delegated payload" * 16
    rk = crypto.make_rekey(sk_a, pk_b)
    ct = crypto.encrypt(pk_a, message)
    transformed = crypto.re_encrypt(rk, ct)
    assert crypto.decrypt(sk_b, transformed) == message
    # A still decrypts the original level-2 ciphertext.
    assert crypto.decrypt(sk_a, ct) == message


def test_non_transferability_and_collusion_limits():
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    sk_c, pk_c = crypto.keygen()
    a = int.from_bytes(sk_a.raw, "big")
    b_scalar = int.from_bytes(sk_b.raw, "big")
    rk = crypto.make_rekey(sk_a, pk_b)
    rk_point = curve.g2_decode(rk.raw)
    # Colluding proxy + B recover at most g2**(1/a), never the scalar a.
    g2_inv_a = curve.point_mul(rk_point, curve.scalar_inv(b_scalar))
    pk2_a = curve.g2_decode(pk_a.raw[97:])
    # g2**(1/a) is NOT A's public key and yields no scalar.
    assert g2_inv_a != pk2_a
    assert g2_inv_a != curve.point_mul(curve.G2, a)
    # It is not a valid A->C re-encryption key: transforming with it cannot
    # be decrypted by C.
    ct = crypto.encrypt(pk_a, b"secret")
    bogus = crypto.ReEncryptionKey(curve.g2_encode(g2_inv_a))
    transformed = crypto.re_encrypt(bogus, ct)
    with pytest.raises(TamperError):
        crypto.decrypt(sk_c, transformed)


def test_level1_cannot_be_re_encrypted_again():
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    ct = crypto.encrypt(pk_a, b"x")
    level1 = crypto.re_encrypt(crypto.make_rekey(sk_a, pk_b), ct)
    with pytest.raises(FormatError):
        crypto.re_encrypt(crypto.make_rekey(sk_a, pk_b), level1)


def test_tampered_ciphertext_is_rejected():
    sk, pk = crypto.keygen()
    ct = bytearray(crypto.encrypt(pk, b"plaintext" * 4).raw)
    ct[-1] ^= 0xFF
    with pytest.raises(TamperError):
        crypto.decrypt(sk, crypto.Ciphertext(bytes(ct)))


def test_malformed_inputs_are_rejected():
    sk, pk = crypto.keygen()
    with pytest.raises(FormatError):
        crypto.decrypt(sk, crypto.Ciphertext(b"nope"))
    with pytest.raises(FormatError):
        crypto.re_encrypt(
            crypto.ReEncryptionKey(b"bad"), crypto.encrypt(pk, b"m")
        )

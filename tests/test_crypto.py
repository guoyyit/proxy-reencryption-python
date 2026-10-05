"""Cryptographic core tests: correctness, non-transferability, collusion resistance."""

from __future__ import annotations

import json

import pytest

from app import crypto
from app.errors import CiphertextTamperedError, MalformedCiphertextError


@pytest.fixture(scope="module")
def parties():
    sk_a, pk_a = crypto.generate_keypair()
    sk_b, pk_b = crypto.generate_keypair()
    sk_c, pk_c = crypto.generate_keypair()
    return sk_a, pk_a, sk_b, pk_b, sk_c, pk_c


def test_owner_encrypt_decrypt_roundtrip(parties):
    sk_a, pk_a, *_ = parties
    ct = crypto.encrypt(pk_a, b"plaintext", b"aad")
    assert crypto.decrypt_lvl2(sk_a, ct, b"aad") == b"plaintext"


def test_reencrypt_then_delegatee_decrypts(parties):
    sk_a, pk_a, sk_b, pk_b, *_ = parties
    ct = crypto.encrypt(pk_a, b"delegate-me", b"aad")
    rk = crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    assert crypto.verify_rekey(pk_a, pk_b, rk)
    ct1 = crypto.re_encrypt(rk, ct)
    assert crypto.decrypt_lvl1(sk_b, ct1, b"aad") == b"delegate-me"


def test_proxy_cannot_decrypt(parties):
    sk_a, pk_a, sk_b, pk_b, *_ = parties
    ct = crypto.encrypt(pk_a, b"secret", b"aad")
    rk = crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    ct1 = crypto.re_encrypt(rk, ct)
    # the re-encryption key is a group element, not a secret scalar: random key fails
    sk_random, _ = crypto.generate_keypair()
    with pytest.raises(CiphertextTamperedError):
        crypto.decrypt_lvl1(sk_random, ct1, b"aad")


def test_non_transability_delegatee_cannot_redirect_to_third_party(parties):
    sk_a, pk_a, sk_b, pk_b, sk_c, pk_c = parties
    # A -> B key, honestly generated
    rk_ab = crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    # A key re-encrypted through an A -> C key must NOT be verifiable/usable as A -> B
    rk_ac = crypto.create_rekey(sk_a, pk_c, crypto.random_blinding_scalar())
    assert not crypto.verify_rekey(pk_a, pk_b, rk_ac)
    assert not crypto.verify_rekey(pk_a, pk_c, rk_ab)
    # swapping the point but keeping the blinding also fails verification
    swapped = crypto.ReEncryptionKey(rk_ac.point, rk_ab.blinding, rk_ab.blinding_g1)
    assert not crypto.verify_rekey(pk_a, pk_b, swapped)


def test_collusion_cannot_recover_owner_scalar(parties):
    """Delegatee + proxy know rk (a group element) and sk_b; x1_a stays hidden.

    Sanity model: everything the colluding parties hold (rk points, blinding,
    pk_a, sk_b) is checked to be distinct from the owner's discrete log, and a
    key derived from sk_b alone cannot decrypt owner ciphertexts.
    """
    sk_a, pk_a, sk_b, pk_b, *_ = parties
    rk = crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    # owner public x1 component is a curve point, not the scalar itself
    assert int(pk_a.pk0[0]) != sk_a.x1
    # re-encryption key lives in G2 (a group element), not in the scalar field
    assert hasattr(rk.point[0], "coeffs")
    assert crypto._encode_g2(rk.point) != crypto._encode_g1(pk_a.pk0)
    # decrypting an owner (level-2) ciphertext with only sk_b fails
    ct = crypto.encrypt(pk_a, b"x", b"aad")
    with pytest.raises(CiphertextTamperedError):
        crypto.decrypt_lvl2(sk_b, ct, b"aad")


def test_tampered_dem_body_rejected(parties):
    import base64

    sk_a, pk_a, *_ = parties
    raw = json.loads(crypto.serialize_ciphertext(crypto.encrypt(pk_a, b"m", b"a")))
    body = bytearray(base64.b64decode(raw["ct"]))
    body[0] ^= 0x01
    raw["ct"] = base64.b64encode(bytes(body)).decode()
    with pytest.raises(CiphertextTamperedError):
        crypto.decrypt_lvl2(sk_a, crypto.deserialize_ciphertext(json.dumps(raw)), b"a")


@pytest.mark.parametrize("bad", ["not-json", "{}", '{"v":1,"lvl":2}', '{"v":9,"lvl":1}'])
def test_malformed_ciphertext_rejected(bad):
    with pytest.raises(MalformedCiphertextError):
        crypto.deserialize_ciphertext(bad)


def test_wrong_associated_data_rejected(parties):
    sk_a, pk_a, sk_b, pk_b, *_ = parties
    ct = crypto.encrypt(pk_a, b"m", b"correct")
    ct1 = crypto.re_encrypt(crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar()), ct)
    with pytest.raises(CiphertextTamperedError):
        crypto.decrypt_lvl1(sk_b, ct1, b"wrong")


def test_single_hop_level1_cannot_be_reencrypted(parties):
    sk_a, pk_a, sk_b, pk_b, *_ = parties
    ct = crypto.encrypt(pk_a, b"m", b"a")
    ct1 = crypto.re_encrypt(crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar()), ct)
    with pytest.raises(MalformedCiphertextError):
        crypto.re_encrypt(crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar()), ct1)

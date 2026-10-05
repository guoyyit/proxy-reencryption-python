"""Concurrency: rotation vs conversion must never observe a torn key version."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from app import crypto
from app.errors import RevokedError


def _fresh_rk(alice, bob):
    sk_a = crypto.deserialize_secret_key(alice.pre_secret_hex)
    pk_b = crypto.deserialize_public_key(bob.pre_public_json)
    return crypto.serialize_rekey(
        crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    )


def test_concurrent_rotation_and_conversion_is_version_consistent(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    pk_a = crypto.deserialize_public_key(alice.pre_public_json)
    sk_b = crypto.deserialize_secret_key(bob.pre_secret_hex)

    # v1 delegation
    service.create_delegation(
        owner_id="alice", delegatee_id="bob", rk_json=_fresh_rk(alice, bob), request_id="d0"
    )
    # a set of ciphertexts created while rotations happen
    n_ct = 24
    for i in range(n_ct):
        ct = crypto.encrypt(pk_a, f"msg-{i}".encode())
        service.register_ciphertext(
            owner_id="alice", ciphertext_id=f"c-{i}",
            ciphertext=crypto.serialize_ciphertext(ct), request_id=f"rc-{i}",
        )

    results: dict[int, int] = {}
    errors: list[Exception] = []
    lock = threading.Lock()

    def convert(i: int) -> None:
        try:
            out = service.reencrypt(
                owner_id="alice", delegatee_id="bob",
                ciphertext_id=f"c-{i}", request_id=f"conv-{i}",
            )
            with lock:
                results[i] = out["version"]
            # the returned ciphertext must be decryptable under that exact version:
            transformed = crypto.deserialize_ciphertext(out["ciphertext"])
            assert crypto.decrypt_lvl1(sk_b, transformed) == f"msg-{i}".encode()
        except RevokedError:
            pass
        except Exception as exc:  # pragma: no cover - surface unexpected errors
            with lock:
                errors.append(exc)

    def rotate(new_version: int) -> None:
        service.rotate_rekey(
            owner_id="alice", delegatee_id="bob",
            rk_json=_fresh_rk(alice, bob), request_id=f"rot-{new_version}",
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = []
        for i in range(n_ct):
            futures.append(pool.submit(convert, i))
            if i % 6 == 5:
                futures.append(pool.submit(rotate, i))
        for future in futures:
            future.result()

    assert not errors, errors
    # every conversion that succeeded reports a concrete, existing version
    for i, version in results.items():
        assert version >= 1
        assert service.store.get_rekey_version(
            service.store.get_delegation_by_pair("alice", "bob")["id"], version
        ) is not None


def test_rotation_is_monotonic_and_atomic(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    service.create_delegation(
        owner_id="alice", delegatee_id="bob", rk_json=_fresh_rk(alice, bob), request_id="d"
    )
    with ThreadPoolExecutor(max_workers=4) as pool:
        outs = list(pool.map(lambda v: service.rotate_rekey(
            owner_id="alice", delegatee_id="bob", rk_json=_fresh_rk(alice, bob),
            request_id=f"rot-{v}",
        ), range(1, 9)))
    versions = sorted(o["version"] for o in outs)
    assert versions == list(range(2, 10))
    delegation = service.store.get_delegation_by_pair("alice", "bob")
    assert delegation["current_version"] == 9
    # all versions present, none missing (no torn intermediate state)
    for v in range(1, 10):
        assert service.store.get_rekey_version(delegation["id"], v) is not None

"""Service-level tests: conversion, permissions and both revocation granularities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app import crypto
from app.errors import ConflictError, ForbiddenError, NotFoundError, RevokedError, ValidationError
from app.errors import StaleVersionError
from app.revocation import to_iso


def _setup_delegation(service, alice, bob, k_v=None):
    sk_a = crypto.deserialize_secret_key(alice.pre_secret_hex)
    pk_b = crypto.deserialize_public_key(bob.pre_public_json)
    k_v = k_v if k_v is not None else crypto.random_blinding_scalar()
    rk = crypto.create_rekey(sk_a, pk_b, k_v)
    service.create_delegation(
        owner_id="alice",
        delegatee_id="bob",
        rk_json=crypto.serialize_rekey(rk),
        request_id="del",
    )
    return rk, k_v


def _encrypt_for_owner(alice, message: bytes, aad: bytes = b""):
    pk_a = crypto.deserialize_public_key(alice.pre_public_json)
    return crypto.encrypt(pk_a, message, aad)


def test_correct_conversion_decrypts_by_delegatee(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    ct = _encrypt_for_owner(alice, b"payload")
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-1",
        ciphertext=crypto.serialize_ciphertext(ct), request_id="regct",
    )
    result = service.reencrypt(
        owner_id="alice", delegatee_id="bob", ciphertext_id="ct-1", request_id="req-1"
    )
    sk_b = crypto.deserialize_secret_key(bob.pre_secret_hex)
    transformed = crypto.deserialize_ciphertext(result["ciphertext"])
    assert crypto.decrypt_lvl1(sk_b, transformed) == b"payload"


def test_non_transferability_third_party_cannot_use_delegation(registered_service, parties):
    service = registered_service
    alice, bob, carol = parties
    _setup_delegation(service, alice, bob)
    ct = _encrypt_for_owner(alice, b"secret")
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-2",
        ciphertext=crypto.serialize_ciphertext(ct), request_id="regct2",
    )
    # no delegation alice -> carol
    with pytest.raises(NotFoundError):
        service.reencrypt(owner_id="alice", delegatee_id="carol", ciphertext_id="ct-2", request_id="r")
    # even bob's transformed ciphertext cannot be decrypted by carol
    result = service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-2", request_id="r2")
    sk_c = crypto.deserialize_secret_key(carol.pre_secret_hex)
    transformed = crypto.deserialize_ciphertext(result["ciphertext"])
    with pytest.raises(crypto.CiphertextTamperedError):
        crypto.decrypt_lvl1(sk_c, transformed)


def test_rekey_must_be_well_formed(registered_service, parties):
    service = registered_service
    alice, bob, carol = parties
    # rk targeted at carol cannot be registered as an alice->bob delegation
    sk_a = crypto.deserialize_secret_key(alice.pre_secret_hex)
    pk_c = crypto.deserialize_public_key(carol.pre_public_json)
    wrong_rk = crypto.create_rekey(sk_a, pk_c, crypto.random_blinding_scalar())
    with pytest.raises(ValidationError):
        service.create_delegation(
            owner_id="alice", delegatee_id="bob",
            rk_json=crypto.serialize_rekey(wrong_rk), request_id="bad",
        )


def test_per_ciphertext_revocation_blocks_only_that_ciphertext(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    for cid in ("ct-a", "ct-b"):
        service.register_ciphertext(
            owner_id="alice", ciphertext_id=cid,
            ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, cid.encode())),
            request_id=f"reg-{cid}",
        )
    service.revoke_ciphertext(owner_id="alice", ciphertext_id="ct-a", request_id="rev-a")
    with pytest.raises(RevokedError):
        service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-a", request_id="c1")
    # other ciphertext unaffected
    other = service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-b", request_id="c2")
    assert other["ciphertext"]


def test_time_window_revocation_blocks_then_recovers(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-w",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"w")),
        request_id="reg-w",
    )
    now = datetime.now(timezone.utc)
    # active window over the delegatee
    service.add_revocation_window(
        owner_id="alice", delegatee_id="bob", target="bob",
        not_before=to_iso(now - timedelta(minutes=1)),
        not_after=to_iso(now + timedelta(minutes=10)),
        reason="suspend", request_id="win-on",
    )
    with pytest.raises(RevokedError):
        service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-w", request_id="win-re")
    # add an already-expired window; the active one still wins
    service.add_revocation_window(
        owner_id="alice", delegatee_id="bob", target="bob",
        not_before=to_iso(now - timedelta(hours=3)),
        not_after=to_iso(now - timedelta(hours=2)),
        reason="past", request_id="win-past",
    )
    with pytest.raises(RevokedError):
        service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-w", request_id="win-re2")


def test_time_window_recovers_after_expiry(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-e",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"e")),
        request_id="reg-e",
    )
    now = datetime.now(timezone.utc)
    service.add_revocation_window(
        owner_id="alice", delegatee_id="bob", target="ct-e",
        not_before=to_iso(now - timedelta(hours=2)),
        not_after=to_iso(now - timedelta(hours=1)),
        reason="past", request_id="win-exp",
    )
    result = service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-e", request_id="re")
    assert result["ciphertext"]


def test_only_owner_can_revoke(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-o",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"o")),
        request_id="reg-o",
    )
    # service layer enforcement: carol is not the owner
    with pytest.raises(NotFoundError):
        service.revoke_ciphertext(owner_id="carol", ciphertext_id="missing", request_id="x")
    # carol trying to revoke alice ciphertext
    import app.service as service_mod

    # emulate by inserting carol then attempting direct ownership path
    with pytest.raises(ForbiddenError):
        service.revoke_ciphertext(owner_id="carol", ciphertext_id="ct-o", request_id="carol-rev")
    denied = [a for a in service.list_audit(requester_id="carol") if a["result"] == "denied"]
    assert denied and denied[0]["action"] == "revoke_ciphertext"


def test_permanent_delegation_revocation_blocks_all(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-d",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"d")),
        request_id="reg-d",
    )
    service.revoke_delegation(owner_id="alice", delegatee_id="bob", reason="done", request_id="rd")
    with pytest.raises(RevokedError):
        service.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-d", request_id="d-re")


def test_duplicate_delegation_conflicts(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    with pytest.raises(ConflictError):
        _setup_delegation(service, alice, bob)


def test_stale_pinned_version_rejected_but_current_works(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-v",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"v")),
        request_id="reg-v",
    )
    sk_a = crypto.deserialize_secret_key(alice.pre_secret_hex)
    pk_b = crypto.deserialize_public_key(bob.pre_public_json)
    new_rk = crypto.serialize_rekey(
        crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    )
    service.rotate_rekey(owner_id="alice", delegatee_id="bob", rk_json=new_rk, request_id="rot")
    with pytest.raises(StaleVersionError):
        service.reencrypt(
            owner_id="alice", delegatee_id="bob", ciphertext_id="ct-v",
            request_id="stale", expected_version=1,
        )
    current = service.reencrypt(
        owner_id="alice", delegatee_id="bob", ciphertext_id="ct-v",
        request_id="current", expected_version=2,
    )
    assert current["version"] == 2


def test_denied_conversion_audit_is_committed_not_rolled_back(registered_service, parties):
    service = registered_service
    alice, bob, _ = parties
    _setup_delegation(service, alice, bob)
    service.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-audit",
        ciphertext=crypto.serialize_ciphertext(_encrypt_for_owner(alice, b"z")),
        request_id="reg-audit",
    )
    service.revoke_ciphertext(owner_id="alice", ciphertext_id="ct-audit", request_id="rv")
    with pytest.raises(RevokedError):
        service.reencrypt(
            owner_id="alice", delegatee_id="bob", ciphertext_id="ct-audit",
            request_id="denied-conversion",
        )
    rows = service.store.list_audit(actor_id="proxy", action="reencrypt")
    denied = [r for r in rows if r["result"] == "denied"]
    assert len(denied) == 1
    assert denied[0]["request_id"] == "denied-conversion"

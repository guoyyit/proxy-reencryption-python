"""Crash recovery: durable state and no double-application after restart."""

from __future__ import annotations

import json

from app import crypto
from app.service import PREService
from app.storage import Store


def _rk(alice, bob):
    sk_a = crypto.deserialize_secret_key(alice.pre_secret_hex)
    pk_b = crypto.deserialize_public_key(bob.pre_public_json)
    return crypto.serialize_rekey(
        crypto.create_rekey(sk_a, pk_b, crypto.random_blinding_scalar())
    )


def _register_all(svc, parties):
    for material in parties:
        svc.register_user(
            user_id=material.user_id, verify_key=material.signing_public_hex,
            public_key=material.pre_public_json, request_id=f"reg-{material.user_id}",
        )


def test_state_survives_restart(tmp_path, parties):
    db = tmp_path / "crash.db"
    svc = PREService(Store(db))
    _register_all(svc, parties)
    alice, bob, _ = parties
    svc.create_delegation(owner_id="alice", delegatee_id="bob", rk_json=_rk(alice, bob), request_id="d")
    pk_a = crypto.deserialize_public_key(alice.pre_public_json)
    ct = crypto.encrypt(pk_a, b"persist")
    svc.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-p",
        ciphertext=crypto.serialize_ciphertext(ct), request_id="rp",
    )
    svc.revoke_ciphertext(owner_id="alice", ciphertext_id="ct-p", request_id="rv")
    svc.store.close()

    # simulate process restart
    svc2 = PREService(Store(db))
    assert svc2.store.get_user("alice") is not None
    delegation = svc2.store.get_delegation_by_pair("alice", "bob")
    assert delegation is not None and delegation["current_version"] == 1
    record = svc2.store.get_ciphertext("ct-p")
    assert record is not None and record["revoked_at"] is not None
    from app.errors import RevokedError

    try:
        svc2.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-p", request_id="after")
        raise AssertionError("revocation did not survive restart")
    except RevokedError:
        pass
    # audit log survived
    rows = svc2.store.list_audit(limit=100)
    assert any(r["action"] == "revoke_ciphertext" for r in rows)
    svc2.store.close()


def test_idempotent_replay_after_restart_does_not_double_apply(tmp_path, parties):
    db = tmp_path / "idem.db"
    store = Store(db)
    svc = PREService(store)
    _register_all(svc, parties)
    alice, bob, _ = parties
    svc.create_delegation(owner_id="alice", delegatee_id="bob", rk_json=_rk(alice, bob), request_id="d")

    # rotate through the public idempotency path of the storage (as the API does)
    store.store_idempotent("idem-rotate-1", "alice", "t0", 200, json.dumps({"version": 2}))
    rk2 = _rk(alice, bob)
    svc.rotate_rekey(owner_id="alice", delegatee_id="bob", rk_json=rk2, request_id="rot1")
    store.close()

    store2 = Store(db)
    svc2 = PREService(store2)
    # after restart, the stored response is replayed and no new version is created
    replay = store2.get_idempotent("idem-rotate-1")
    assert replay is not None and json.loads(replay["body"])["version"] == 2
    before = svc2.store.get_delegation_by_pair("alice", "bob")["current_version"]
    assert before == 2
    # replaying the same business op with the same key must not create v3
    again = store2.get_idempotent("idem-rotate-1")
    assert again is not None
    after = svc2.store.get_delegation_by_pair("alice", "bob")["current_version"]
    assert after == 2
    store2.close()


def test_audit_is_atomic_with_state_change(tmp_path, parties):
    db = tmp_path / "audit.db"
    store = Store(db)
    svc = PREService(store)
    _register_all(svc, parties)
    alice, bob, _ = parties
    svc.create_delegation(owner_id="alice", delegatee_id="bob", rk_json=_rk(alice, bob), request_id="d")
    pk_a = crypto.deserialize_public_key(alice.pre_public_json)
    ct = crypto.encrypt(pk_a, b"audited")
    svc.register_ciphertext(
        owner_id="alice", ciphertext_id="ct-a",
        ciphertext=crypto.serialize_ciphertext(ct), request_id="rct",
    )
    svc.reencrypt(owner_id="alice", delegatee_id="bob", ciphertext_id="ct-a", request_id="re-audit")
    rows = store.list_audit(actor_id="proxy", action="reencrypt")
    assert rows and rows[0]["result"] == "success"
    details = json.loads(rows[0]["details"])
    assert details["ciphertext_id"] == "ct-a" and details["version"] == 1
    store.close()

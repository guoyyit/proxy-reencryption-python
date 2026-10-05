"""End-to-end HTTP tests: delegation, revocations, rotation and audit."""

from __future__ import annotations

import time

import httpx
import pytest

from pre import crypto, schemas
from pre.errors import RevokedError


def _delegate(system, delegator_client, delegatee_name, target_pk):
    rk = delegator_client.make_rekey(target_pk)
    return delegator_client.create_delegation(delegatee_name, rk)


def test_full_delegation_flow(system):
    alice, bob = system["alice"], system["bob"]
    _delegate(system, alice, "bob", system["pkB"])
    message = b"full flow message" * 8
    ct = alice.encrypt(system["pkA"], message)
    transformed, version, replayed = alice.transform(
        "alice", "bob", ct, "ct-1", request_id="req-1"
    )
    assert version == 1 and replayed is False
    assert bob.decrypt(transformed) == message


def test_idempotent_transform_replay(system):
    alice, bob = system["alice"], system["bob"]
    _delegate(system, alice, "bob", system["pkB"])
    ct = alice.encrypt(system["pkA"], b"replay" * 4)
    out1, _, replay1 = alice.transform(
        "alice", "bob", ct, "ct", request_id="same"
    )
    out2, _, replay2 = alice.transform(
        "alice", "bob", ct, "ct", request_id="same"
    )
    assert replay1 is False and replay2 is True
    assert out1 == out2
    assert bob.decrypt(out2) == b"replay" * 4


def test_per_ciphertext_revocation_blocks_future_transforms(system):
    alice, bob = system["alice"], system["bob"]
    _delegate(system, alice, "bob", system["pkB"])
    ct = alice.encrypt(system["pkA"], b"revoke me")
    # A transform already completed stays valid.
    done, _, _ = alice.transform("alice", "bob", ct, "old", request_id="r-old")
    assert bob.decrypt(done) == b"revoke me"
    alice.revoke_ciphertext("old")
    # Same ciphertext cannot be transformed again.
    with pytest.raises(Exception):
        alice.transform("alice", "bob", ct, "old", request_id="r-new")
    # A different ciphertext is unaffected.
    other, _, _ = alice.transform(
        "alice", "bob", ct, "other", request_id="r-other"
    )
    assert bob.decrypt(other) == b"revoke me"


def test_time_window_revocation(system):
    alice, carol = system["alice"], system["carol"]
    _delegate(system, alice, "carol", system["pkC"])
    ct = alice.encrypt(system["pkA"], b"window")
    # Revocation scheduled in the future is not yet effective.
    alice.revoke_delegation("carol", not_before=time.time() + 3600)
    out, _, _ = alice.transform(
        "alice", "carol", ct, "w1", request_id="rw1"
    )
    assert carol.decrypt(out) == b"window"
    # A separate delegation already inside its revocation window is blocked.
    bob = system["bob"]
    _delegate(system, alice, "bob", system["pkB"])
    alice.revoke_delegation("bob", not_before=time.time() - 1)
    with pytest.raises(httpx.HTTPStatusError) as exc:
        alice.transform("alice", "bob", ct, "w2", request_id="rw2")
    assert exc.value.response.status_code == 409
    assert exc.value.response.json()["code"] == "RevokedError"


def test_concurrent_rotation_pins_definite_version(system):
    alice, bob = system["alice"], system["bob"]
    v1 = _delegate(system, alice, "bob", system["pkB"])
    # Rotate to v2.
    v2 = alice.rotate_delegation("bob", alice.make_rekey(system["pkB"]))
    assert v2 == v1 + 1
    ct = alice.encrypt(system["pkA"], b"versioned")
    # An in-flight request pinning v1 still completes on v1.
    out1, used1, _ = alice.transform(
        "alice", "bob", ct, "v1", pin_version=1, request_id="rv1"
    )
    assert used1 == 1 and bob.decrypt(out1) == b"versioned"
    # New requests land on the active v2.
    out2, used2, _ = alice.transform(
        "alice", "bob", ct, "v2", request_id="rv2"
    )
    assert used2 == 2 and bob.decrypt(out2) == b"versioned"


def test_unauthorized_delegation_is_denied_and_audited(system):
    bob, alice = system["bob"], system["alice"]
    rk = bob.make_rekey(system["pkC"])
    response = bob._signed_post(
        "/delegations",
        {
            "delegator": "alice",
            "delegatee": "carol",
            "rekey": schemas.b64e(rk),
        },
    )
    assert response.status_code == 401
    audit = alice.audit()
    assert any(
        entry["result"] == "denied" and entry["action"] == "create_delegation"
        for entry in audit
    )


def test_malformed_ciphertext_returns_distinct_error(system):
    test_client = system["test_client"]
    response = test_client.post(
        "/transform",
        json={
            "request_id": "bad",
            "delegator": "alice",
            "delegatee": "bob",
            "ciphertext": schemas.b64e(b"not-a-ciphertext"),
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "FormatError"


def test_every_transform_is_audited(system):
    alice, bob = system["alice"], system["bob"]
    _delegate(system, alice, "bob", system["pkB"])
    ct = alice.encrypt(system["pkA"], b"audit me")
    alice.transform("alice", "bob", ct, "aud", request_id="ra")
    audit = alice.audit(actor="proxy")
    assert any(
        e["action"] == "transform" and e["result"] == "ok"
        and e["request_id"] == "ra"
        for e in audit
    )

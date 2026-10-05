"""Crash recovery and concurrency semantics."""

from __future__ import annotations

import threading

from pre import crypto
from pre.api import create_app
from pre.client import Client
from pre.storage import Storage


def test_state_survives_process_restart(tmp_path):
    db_path = str(tmp_path / "restart.db")
    from starlette.testclient import TestClient

    app1 = create_app(db_path)
    tc1 = TestClient(app1)
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    alice = Client("http://local", "alice", sk_a, pk_a, transport=tc1._transport)
    bob = Client("http://local", "bob", sk_b, pk_b, transport=tc1._transport)
    alice.register()
    bob.register()
    alice.create_delegation("bob", alice.make_rekey(pk_b))
    ct = alice.encrypt(pk_a, b"persist me")
    out, _, _ = alice.transform("alice", "bob", ct, "c", request_id="persist")
    assert bob.decrypt(out) == b"persist me"
    alice.revoke_ciphertext("c-revoked")
    app1.state.service.storage.close()

    # Simulate a process restart by reopening the same database.
    app2 = create_app(db_path)
    tc2 = TestClient(app2)
    alice2 = Client("http://local", "alice", sk_a, pk_a, transport=tc2._transport)
    bob2 = Client("http://local", "bob", sk_b, pk_b, transport=tc2._transport)
    # Replay of an applied request returns the same stored result.
    out2, _, replayed = alice2.transform(
        "alice", "bob", ct, "c", request_id="persist"
    )
    assert replayed is True and out2 == out
    assert bob2.decrypt(out2) == b"persist me"
    # Revocation state persisted.
    svc = app2.state.service
    ok, reason = svc.storage.delegation_usable(
        "alice", "bob", 1, __import__("time").time(), "c-revoked"
    )
    assert ok is False and reason == "ciphertext revoked"
    # Delegation version history persisted.
    assert svc.storage.latest_delegation_version("alice", "bob") == 1


def test_concurrent_transforms_each_get_a_definite_result(tmp_path):
    from starlette.testclient import TestClient

    db_path = str(tmp_path / "concurrent.db")
    app = create_app(db_path)
    tc = TestClient(app)
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    alice = Client("http://local", "alice", sk_a, pk_a, transport=tc._transport)
    bob = Client("http://local", "bob", sk_b, pk_b, transport=tc._transport)
    alice.register()
    bob.register()
    alice.create_delegation("bob", alice.make_rekey(pk_b))
    message = b"concurrent" * 4

    results: list[bytes] = []
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            ct = alice.encrypt(pk_a, message)
            out, _, _ = alice.transform(
                "alice", "bob", ct, f"c{idx}", request_id=f"req{idx}"
            )
            assert bob.decrypt(out) == message
            results.append(out)
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(results) == 6


def test_rotation_concurrent_with_transforms_never_corrupts(tmp_path):
    from starlette.testclient import TestClient

    db_path = str(tmp_path / "rotate.db")
    app = create_app(db_path)
    tc = TestClient(app)
    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    alice = Client("http://local", "alice", sk_a, pk_a, transport=tc._transport)
    bob = Client("http://local", "bob", sk_b, pk_b, transport=tc._transport)
    alice.register()
    bob.register()
    alice.create_delegation("bob", alice.make_rekey(pk_b))

    stop = threading.Event()
    failures: list[Exception] = []

    def rotator() -> None:
        try:
            for i in range(3):
                alice.rotate_delegation("bob", alice.make_rekey(pk_b))
        except Exception as exc:  # pragma: no cover
            failures.append(exc)
        finally:
            stop.set()

    def transformer(idx: int) -> None:
        counter = 0
        try:
            while not stop.is_set():
                ct = alice.encrypt(pk_a, b"race")
                counter += 1
                out, version, _ = alice.transform(
                    "alice", "bob", ct, f"race{idx}",
                    request_id=f"r{idx}-{counter}",
                )
                assert version in (1, 2, 3, 4)
                assert bob.decrypt(out) == b"race"
        except Exception as exc:  # pragma: no cover
            failures.append(exc)

    workers = [threading.Thread(target=transformer, args=(i,)) for i in range(3)]
    rot = threading.Thread(target=rotator)
    rot.start()
    for w in workers:
        w.start()
    rot.join()
    for w in workers:
        w.join()
    assert not failures, failures

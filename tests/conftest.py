"""Shared fixtures: an in-process HTTP app with local client SDKs."""

from __future__ import annotations

import os
import tempfile

import pytest
from starlette.testclient import TestClient

from pre import crypto
from pre.api import create_app
from pre.client import Client


@pytest.fixture()
def tmp_db() -> str:
    return os.path.join(tempfile.mkdtemp(prefix="pre-test-"), "data.db")


@pytest.fixture()
def system(tmp_db):
    app = create_app(tmp_db)
    test_client = TestClient(app)
    transport = test_client._transport

    sk_a, pk_a = crypto.keygen()
    sk_b, pk_b = crypto.keygen()
    sk_c, pk_c = crypto.keygen()
    alice = Client("http://local", "alice", sk_a, pk_a, transport=transport)
    bob = Client("http://local", "bob", sk_b, pk_b, transport=transport)
    carol = Client("http://local", "carol", sk_c, pk_c, transport=transport)
    alice.register()
    bob.register()
    carol.register()

    yield {
        "app": app,
        "test_client": test_client,
        "transport": transport,
        "alice": alice,
        "bob": bob,
        "carol": carol,
        "pkA": pk_a,
        "pkB": pk_b,
        "pkC": pk_c,
        "db_path": tmp_db,
    }
    test_client.close()

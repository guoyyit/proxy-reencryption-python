"""Shared fixtures: temp service and local parties."""

from __future__ import annotations

import pytest

from app import crypto
from app.client import KeyMaterial, create_key_material
from app.service import PREService
from app.storage import Store


@pytest.fixture
def service(tmp_path):
    db = tmp_path / "pre.db"
    store = Store(db)
    svc = PREService(store)
    yield svc
    store.close()


@pytest.fixture
def parties():
    alice = create_key_material("alice")
    bob = create_key_material("bob")
    carol = create_key_material("carol")
    return alice, bob, carol


@pytest.fixture
def registered_service(service, parties):
    alice, bob, carol = parties
    for material in parties:
        service.register_user(
            user_id=material.user_id,
            verify_key=material.signing_public_hex,
            public_key=material.pre_public_json,
            request_id=f"reg-{material.user_id}",
        )
    return service


def _pk_of(material: KeyMaterial):
    return crypto.deserialize_public_key(material.pre_public_json)


def _sk_of(material: KeyMaterial):
    return crypto.deserialize_secret_key(material.pre_secret_hex)

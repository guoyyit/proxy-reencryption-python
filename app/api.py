"""HTTP layer exposing the local proxy re-encryption service."""

from __future__ import annotations

import json
import os
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app import auth, crypto
from app.errors import PREError, UnauthorizedError
from app.revocation import to_iso, utc_now
from app.service import PROXY_ACTOR, PREService
from app.storage import Store

DEFAULT_DB_PATH = "./data/pre_service.db"

app = FastAPI(title="Local Proxy Re-Encryption Service", version="1.0.0")


def get_store() -> Store:
    store = getattr(app.state, "store", None)
    if store is None:
        store = Store(os.environ.get("PRE_DB_PATH", DEFAULT_DB_PATH))
        app.state.store = store
        app.state.service = PREService(store)
    return store


def get_service() -> PREService:
    get_store()
    return app.state.service


@app.on_event("startup")
def _startup() -> None:
    get_store()


@app.on_event("shutdown")
def _shutdown() -> None:
    store = getattr(app.state, "store", None)
    if store is not None:
        store.close()


@app.exception_handler(PREError)
async def _pre_error_handler(_: Request, exc: PREError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.http_status,
        content={"error": {"code": exc.code, "message": exc.message, "details": exc.details}},
    )


async def _read_json(request: Request) -> tuple[dict[str, Any], bytes]:
    raw = await request.body()
    if not raw:
        return {}, b""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        from app.errors import MalformedCiphertextError

        raise MalformedCiphertextError("request body must be JSON") from exc
    if not isinstance(data, dict):
        from app.errors import ValidationError

        raise ValidationError("request body must be a JSON object")
    return data, raw


def _authenticate(request: Request, raw: bytes) -> str:
    """Verify the signed request and replay nonce; return the authenticated user id."""
    service = get_service()
    headers = {k.lower(): v for k, v in request.headers.items()}
    user_id = headers.get("x-user-id", "")
    row = service.store.get_user(user_id)
    verify_key = row["verify_key"] if row is not None else None
    actor = auth.authenticate_headers(
        headers, request.method, request.url.path, raw, verify_key
    )
    nonce = headers.get("x-nonce", "")
    if not service.store.check_and_store_nonce(f"{actor}:{nonce}", to_iso(utc_now())):
        # A retried request carrying the same Idempotency-Key is a legitimate
        # replay and is answered from the stored response by the route.
        idem_key = headers.get("x-idempotency-key")
        if not idem_key or service.store.get_idempotent(idem_key) is None:
            raise UnauthorizedError("replayed request nonce")
    return actor


def _idem_replay(idem_key: str | None) -> JSONResponse | None:
    if not idem_key:
        return None
    row = get_service().store.get_idempotent(idem_key)
    if row is None:
        return None
    return JSONResponse(status_code=row["status_code"], content=json.loads(row["body"]))


def _idem_store(idem_key: str | None, actor: str, status_code: int, payload: dict[str, Any]) -> None:
    if idem_key:
        get_service().store.store_idempotent(
            idem_key, actor, to_iso(utc_now()), status_code, json.dumps(payload)
        )


# ---------------------------------------------------------------- health / keygen
@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/users")
async def register_user(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    # registration is self-service: proof of possession of the signing key is
    # given by the signed request itself, using the embedded verify key.
    headers = {k.lower(): v for k, v in request.headers.items()}
    user_id = headers.get("x-user-id") or data.get("user_id")
    if not user_id:
        from app.errors import ValidationError

        raise ValidationError("user_id is required")
    verify_key = data.get("verify_key")
    public_key = data.get("public_key")
    if not verify_key or not public_key:
        from app.errors import ValidationError

        raise ValidationError("verify_key and public_key are required")
    service = get_service()
    # Proof of possession of the presented Ed25519 key. If the id already
    # exists, the signature must verify against the *stored* key, preventing
    # account/id squatting with a self-issued replacement key.
    existing = service.store.get_user(user_id)
    verification_key = existing["verify_key"] if existing is not None else verify_key
    auth.authenticate_headers(
        headers, request.method, request.url.path, raw, verification_key
    )
    if existing is not None and existing["verify_key"] != verify_key:
        from app.errors import ConflictError

        raise ConflictError("user id already registered with a different signing key")
    idem = headers.get("x-idempotency-key")
    replay = _idem_replay(idem)
    if replay is not None:
        return replay
    result = service.register_user(
        user_id=user_id, verify_key=verify_key, public_key=public_key,
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, user_id, 201, result)
    return JSONResponse(status_code=201, content=result)


@app.post("/crypto/encrypt")
async def encrypt_for_user(request: Request) -> JSONResponse:
    """Public operation: anyone can encrypt to a registered public key."""
    data, _ = await _read_json(request)
    service = get_service()
    owner_id = data.get("owner_id")
    plaintext_hex = data.get("plaintext_hex", "")
    associated_data = bytes.fromhex(data.get("associated_data_hex", ""))
    row = service.store.get_user(owner_id) if owner_id else None
    if row is None:
        from app.errors import NotFoundError

        raise NotFoundError("owner not registered")
    pk = crypto.deserialize_public_key(row["pub_key"])
    try:
        plaintext = bytes.fromhex(plaintext_hex)
    except ValueError as exc:
        from app.errors import ValidationError

        raise ValidationError("plaintext_hex must be hex") from exc
    ct = crypto.encrypt(pk, plaintext, associated_data)
    return JSONResponse(content={"ciphertext": crypto.serialize_ciphertext(ct)})


def _authenticated(request: Request, raw: bytes) -> tuple[str, dict[str, str]]:
    headers = {k.lower(): v for k, v in request.headers.items()}
    actor = _authenticate(request, raw)
    return actor, headers


@app.post("/ciphertexts")
async def register_ciphertext(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    result = service.register_ciphertext(
        owner_id=actor,
        ciphertext_id=data.get("ciphertext_id"),
        ciphertext=data.get("ciphertext", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 201, result)
    return JSONResponse(status_code=201, content=result)


@app.post("/delegations")
async def create_delegation(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    result = service.create_delegation(
        owner_id=actor,
        delegatee_id=data.get("delegatee_id", ""),
        rk_json=data.get("re_encryption_key", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 201, result)
    return JSONResponse(status_code=201, content=result)


@app.post("/delegations/rotate")
async def rotate_rekey(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    result = service.rotate_rekey(
        owner_id=actor,
        delegatee_id=data.get("delegatee_id", ""),
        rk_json=data.get("re_encryption_key", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 200, result)
    return JSONResponse(content=result)


@app.post("/delegations/revoke")
async def revoke_delegation(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    result = service.revoke_delegation(
        owner_id=actor,
        delegatee_id=data.get("delegatee_id", ""),
        reason=data.get("reason", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 200, result)
    return JSONResponse(content=result)


@app.post("/revocations/ciphertext")
async def revoke_ciphertext(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    result = service.revoke_ciphertext(
        owner_id=actor,
        ciphertext_id=data.get("ciphertext_id", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 200, result)
    return JSONResponse(content=result)


@app.post("/revocations/window")
async def add_window(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    actor, headers = _authenticated(request, raw)
    service = get_service()
    idem = headers.get("x-idempotency-key")
    if (replay := _idem_replay(idem)) is not None:
        return replay
    target = data.get("target", data.get("delegatee_id", ""))
    result = service.add_revocation_window(
        owner_id=actor,
        delegatee_id=data.get("delegatee_id"),
        target=target,
        not_before=data.get("not_before"),
        not_after=data.get("not_after"),
        reason=data.get("reason", ""),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    _idem_store(idem, actor, 201, result)
    return JSONResponse(status_code=201, content=result)


@app.post("/reencrypt")
async def reencrypt(request: Request) -> JSONResponse:
    data, raw = await _read_json(request)
    # the proxy endpoint is invoked by the delegatee (or anyone holding the
    # delegation reference); authorization to actually convert is enforced by
    # the existence of an owner-created delegation and the revocation state.
    headers = {k.lower(): v for k, v in request.headers.items()}
    actor = headers.get("x-user-id", PROXY_ACTOR)
    if "x-signature" in headers:
        actor = _authenticate(request, raw)
    service = get_service()
    result = service.reencrypt(
        owner_id=data.get("owner_id", ""),
        delegatee_id=data.get("delegatee_id", ""),
        ciphertext_id=data.get("ciphertext_id", ""),
        expected_version=data.get("expected_version"),
        request_id=headers.get("x-request-id", uuid4().hex),
    )
    return JSONResponse(content=result)


@app.get("/audit")
async def read_audit(request: Request) -> JSONResponse:
    raw = b""
    actor = _authenticate(request, raw)
    service = get_service()
    action = request.query_params.get("action")
    limit = min(int(request.query_params.get("limit", "200")), 1000)
    rows = service.list_audit(requester_id=actor, action=action, limit=limit)
    return JSONResponse(content={"audit": rows})

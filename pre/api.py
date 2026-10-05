"""FastAPI HTTP layer exposing the local proxy re-encryption service."""

from __future__ import annotations

import os

from fastapi import FastAPI, Header, Request
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse

from . import schemas
from .errors import (
    AuthError,
    ConflictError,
    FormatError,
    NotFoundError,
    PREError,
    RevokedError,
    TamperError,
)
from .service import Service
from .storage import Storage

DB_PATH = os.environ.get("PRE_DB_PATH", os.path.join(os.getcwd(), "pre_data.db"))


def create_app(db_path: str | None = None) -> FastAPI:
    storage = Storage(db_path or DB_PATH)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            yield
        finally:
            storage.close()

    app = FastAPI(
        title="Local Proxy Re-Encryption Service",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.service = Service(storage)

    @app.exception_handler(PREError)
    async def handle_pre_error(_: Request, exc: PREError) -> JSONResponse:
        status = {
            FormatError: 422,
            TamperError: 422,
            AuthError: 401,
            RevokedError: 409,
            NotFoundError: 404,
            ConflictError: 409,
        }.get(type(exc), 400)
        return JSONResponse(
            status_code=status,
            content={
                "error": type(exc).__name__,
                "code": type(exc).__name__,
                "detail": str(exc),
            },
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/users/register")
    async def register(body: schemas.RegisterRequest) -> dict:
        app.state.service.register_user(
            body.user_id, schemas.b64d(body.public_key)
        )
        return {"user_id": body.user_id, "status": "registered"}

    def _require_auth(
        user: str,
        path: str,
        raw: bytes,
        x_timestamp: str,
        x_nonce: str,
        x_signature: str,
        method: str = "POST",
    ) -> None:
        app.state.service.authenticate(
            user,
            method,
            path,
            float(x_timestamp),
            x_nonce,
            raw,
            schemas.b64d(x_signature),
        )

    @app.post("/delegations")
    async def create_delegation(
        request: Request,
        x_user: str = Header(...),
        x_timestamp: str = Header(...),
        x_nonce: str = Header(...),
        x_signature: str = Header(...),
    ) -> schemas.VersionResponse:
        raw, body = await _parse(request, schemas.DelegationRequest)
        _require_auth(
            x_user, "/delegations", raw,
            x_timestamp, x_nonce, x_signature,
        )
        if x_user != body.delegator:
            app.state.service.storage.append_audit(
                x_user, "create_delegation",
                f"ownership violation target={body.delegator}",
                "denied",
                delegator=body.delegator, delegatee=body.delegatee,
            )
            raise AuthError("only the delegator may create a delegation")
        version = app.state.service.create_delegation(
            body.delegator, body.delegatee, schemas.b64d(body.rekey)
        )
        return schemas.VersionResponse(
            delegator=body.delegator, delegatee=body.delegatee, version=version
        )

    @app.post("/delegations/rotate")
    async def rotate_delegation(
        request: Request,
        x_user: str = Header(...),
        x_timestamp: str = Header(...),
        x_nonce: str = Header(...),
        x_signature: str = Header(...),
    ) -> schemas.VersionResponse:
        raw, body = await _parse(request, schemas.DelegationRequest)
        _require_auth(
            x_user, "/delegations/rotate", raw,
            x_timestamp, x_nonce, x_signature,
        )
        if x_user != body.delegator:
            app.state.service.storage.append_audit(
                x_user, "rotate_delegation",
                f"ownership violation target={body.delegator}",
                "denied",
                delegator=body.delegator, delegatee=body.delegatee,
            )
            raise AuthError("only the delegator may rotate a delegation")
        version = app.state.service.rotate_rekey(
            body.delegator, body.delegatee, schemas.b64d(body.rekey)
        )
        return schemas.VersionResponse(
            delegator=body.delegator, delegatee=body.delegatee, version=version
        )

    @app.post("/delegations/revoke")
    async def revoke_delegation(
        request: Request,
        x_user: str = Header(...),
        x_timestamp: str = Header(...),
        x_nonce: str = Header(...),
        x_signature: str = Header(...),
    ) -> schemas.VersionResponse:
        raw, body = await _parse(request, schemas.RevokeRequest)
        _require_auth(
            x_user, "/delegations/revoke", raw,
            x_timestamp, x_nonce, x_signature,
        )
        if x_user != body.delegator:
            app.state.service.storage.append_audit(
                x_user, "revoke_delegation",
                f"ownership violation target={body.delegator}",
                "denied",
                delegator=body.delegator, delegatee=body.delegatee,
            )
            raise AuthError("only the delegator may revoke a delegation")
        version = app.state.service.revoke(
            body.delegator,
            body.delegatee,
            version=body.version,
            not_before=body.not_before,
        )
        return schemas.VersionResponse(
            delegator=body.delegator, delegatee=body.delegatee, version=version
        )

    @app.post("/ciphertexts/revoke")
    async def revoke_ciphertext(
        request: Request,
        x_user: str = Header(...),
        x_timestamp: str = Header(...),
        x_nonce: str = Header(...),
        x_signature: str = Header(...),
    ) -> dict:
        raw, body = await _parse(request, schemas.CiphertextRevokeRequest)
        _require_auth(
            x_user, "/ciphertexts/revoke", raw,
            x_timestamp, x_nonce, x_signature,
        )
        if x_user != body.delegator:
            app.state.service.storage.append_audit(
                x_user, "revoke_ciphertext",
                f"ownership violation target={body.delegator}",
                "denied",
                delegator=body.delegator,
            )
            raise AuthError("only the data owner may revoke a ciphertext")
        app.state.service.revoke_ciphertext(
            body.delegator, body.ciphertext_id, body.delegatee
        )
        return {"status": "revoked", "ciphertext_id": body.ciphertext_id}

    @app.post("/transform")
    async def transform(body: schemas.TransformRequest) -> schemas.TransformResponse:
        existing = app.state.service.storage.get_transform(body.request_id)
        replayed = existing is not None
        result = app.state.service.transform(
            body.request_id,
            body.delegator,
            body.delegatee,
            schemas.b64d(body.ciphertext),
            ciphertext_id=body.ciphertext_id,
            pin_version=body.pin_version,
        )
        row = app.state.service.storage.get_transform(body.request_id)
        return schemas.TransformResponse(
            request_id=body.request_id,
            version=int(row["version"]),
            ciphertext=schemas.b64e(result),
            replayed=replayed,
        )

    @app.get("/audit")
    async def audit(limit: int = 200, actor: str | None = None) -> dict:
        return {"entries": app.state.service.audit_trail(limit, actor)}

    return app


async def _parse(request: Request, model: type):
    raw = await request.body()
    try:
        return raw, model.model_validate_json(raw)
    except Exception as exc:
        raise FormatError("invalid request body") from exc


app = create_app()

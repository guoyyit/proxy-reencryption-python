"""Domain errors with stable, distinguishable codes returned over HTTP."""

from __future__ import annotations


class PREError(Exception):
    """Base class for all service errors."""

    code: str = "internal_error"
    http_status: int = 500

    def __init__(self, message: str = "", *, details: dict | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details = details or {}


class ValidationError(PREError):
    code = "validation_error"
    http_status = 400


class MalformedCiphertextError(PREError):
    code = "malformed_ciphertext"
    http_status = 400


class CiphertextTamperedError(PREError):
    code = "ciphertext_tampered"
    http_status = 400


class WrongKeyError(PREError):
    code = "wrong_key"
    http_status = 400


class UnauthorizedError(PREError):
    code = "unauthorized"
    http_status = 401


class ForbiddenError(PREError):
    code = "forbidden"
    http_status = 403


class NotFoundError(PREError):
    code = "not_found"
    http_status = 404


class ConflictError(PREError):
    code = "conflict"
    http_status = 409


class RevokedError(PREError):
    """Base class for all revocation outcomes (match on .code to distinguish)."""

    code = "delegation_revoked"
    http_status = 403


class CiphertextRevokedError(RevokedError):
    code = "ciphertext_revoked"
    http_status = 403


class RevocationWindowActiveError(RevokedError):
    code = "revocation_window_active"
    http_status = 403


class StaleVersionError(PREError):
    code = "stale_reencryption_key_version"
    http_status = 409

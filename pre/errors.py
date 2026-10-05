"""Distinguishable error types for the PRE service."""


class PREError(Exception):
    """Base class for all service errors."""


class FormatError(PREError):
    """Malformed serialization or bad parameters."""


class TamperError(PREError):
    """Ciphertext / data failed integrity checks."""


class AuthError(PREError):
    """Authentication or authorization failure."""


class RevokedError(PREError):
    """Delegation is revoked for the requested target."""


class NotFoundError(PREError):
    """Referenced entity does not exist."""


class ConflictError(PREError):
    """Optimistic concurrency / version conflict."""

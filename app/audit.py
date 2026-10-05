"""Audit action names and result labels shared across layers."""

from __future__ import annotations

REGISTER = "register"
REGISTER_CIPHERTEXT = "register_ciphertext"
CREATE_DELEGATION = "create_delegation"
ROTATE_REKEY = "rotate_rekey"
REVOKE_CIPHERTEXT = "revoke_ciphertext"
REVOKE_DELEGATION = "revoke_delegation"
ADD_REVOCATION_WINDOW = "add_revocation_window"
REENCRYPT = "reencrypt"

SUCCESS = "success"
DENIED = "denied"
ERROR = "error"

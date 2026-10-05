"""End-to-end local demonstration.

Runs the full lifecycle against a live HTTP server:

  1. three users generate local key material (PRE + signing keys);
  2. the data owner encrypts a document and registers it;
  3. the owner creates a re-encryption key locally (never exposing the private
     key) and delegates to a chosen user;
  4. the proxy converts the ciphertext without seeing plaintext;
  5. the delegatee decrypts; third parties cannot;
  6. per-ciphertext and time-window revocations are shown;
  7. key rotation is shown with version numbers;
  8. the audit trail is printed.

Usage:
    uv run python scripts/demo.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.client import PREClient, create_key_material  # noqa: E402
from app.revocation import to_iso  # noqa: E402


def _wait_for_server(base_url: str) -> None:
    for _ in range(60):
        try:
            if httpx.get(f"{base_url}/health", timeout=1.0).status_code == 200:
                return
        except httpx.TransportError:
            time.sleep(0.25)
    raise RuntimeError("server did not become ready")


def main() -> None:
    workdir = tempfile.mkdtemp(prefix="pre-demo-")
    db_path = os.path.join(workdir, "demo.db")
    env = {**os.environ, "PRE_DB_PATH": db_path}
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8765"],
        cwd=Path(__file__).resolve().parent.parent,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = "http://127.0.0.1:8765"
    try:
        _wait_for_server(base)
        alice_mat = create_key_material("alice")
        bob_mat = create_key_material("bob")
        carol_mat = create_key_material("carol")

        with (
            PREClient(base, alice_mat) as alice,
            PREClient(base, bob_mat) as bob,
            PREClient(base, carol_mat) as carol,
        ):
            print("== register users ==")
            for client in (alice, bob, carol):
                print(client.register())

            print("\n== owner encrypts ==")
            message = b"contract v1: quarterly results"
            encrypted = httpx.post(
                f"{base}/crypto/encrypt",
                json={"owner_id": "alice", "plaintext_hex": message.hex()},
                timeout=30,
            ).json()["ciphertext"]
            assert alice.decrypt_own(encrypted) == message
            registered = alice.register_ciphertext(encrypted, ciphertext_id="doc-1")
            print(registered)

            print("\n== owner delegates alice -> bob ==")
            rk_v1 = alice.make_re_encryption_key(bob_mat.pre_public_json)
            print(alice.create_delegation("bob", rk_v1))

            print("\n== proxy re-encrypts (no plaintext access) ==")
            converted = httpx.post(
                f"{base}/reencrypt",
                json={"owner_id": "alice", "delegatee_id": "bob", "ciphertext_id": "doc-1"},
                timeout=60,
            ).json()
            print("version used:", converted["version"])
            assert bob.decrypt_delegated(converted["ciphertext"]) == message
            print("bob decrypted:", bob.decrypt_delegated(converted["ciphertext"]).decode())

            print("\n== carol (non-delegatee) cannot decrypt ==")
            try:
                carol.decrypt_delegated(converted["ciphertext"])
            except Exception as exc:  # noqa: BLE001
                print("carol rejected:", type(exc).__name__)

            print("\n== rotate re-encryption key to v2 ==")
            rk_v2 = alice.make_re_encryption_key(bob_mat.pre_public_json)
            print(alice.rotate("bob", rk_v2))

            print("\n== time-window revocation (suspend delegation 5 minutes) ==")
            now = datetime.now(timezone.utc)
            print(alice.add_revocation_window(
                target="bob",
                not_before=to_iso(now - timedelta(minutes=1)),
                not_after=to_iso(now + timedelta(minutes=5)),
                reason="temporary suspension",
            ))
            window_denied = httpx.post(
                f"{base}/reencrypt",
                json={"owner_id": "alice", "delegatee_id": "bob", "ciphertext_id": "doc-1"},
                timeout=60,
            )
            print("conversion inside window:", window_denied.status_code,
                  window_denied.json()["error"]["code"])

            print("\n== per-ciphertext revocation ==")
            print(alice.revoke_ciphertext("doc-1"))
            denied = httpx.post(
                f"{base}/reencrypt",
                json={"owner_id": "alice", "delegatee_id": "bob", "ciphertext_id": "doc-1"},
                timeout=60,
            )
            print("conversion after revocation:", denied.status_code, denied.json()["error"]["code"])

            print("\n== audit trail (alice) ==")
            for row in alice.audit()["audit"][:8]:
                print(row["ts"], row["action"], row["result"], row["details"])

    finally:
        server.terminate()
        server.wait(timeout=10)
        print(f"\nDemo database kept at: {db_path}")


if __name__ == "__main__":
    main()

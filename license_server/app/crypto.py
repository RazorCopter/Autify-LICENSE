import base64
import hashlib
import json
import os
import time
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status


def _key() -> bytes:
    secret = os.getenv("LICENSE_SHARED_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("LICENSE_SHARED_SECRET deve contenere almeno 32 caratteri")
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _license_code_key() -> bytes:
    secret = os.getenv("LICENSE_ADMIN_KEY", "")
    if len(secret) < 24:
        raise RuntimeError("LICENSE_ADMIN_KEY deve contenere almeno 24 caratteri")
    return hashlib.sha256(b"autify-license-code-storage-v1\0" + secret.encode("utf-8")).digest()


def encrypt_license_code(code: str, code_hash: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_license_code_key()).encrypt(nonce, code.encode("utf-8"), code_hash.encode("ascii"))
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_license_code(encrypted_code: str, code_hash: str) -> str:
    try:
        encrypted = base64.b64decode(encrypted_code, altchars=b"-_", validate=True)
        if len(encrypted) < 29:
            raise ValueError("Codice cifrato non valido")
        plaintext = AESGCM(_license_code_key()).decrypt(
            encrypted[:12], encrypted[12:], code_hash.encode("ascii")
        )
        return plaintext.decode("utf-8")
    except (InvalidTag, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Codice cifrato non valido") from exc


def encrypt_payload(payload: dict[str, Any]) -> dict[str, str]:
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
    }


def decrypt_payload(envelope: dict[str, str], *, validate_freshness: bool = True) -> dict[str, Any]:
    try:
        nonce = base64.urlsafe_b64decode(envelope["nonce"])
        ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"])
        data = AESGCM(_key()).decrypt(nonce, ciphertext, None)
        payload = json.loads(data.decode("utf-8"))
    except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Payload cifrato non valido") from exc

    if validate_freshness:
        timestamp = payload.get("timestamp")
        request_nonce = payload.get("request_nonce")
        freshness_seconds = int(os.getenv("LICENSE_REQUEST_FRESHNESS_SECONDS", "120"))
        if not isinstance(timestamp, int) or abs(int(time.time()) - timestamp) > freshness_seconds:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Timestamp richiesta non valido")
        if not isinstance(request_nonce, str) or len(request_nonce) < 16:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce richiesta non valido")
    return payload

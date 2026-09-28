import hashlib
import os
import secrets
import sqlite3
import string
import calendar
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .crypto import decrypt_payload, encrypt_payload

DB_PATH = Path(os.getenv("LICENSE_DB_PATH", "/data/licenses.db"))
VALID_PLANS = {"1M": 1, "6M": 6, "12M": 12, "LIFE": None}
limiter = Limiter(key_func=get_remote_address)

@contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def initialize_database() -> None:
    with db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                code_hash TEXT PRIMARY KEY,
                code_suffix TEXT NOT NULL,
                plan TEXT NOT NULL,
                customer TEXT,
                created_at TEXT NOT NULL,
                activated_at TEXT,
                expires_at TEXT,
                instance_id TEXT,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS request_nonces (
                nonce TEXT PRIMARY KEY,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_license_instance ON licenses(instance_id);
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(licenses)")}
        if "token_hash" not in columns:
            connection.execute("ALTER TABLE licenses ADD COLUMN token_hash TEXT")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_license_token ON licenses(token_hash)")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Valida i segreti al bootstrap, prima di accettare traffico.
    from .crypto import _key
    _key()
    admin_key = os.getenv("LICENSE_ADMIN_KEY", "")
    if len(admin_key) < 24:
        raise RuntimeError("LICENSE_ADMIN_KEY deve contenere almeno 24 caratteri")
    initialize_database()
    yield


app = FastAPI(title="Autify License Server", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class Envelope(BaseModel):
    nonce: str
    ciphertext: str


class GenerateRequest(BaseModel):
    plan: str = Field(pattern="^(1M|6M|12M|LIFE)$")
    customer: str | None = Field(default=None, max_length=200)
    quantity: int = Field(default=1, ge=1, le=100)


class CodeRequest(BaseModel):
    code: str


def require_admin(x_license_admin_key: str = Header(default="")) -> None:
    configured = os.getenv("LICENSE_ADMIN_KEY", "")
    if len(configured) < 24 or not secrets.compare_digest(x_license_admin_key, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chiave amministrativa non valida")


def code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def checksum(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()[:6].upper()


def generate_code(plan: str) -> str:
    alphabet = string.ascii_uppercase + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(16))
    base = f"AUTIFY-{plan}-{random_part}"
    return f"{base}-{checksum(base)}"


def normalize_code(code: str) -> str:
    normalized = code.strip().upper()
    parts = normalized.split("-")
    if len(parts) != 4 or parts[0] != "AUTIFY" or parts[1] not in VALID_PLANS or checksum("-".join(parts[:3])) != parts[3]:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Codice licenza non valido")
    return normalized


def add_months(value: datetime, months: int) -> datetime:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def consume_nonce(connection: sqlite3.Connection, nonce: str, timestamp: int) -> None:
    # BEGIN IMMEDIATE serializza check/inserimento tra processi prima di ogni altra scrittura.
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("DELETE FROM request_nonces WHERE created_at < ?", (timestamp - 600,))
    try:
        connection.execute("INSERT INTO request_nonces(nonce, created_at) VALUES (?, ?)", (nonce, timestamp))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Richiesta già elaborata") from exc


def public_license(row: sqlite3.Row, now: datetime) -> dict:
    expires_at = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
    active = row["revoked_at"] is None and row["activated_at"] is not None and (expires_at is None or expires_at > now)
    reason = "active" if active else "revoked" if row["revoked_at"] else "expired" if row["activated_at"] else "not_activated"
    return {
        "valid": active,
        "reason": reason,
        "plan": row["plan"],
        "activated_at": row["activated_at"],
        "expires_at": row["expires_at"],
        "instance_id": row["instance_id"],
        "server_time": now.isoformat(),
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/admin/licenses", dependencies=[Depends(require_admin)])
def create_licenses(payload: GenerateRequest) -> dict:
    generated = []
    now = datetime.now(timezone.utc).isoformat()
    with db() as connection:
        for _ in range(payload.quantity):
            code = generate_code(payload.plan)
            connection.execute(
                "INSERT INTO licenses(code_hash, code_suffix, plan, customer, created_at) VALUES (?, ?, ?, ?, ?)",
                (code_hash(code), code[-6:], payload.plan, payload.customer, now),
            )
            generated.append(code)
    return {"codes": generated, "plan": payload.plan}


@app.post("/v1/admin/licenses/revoke", dependencies=[Depends(require_admin)])
def revoke_license(payload: CodeRequest) -> dict:
    code = normalize_code(payload.code)
    with db() as connection:
        result = connection.execute(
            "UPDATE licenses SET revoked_at = ? WHERE code_hash = ?", (datetime.now(timezone.utc).isoformat(), code_hash(code))
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Licenza non trovata")
    return {"status": "revoked"}


@app.post("/v1/admin/licenses/release", dependencies=[Depends(require_admin)])
def release_license(payload: CodeRequest) -> dict:
    code = normalize_code(payload.code)
    with db() as connection:
        result = connection.execute(
            "UPDATE licenses SET instance_id = NULL, activated_at = NULL, expires_at = NULL, revoked_at = NULL WHERE code_hash = ?",
            (code_hash(code),),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Licenza non trovata")
    return {"status": "released"}


@app.post("/v1/activate", response_model=Envelope)
@limiter.limit(os.getenv("LICENSE_ACTIVATE_RATE_LIMIT", "10/minute"))
def activate(request: Request, envelope: Envelope) -> dict:
    payload = decrypt_payload(envelope.model_dump())
    code = normalize_code(str(payload.get("code", "")))
    instance_id = str(payload.get("instance_id", ""))
    if len(instance_id) < 16:
        raise HTTPException(status_code=400, detail="Identificativo istanza non valido")

    now = datetime.now(timezone.utc)
    with db() as connection:
        consume_nonce(connection, payload["request_nonce"], int(payload["timestamp"]))
        row = connection.execute("SELECT * FROM licenses WHERE code_hash = ?", (code_hash(code),)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Licenza non trovata")
        if row["revoked_at"]:
            raise HTTPException(status_code=403, detail="Licenza revocata")
        if row["instance_id"] and row["instance_id"] != instance_id:
            raise HTTPException(status_code=409, detail="Licenza già associata a un'altra istanza")
        opaque_token = secrets.token_urlsafe(32)
        if not row["activated_at"]:
            months = VALID_PLANS[row["plan"]]
            expires_at = add_months(now, months).isoformat() if months else None
            connection.execute(
                "UPDATE licenses SET instance_id = ?, activated_at = ?, expires_at = ?, token_hash = ? WHERE code_hash = ?",
                (instance_id, now.isoformat(), expires_at, code_hash(opaque_token), code_hash(code)),
            )
        else:
            connection.execute(
                "UPDATE licenses SET token_hash = ? WHERE code_hash = ?",
                (code_hash(opaque_token), code_hash(code)),
            )
        row = connection.execute("SELECT * FROM licenses WHERE code_hash = ?", (code_hash(code),)).fetchone()
        result = public_license(row, now)
        result["license_token"] = opaque_token
    return encrypt_payload(result)


@app.post("/v1/validate", response_model=Envelope)
@limiter.limit(os.getenv("LICENSE_VALIDATE_RATE_LIMIT", "60/minute"))
def validate(request: Request, envelope: Envelope) -> dict:
    payload = decrypt_payload(envelope.model_dump())
    instance_id = str(payload.get("instance_id", ""))
    token = str(payload.get("license_token", ""))
    now = datetime.now(timezone.utc)
    with db() as connection:
        consume_nonce(connection, payload["request_nonce"], int(payload["timestamp"]))
        token_digest = code_hash(token)
        row = connection.execute(
            "SELECT * FROM licenses WHERE token_hash = ? OR (token_hash IS NULL AND code_hash = ?)",
            (token_digest, token),
        ).fetchone()
        if row is None or row["instance_id"] != instance_id:
            result = {"valid": False, "reason": "license_not_found", "server_time": now.isoformat()}
        else:
            result = public_license(row, now)
    return encrypt_payload(result)
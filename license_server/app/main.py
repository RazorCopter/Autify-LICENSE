import hashlib
import os
import secrets
import sqlite3
import string
import calendar
import threading
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .crypto import decrypt_license_code, decrypt_payload, encrypt_license_code, encrypt_payload

DB_PATH = Path(os.getenv("LICENSE_DB_PATH", "/data/licenses.db"))
STATIC_PATH = Path(__file__).resolve().parent / "static"
VALID_PLANS = {"1M": 1, "6M": 6, "12M": 12, "LIFE": None}
ADMIN_SESSION_COOKIE = "autify_license_admin_session"
limiter = Limiter(key_func=get_remote_address)
ADMIN_SESSIONS: dict[str, datetime] = {}
ADMIN_LOGIN_ATTEMPTS: dict[str, list[datetime]] = {}
ADMIN_STATE_LOCK = threading.Lock()

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
                revoked_at TEXT,
                encrypted_code TEXT
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
        if "encrypted_code" not in columns:
            connection.execute("ALTER TABLE licenses ADD COLUMN encrypted_code TEXT")
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


app = FastAPI(title="Autify License Server", version="1.2.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/admin", StaticFiles(directory=STATIC_PATH, html=True), name="admin")


class Envelope(BaseModel):
    nonce: str
    ciphertext: str


class GenerateRequest(BaseModel):
    plan: str = Field(pattern="^(1M|6M|12M|LIFE)$")
    customer: str | None = Field(default=None, max_length=200)
    quantity: int = Field(default=1, ge=1, le=100)


class CodeRequest(BaseModel):
    code: str


class AdminLoginRequest(BaseModel):
    admin_key: str = Field(min_length=1, max_length=1000)


def admin_key_is_valid(candidate: str) -> bool:
    configured = os.getenv("LICENSE_ADMIN_KEY", "")
    return len(configured) >= 24 and bool(candidate) and secrets.compare_digest(candidate, configured)


def session_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expiry() -> datetime:
    try:
        hours = int(os.getenv("LICENSE_ADMIN_SESSION_HOURS", "8"))
    except ValueError:
        hours = 8
    return datetime.now(timezone.utc) + timedelta(hours=max(1, min(hours, 168)))


def create_admin_session() -> tuple[str, datetime]:
    token = secrets.token_urlsafe(48)
    expires_at = session_expiry()
    now = datetime.now(timezone.utc)
    with ADMIN_STATE_LOCK:
        expired = [digest for digest, expiry in ADMIN_SESSIONS.items() if expiry <= now]
        for digest in expired:
            ADMIN_SESSIONS.pop(digest, None)
        ADMIN_SESSIONS[session_digest(token)] = expires_at
    return token, expires_at


def admin_session_is_valid(token: str) -> bool:
    if not token:
        return False
    digest = session_digest(token)
    now = datetime.now(timezone.utc)
    with ADMIN_STATE_LOCK:
        expires_at = ADMIN_SESSIONS.get(digest)
        if expires_at is None:
            return False
        if expires_at <= now:
            ADMIN_SESSIONS.pop(digest, None)
            return False
    return True


def register_admin_login_attempt(client_address: str) -> None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=15)
    with ADMIN_STATE_LOCK:
        attempts = [attempt for attempt in ADMIN_LOGIN_ATTEMPTS.get(client_address, []) if attempt > window_start]
        if len(attempts) >= 10:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Troppi tentativi di accesso. Riprova tra alcuni minuti",
            )
        attempts.append(now)
        ADMIN_LOGIN_ATTEMPTS[client_address] = attempts


def clear_admin_login_attempts(client_address: str) -> None:
    with ADMIN_STATE_LOCK:
        ADMIN_LOGIN_ATTEMPTS.pop(client_address, None)


def require_admin(request: Request, x_license_admin_key: str = Header(default="")) -> None:
    if admin_key_is_valid(x_license_admin_key):
        return
    if admin_session_is_valid(request.cookies.get(ADMIN_SESSION_COOKIE, "")):
        return
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticazione amministrativa richiesta")


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


def admin_license(row: sqlite3.Row, now: datetime) -> dict:
    public = public_license(row, now)
    return {
        "code_suffix": row["code_suffix"],
        "plan": row["plan"],
        "customer": row["customer"],
        "created_at": row["created_at"],
        "activated_at": row["activated_at"],
        "expires_at": row["expires_at"],
        "instance_id": row["instance_id"],
        "revoked_at": row["revoked_at"],
        "status": public["reason"],
        "code_available": row["encrypted_code"] is not None,
    }


def license_by_suffix(connection: sqlite3.Connection, code_suffix: str) -> sqlite3.Row:
    normalized_suffix = code_suffix.strip().upper()
    if len(normalized_suffix) != 6 or any(character not in string.ascii_uppercase + string.digits for character in normalized_suffix):
        raise HTTPException(status_code=400, detail="Suffisso licenza non valido")
    rows = connection.execute("SELECT * FROM licenses WHERE code_suffix = ?", (normalized_suffix,)).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="Licenza non trovata")
    if len(rows) > 1:
        raise HTTPException(status_code=409, detail="Suffisso ambiguo")
    return rows[0]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/v1/admin/session")
def login_admin(payload: AdminLoginRequest, request: Request, response: Response) -> dict:
    client_address = request.client.host if request.client else "unknown"
    register_admin_login_attempt(client_address)
    if not admin_key_is_valid(payload.admin_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chiave amministrativa non valida")
    clear_admin_login_attempts(client_address)
    token, expires_at = create_admin_session()
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=token,
        expires=expires_at,
        httponly=True,
        secure=os.getenv("LICENSE_ADMIN_COOKIE_SECURE", "true").lower() not in {"0", "false", "no"},
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "expires_at": expires_at.isoformat()}


@app.get("/v1/admin/session", dependencies=[Depends(require_admin)])
def get_admin_session() -> dict:
    return {"authenticated": True}


@app.delete("/v1/admin/session")
def logout_admin(request: Request, response: Response) -> dict:
    token = request.cookies.get(ADMIN_SESSION_COOKIE, "")
    if token:
        with ADMIN_STATE_LOCK:
            ADMIN_SESSIONS.pop(session_digest(token), None)
    response.delete_cookie(key=ADMIN_SESSION_COOKIE, path="/", samesite="strict")
    return {"authenticated": False}


@app.get("/v1/admin/licenses", dependencies=[Depends(require_admin)])
def list_licenses(
    license_status: str | None = Query(default=None, alias="status", pattern="^(not_activated|active|expired|revoked)$"),
    plan: str | None = Query(default=None, pattern="^(1M|6M|12M|LIFE)$"),
    customer: str | None = Query(default=None, max_length=200),
) -> dict:
    now = datetime.now(timezone.utc)
    clauses = []
    parameters: list[str] = []
    if plan:
        clauses.append("plan = ?")
        parameters.append(plan)
    if customer:
        clauses.append("customer LIKE ?")
        parameters.append(f"%{customer.strip()}%")
    query = "SELECT * FROM licenses"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC, code_suffix ASC"
    with db() as connection:
        licenses = [admin_license(row, now) for row in connection.execute(query, parameters).fetchall()]
    if license_status:
        licenses = [license for license in licenses if license["status"] == license_status]
    return {"licenses": licenses, "total": len(licenses)}


@app.get("/v1/admin/licenses/{code_suffix}", dependencies=[Depends(require_admin)])
def get_license(code_suffix: str) -> dict:
    with db() as connection:
        row = license_by_suffix(connection, code_suffix)
        return admin_license(row, datetime.now(timezone.utc))


@app.get("/v1/admin/licenses/{code_suffix}/code", dependencies=[Depends(require_admin)])
def reveal_license_code(code_suffix: str) -> dict:
    with db() as connection:
        row = license_by_suffix(connection, code_suffix)
    if row["encrypted_code"] is None:
        raise HTTPException(status_code=404, detail="Codice licenza non disponibile")
    try:
        code = decrypt_license_code(row["encrypted_code"], row["code_hash"])
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Codice licenza non recuperabile") from exc
    if not secrets.compare_digest(code_hash(code), row["code_hash"]):
        raise HTTPException(status_code=500, detail="Codice licenza non recuperabile")
    return {"code": code}


@app.get("/v1/admin/stats", dependencies=[Depends(require_admin)])
def license_stats() -> dict:
    now = datetime.now(timezone.utc)
    counts = {"total": 0, "not_activated": 0, "active": 0, "expired": 0, "revoked": 0}
    with db() as connection:
        rows = connection.execute("SELECT * FROM licenses").fetchall()
    for row in rows:
        counts["total"] += 1
        counts[public_license(row, now)["reason"]] += 1
    return counts


@app.post("/v1/admin/licenses", dependencies=[Depends(require_admin)])
def create_licenses(payload: GenerateRequest) -> dict:
    generated = []
    now = datetime.now(timezone.utc).isoformat()
    with db() as connection:
        for _ in range(payload.quantity):
            code = generate_code(payload.plan)
            hashed_code = code_hash(code)
            connection.execute(
                "INSERT INTO licenses(code_hash, code_suffix, plan, customer, created_at, encrypted_code) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (hashed_code, code[-6:], payload.plan, payload.customer, now, encrypt_license_code(code, hashed_code)),
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


@app.post("/v1/admin/licenses/{code_suffix}/revoke", dependencies=[Depends(require_admin)])
def revoke_license_by_suffix(code_suffix: str) -> dict:
    normalized_suffix = code_suffix.strip().upper()
    with db() as connection:
        rows = connection.execute("SELECT code_hash FROM licenses WHERE code_suffix = ?", (normalized_suffix,)).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="Licenza non trovata")
        if len(rows) > 1:
            raise HTTPException(status_code=409, detail="Suffisso ambiguo")
        connection.execute(
            "UPDATE licenses SET revoked_at = ? WHERE code_hash = ?",
            (datetime.now(timezone.utc).isoformat(), rows[0]["code_hash"]),
        )
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


@app.post("/v1/admin/licenses/{code_suffix}/release", dependencies=[Depends(require_admin)])
def release_license_by_suffix(code_suffix: str) -> dict:
    normalized_suffix = code_suffix.strip().upper()
    with db() as connection:
        rows = connection.execute("SELECT code_hash FROM licenses WHERE code_suffix = ?", (normalized_suffix,)).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail="Licenza non trovata")
        if len(rows) > 1:
            raise HTTPException(status_code=409, detail="Suffisso ambiguo")
        connection.execute(
            "UPDATE licenses SET instance_id = NULL, activated_at = NULL, expires_at = NULL, "
            "revoked_at = NULL, token_hash = NULL WHERE code_hash = ?",
            (rows[0]["code_hash"],),
        )
    return {"status": "released"}


@app.delete("/v1/admin/licenses/{code_suffix}", dependencies=[Depends(require_admin)])
def delete_license(code_suffix: str, force: bool = Query(default=False)) -> dict:
    with db() as connection:
        row = license_by_suffix(connection, code_suffix)
        if public_license(row, datetime.now(timezone.utc))["reason"] == "active" and not force:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="La licenza e' attiva: ripetere la richiesta con force=true per eliminarla",
            )
        connection.execute("DELETE FROM licenses WHERE code_hash = ?", (row["code_hash"],))
    return {"status": "deleted"}


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
            raise HTTPException(
                status_code=409,
                detail=(
                    "Licenza già attiva su un'altra installazione. "
                    "Disattivarla dalla precedente installazione prima di procedere."
                ),
            )
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
                "UPDATE licenses SET instance_id = ?, token_hash = ? WHERE code_hash = ?",
                (instance_id, code_hash(opaque_token), code_hash(code)),
            )
        row = connection.execute("SELECT * FROM licenses WHERE code_hash = ?", (code_hash(code),)).fetchone()
        result = public_license(row, now)
        result["license_token"] = opaque_token
    return encrypt_payload(result)


@app.post("/v1/deactivate", response_model=Envelope)
@limiter.limit(os.getenv("LICENSE_ACTIVATE_RATE_LIMIT", "10/minute"))
def deactivate(request: Request, envelope: Envelope) -> dict:
    payload = decrypt_payload(envelope.model_dump())
    instance_id = str(payload.get("instance_id", ""))
    token = str(payload.get("license_token", ""))
    now = datetime.now(timezone.utc)
    with db() as connection:
        consume_nonce(connection, payload["request_nonce"], int(payload["timestamp"]))
        token_digest = code_hash(token)
        row = connection.execute(
            "SELECT * FROM licenses WHERE token_hash = ?", (token_digest,)
        ).fetchone()
        if row is None or row["instance_id"] != instance_id:
            result = {"valid": False, "reason": "unauthorized", "server_time": now.isoformat()}
        else:
            connection.execute(
                "UPDATE licenses SET instance_id = NULL, activated_at = NULL, "
                "expires_at = NULL, token_hash = NULL, revoked_at = NULL "
                "WHERE token_hash = ?",
                (token_digest,),
            )
            result = {"valid": True, "reason": "deactivated", "server_time": now.isoformat()}
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
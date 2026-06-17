"""
Simple session-based auth.
Users are stored in-memory — extend to DB as needed.
Passwords are bcrypt-hashed at startup.
"""
from fastapi import APIRouter, HTTPException, Response, Request, Depends
from pydantic import BaseModel
import bcrypt, secrets, time, logging

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Users ─────────────────────────────────────────────────────────────────────
# Roles:
#   admin  — full access: add repos, delete repos, trigger scans, view all
#   dev    — can trigger scans and view all; cannot add or delete repos
#   reader — read-only: view findings, CBOM, reports; no scan or delete
_RAW_USERS = [
    {"username": "admin",  "password": "pqcadmin",  "role": "admin",  "name": "Admin User"},
    {"username": "dev",    "password": "pqcdev",    "role": "dev",    "name": "Developer"},
    {"username": "reader", "password": "pqcreader", "role": "reader", "name": "Reader"},
]

# Hash passwords once at startup
USERS = {}
for u in _RAW_USERS:
    USERS[u["username"]] = {
        "hash": bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()),
        "role": u["role"],
        "name": u["name"],
    }

# In-memory session store: { token: { username, role, name, created_at } }
SESSIONS: dict = {}
SESSION_TTL = 8 * 60 * 60  # 8 hours

# ── Schemas ───────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def _purge_expired():
    now = time.time()
    expired = [t for t, s in SESSIONS.items() if now - s["created_at"] > SESSION_TTL]
    for t in expired:
        del SESSIONS[t]

def get_session(request: Request):
    token = request.cookies.get("pqc_session") or \
            request.headers.get("X-Session-Token")
    if not token or token not in SESSIONS:
        raise HTTPException(401, "Not authenticated")
    session = SESSIONS[token]
    if time.time() - session["created_at"] > SESSION_TTL:
        del SESSIONS[token]
        raise HTTPException(401, "Session expired")
    return session

def require_role(*allowed_roles):
    """Dependency factory — raises 403 if the session role is not in allowed_roles."""
    def _check(session = Depends(get_session)):
        if session["role"] not in allowed_roles:
            raise HTTPException(403, f"Requires role: {' or '.join(allowed_roles)}")
        return session
    return _check

# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/login")
def login(payload: LoginRequest, response: Response):
    _purge_expired()
    user = USERS.get(payload.username.lower().strip())
    if not user or not bcrypt.checkpw(payload.password.encode(), user["hash"]):
        raise HTTPException(401, "Invalid username or password")

    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "username":   payload.username,
        "role":       user["role"],
        "name":       user["name"],
        "created_at": time.time(),
    }
    # Set httpOnly cookie (works even over HTTP)
    response.set_cookie(
        key="pqc_session", value=token,
        httponly=True, samesite="lax", secure=False,
        max_age=SESSION_TTL,
    )
    logger.info(f"Login: {payload.username} ({user['role']})")
    return {"token": token, "username": payload.username,
            "name": user["name"], "role": user["role"]}

@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("pqc_session") or \
            request.headers.get("X-Session-Token")
    if token and token in SESSIONS:
        del SESSIONS[token]
    response.delete_cookie("pqc_session")
    return {"status": "logged out"}

@router.get("/me")
def me(session = Depends(get_session)):
    return {"username": session["username"],
            "name":     session["name"],
            "role":     session["role"]}

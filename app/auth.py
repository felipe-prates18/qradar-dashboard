import re
import sqlite3
from pathlib import Path
from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.status import HTTP_401_UNAUTHORIZED
from fastapi.templating import Jinja2Templates
import bcrypt

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "users.db"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
auth_router = APIRouter()
LEGACY_SHA256_REGEX = re.compile(r"^[0-9a-f]{64}$")
BCRYPT_COST = 12


class AuthenticationError(Exception):
    """Raised when a request requires authentication but the user is anonymous."""

    def __init__(self, message: str = "Autenticação necessária") -> None:
        self.message = message

def _connect():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=BCRYPT_COST)
    return bcrypt.hashpw(password.encode(), salt).decode()


def _is_legacy_hash(password_hash: str) -> bool:
    return bool(password_hash and LEGACY_SHA256_REGEX.fullmatch(password_hash))


def _verify_password(plain_password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(plain_password.encode(), password_hash.encode())
        except ValueError:
            return False
    if _is_legacy_hash(password_hash):
        import hashlib

        return hashlib.sha256(plain_password.encode()).hexdigest() == password_hash
    return False


def _needs_bcrypt_rehash(password_hash: str) -> bool:
    try:
        parts = password_hash.split("$")
        cost = int(parts[2])
    except (IndexError, ValueError):
        return True
    return cost < BCRYPT_COST or password_hash.startswith("$2a$")

def get_user(username: str):
    con = _connect()
    cur = con.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if "is_admin" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        con.commit()
    cur.execute("SELECT id, username, password_hash, is_active, COALESCE(is_admin,0) as is_admin FROM users WHERE username=? LIMIT 1", (username,))
    row = cur.fetchone()
    con.close()
    return row


def _update_password_hash(user_id: int, new_hash: str) -> None:
    con = _connect()
    cur = con.cursor()
    cur.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
    con.commit()
    con.close()

def verify_credentials(username: str, password: str):
    row = get_user(username)
    if not row:
        return None
    if int(row["is_active"]) != 1:
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    if _is_legacy_hash(row["password_hash"]):
        _update_password_hash(row["id"], hash_password(password))
    elif row["password_hash"].startswith("$2") and _needs_bcrypt_rehash(row["password_hash"]):
        _update_password_hash(row["id"], hash_password(password))
    return row

def verify_user(request: Request):
    u = request.session.get("user")
    if not u:
        return None
    row = get_user(u)
    if not row or int(row["is_active"]) != 1:
        return None
    return row["username"]

def verify_user_required_page(request: Request):
    u = verify_user(request)
    if not u:
        raise AuthenticationError("Sessão expirada ou inválida. Faça login novamente.")
    return u

def verify_user_required_api(request: Request):
    u = verify_user(request)
    if not u:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    return u

def is_admin(username: str) -> bool:
    row = get_user(username)
    return bool(row and int(row["is_admin"]) == 1 and int(row["is_active"]) == 1)

@auth_router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@auth_router.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), remember_me: bool = Form(False)):
    row = verify_credentials(username, password)
    if not row:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Usuário ou senha inválidos"}, status_code=401)
    request.session["user"] = row["username"]
    return RedirectResponse(url="/", status_code=302)

@auth_router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)

@auth_router.get("/api/me")
def api_me(user: str = Depends(verify_user_required_api)):
    return {"user": user}

@auth_router.post("/api/admin/users")
def api_admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), is_admin: str = Form("false"), user: str = Depends(verify_user_required_api)):
    if not is_admin_user(user):
        raise HTTPException(status_code=403, detail="Admin required")
    admin_val = 1 if is_admin.lower() in ("1", "true", "on", "yes") else 0
    con = _connect()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_active, is_admin) VALUES (?,?,1,?)",
            (username, hash_password(password), admin_val),
        )
        con.commit()
        return {"detail": "Usuário criado"}
    except sqlite3.IntegrityError:
        return JSONResponse({"detail": "Usuário já existe"}, status_code=400)
    finally:
        con.close()

def is_admin_user(username: str) -> bool:
    return is_admin(username)


@auth_router.get("/me/password", response_class=HTMLResponse)
def change_password_page(request: Request, user: str = Depends(verify_user_required_page)):
    return templates.TemplateResponse(
        "change_password.html",
        {"request": request, "user": user},
    )


@auth_router.post("/me/password", response_class=HTMLResponse)
def change_password_submit(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: str = Depends(verify_user_required_page),
):
    context = {"request": request, "user": user}

    row = verify_credentials(user, current_password)
    if not row:
        context["error"] = "Senha atual incorreta."
        return templates.TemplateResponse("change_password.html", context, status_code=400)

    new_password = new_password.strip()
    confirm_password = confirm_password.strip()

    if new_password != confirm_password:
        context["error"] = "A confirmação da senha não confere."
        return templates.TemplateResponse("change_password.html", context, status_code=400)

    if len(new_password) < 6:
        context["error"] = "A nova senha deve ter pelo menos 6 caracteres."
        return templates.TemplateResponse("change_password.html", context, status_code=400)

    if _verify_password(new_password, row["password_hash"]):
        context["error"] = "A nova senha deve ser diferente da senha atual."
        return templates.TemplateResponse("change_password.html", context, status_code=400)

    _update_password_hash(row["id"], hash_password(new_password))
    context["success"] = "Senha alterada com sucesso."
    return templates.TemplateResponse("change_password.html", context)


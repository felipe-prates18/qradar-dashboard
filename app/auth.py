import sqlite3
import hashlib
from pathlib import Path
from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.status import HTTP_307_TEMPORARY_REDIRECT, HTTP_401_UNAUTHORIZED
from fastapi.templating import Jinja2Templates

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "users.db"
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
auth_router = APIRouter()

def _connect():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

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

def verify_credentials(username: str, password: str):
    row = get_user(username)
    if not row:
        return None
    if int(row["is_active"]) != 1:
        return None
    if row["password_hash"] != _sha256(password):
        return None
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
        raise HTTPException(status_code=HTTP_307_TEMPORARY_REDIRECT, headers={"Location": "/login"})
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
        cur.execute("INSERT INTO users (username, password_hash, is_active, is_admin) VALUES (?,?,1,?)", (username, _sha256(password), admin_val))
        con.commit()
        return {"detail": "Usuário criado"}
    except sqlite3.IntegrityError:
        return JSONResponse({"detail": "Usuário já existe"}, status_code=400)
    finally:
        con.close()

def is_admin_user(username: str) -> bool:
    return is_admin(username)


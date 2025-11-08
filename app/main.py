import json
import logging
import secrets
import sqlite3
from pathlib import Path
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from .auth import (
    auth_router,
    verify_user_required_page,
    verify_user_required_api,
    verify_user,
    is_admin,
    hash_password,
    AuthenticationError,
    has_wallboard_token,
    WALLBOARD_COOKIE_NAME,
    wallboard_token_request_allowed,
)
import requests
from requests.exceptions import RequestException

from .collectors import collect_monitoring_data, collect_health_data
from .alerts import AlertManager

try:
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    InsecureRequestWarning = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "users.db"

with open(BASE_DIR / "config.json", "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

app = FastAPI(title="QRadar Monitoring App")
logger = logging.getLogger(__name__)
session_secret = CONFIG.get("session_secret", "qradar-app-secret")
runtime_secret = f"{session_secret}:{secrets.token_hex(16)}"
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
WALLBOARD_TOKEN = CONFIG.get("wallboard_token")
WALLBOARD_COOKIE_MAX_AGE = 30 * 24 * 60 * 60
app.add_middleware(
    SessionMiddleware,
    secret_key=runtime_secret,
    same_site="lax",
    max_age=SESSION_MAX_AGE_SECONDS,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.include_router(auth_router)


def _collect_monitoring_payload():
    return collect_monitoring_data(CONFIG, logger=logger)


def _collect_health_payload():
    return collect_health_data(CONFIG, logger=logger)


alert_manager = AlertManager(
    CONFIG,
    fetch_monitoring=_collect_monitoring_payload,
    fetch_health=_collect_health_payload,
    logger=logger,
)


@app.on_event("startup")
async def _start_alert_manager():
    await alert_manager.start()


@app.on_event("shutdown")
async def _stop_alert_manager():
    await alert_manager.stop()


@app.middleware("http")
async def restrict_wallboard_token_scope(request: Request, call_next):
    if has_wallboard_token(request) and not wallboard_token_request_allowed(request):
        session_user = verify_user(request)
        if not session_user:
            accept_header = (request.headers.get("accept") or "").lower()
            if "text/html" in accept_header:
                response = templates.TemplateResponse(
                    "error.html",
                    {"request": request, "message": "Acesso restrito ao painel SOC."},
                    status_code=401,
                )
            else:
                response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
            response.delete_cookie(WALLBOARD_COOKIE_NAME)
            return response
    response = await call_next(request)
    return response


def _con():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def _wallboard_token_supplied_via_link(request: Request) -> bool:
    if not WALLBOARD_TOKEN:
        return False
    query_token = request.query_params.get("token") if hasattr(request, "query_params") else None
    header_token = request.headers.get("x-wallboard-token")
    for candidate in (query_token, header_token):
        if candidate and secrets.compare_digest(str(candidate), WALLBOARD_TOKEN):
            return True
    return False

@app.get("/", response_class=HTMLResponse)
def home(request: Request, user: str = Depends(verify_user_required_page)):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user, "title": "Monitoramento"},
    )


@app.get("/painel", response_class=HTMLResponse)
def wallboard(request: Request):
    session_user = verify_user(request)
    token_authenticated = has_wallboard_token(request)
    if not session_user and not token_authenticated:
        raise AuthenticationError("Sessão expirada ou inválida. Faça login novamente.")

    context = {"request": request, "user": session_user or "__wallboard__", "title": "Painel SOC"}
    response = templates.TemplateResponse("tv.html", context)

    if token_authenticated and WALLBOARD_TOKEN and _wallboard_token_supplied_via_link(request):
        response.set_cookie(
            WALLBOARD_COOKIE_NAME,
            WALLBOARD_TOKEN,
            max_age=WALLBOARD_COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
        )

    return response

@app.get("/api/clients")
def get_clients(user: str = Depends(verify_user_required_api)):
    clients = [
        {
            "name": e.get("name", ""),
            "host": e.get("host", ""),
            "code": e.get("codigo") or e.get("code") or "",
        }
        for e in CONFIG.get("qradar_envs", [])
    ]
    return JSONResponse(clients)

@app.get("/api/monitor")
def get_monitoring(user: str = Depends(verify_user_required_api)):
    payload = collect_monitoring_data(CONFIG, logger=logger)
    return JSONResponse(payload)


@app.get("/api/health")
def get_health(user: str = Depends(verify_user_required_api)):
    payload = collect_health_data(CONFIG, logger=logger)
    return JSONResponse(payload)

@app.exception_handler(AuthenticationError)
def handle_authentication_error(request: Request, exc: AuthenticationError):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "message": exc.message},
        status_code=401,
    )


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request, user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Você não tem permissão para acessar esta área."},
            status_code=403,
        )
    con = _con()
    cur = con.cursor()
    cur.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in cur.fetchall()]
    if "is_admin" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        con.commit()
    cur.execute("SELECT id, username, is_active, COALESCE(is_admin,0) as is_admin FROM users ORDER BY username")
    users = cur.fetchall()
    con.close()

    mapped = [
        {
            "id": u["id"],
            "username": u["username"],
            "is_active": int(u["is_active"]) == 1,
            "is_admin": int(u["is_admin"]) == 1,
        }
        for u in users
    ]

    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": mapped, "user": user},
    )

@app.post("/admin/users/create")
def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), is_admin_flag: str = Form(None), user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem criar usuários."},
            status_code=403,
        )
    is_admin_val = 1 if (is_admin_flag in ("on", "true", "1", "yes")) else 0
    con = _con()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_active, is_admin) VALUES (?,?,1,?)",
            (username, hash_password(password), is_admin_val)
        )
        con.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        con.close()
    return RedirectResponse(url="/admin/users", status_code=302)

@app.post("/admin/users/toggle")
def admin_toggle_user(request: Request, user_id: int = Form(...), field: str = Form(...), user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem alterar usuários."},
            status_code=403,
        )
    if field not in ("is_active", "is_admin"):
        return RedirectResponse(url="/admin/users", status_code=302)
    con = _con()
    cur = con.cursor()
    cur.execute(f"UPDATE users SET {field}=CASE {field} WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (user_id,))
    con.commit()
    con.close()
    return RedirectResponse(url="/admin/users", status_code=302)

@app.get("/api/admin/users")
def api_admin_list(user: str = Depends(verify_user_required_api)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    con = _con()
    cur = con.cursor()
    cur.execute("SELECT username, COALESCE(is_admin,0) as is_admin, is_active FROM users ORDER BY username")
    data = [{"username": r[0], "is_admin": int(r[1]) == 1, "is_active": int(r[2]) == 1} for r in cur.fetchall()]
    con.close()
    return data

@app.get("/healthz")
def healthz():
    return {"ok": True}


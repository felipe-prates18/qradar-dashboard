import asyncio
import json
import logging
import secrets
import sqlite3
from urllib.parse import urlencode
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Optional
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
CACHE_TTL_SECONDS = 180
CACHE_REFRESH_INTERVAL_SECONDS = CACHE_TTL_SECONDS
app.add_middleware(
    SessionMiddleware,
    secret_key=runtime_secret,
    same_site="lax",
    max_age=SESSION_MAX_AGE_SECONDS,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.include_router(auth_router)


class _DataCache:
    def __init__(self, ttl_seconds: int):
        self.ttl = timedelta(seconds=max(1, int(ttl_seconds)))
        self._lock = Lock()
        self._payload: Optional[Dict[str, Any]] = None
        self._collected_at: Optional[datetime] = None

    def _now(self) -> datetime:
        return datetime.utcnow()

    def get_cached(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._payload

    def store(self, payload: Dict[str, Any]) -> None:
        timestamp = self._now()
        with self._lock:
            self._payload = payload
            self._collected_at = timestamp

    def refresh(self, fetcher: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        payload = fetcher()
        self.store(payload)
        return payload

    def get_or_refresh(self, fetcher: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        with self._lock:
            payload = self._payload
            collected_at = self._collected_at

        if (
            payload is not None
            and collected_at is not None
            and self._now() - collected_at < self.ttl
        ):
            return payload

        return self.refresh(fetcher)

    def is_expired(self) -> bool:
        with self._lock:
            if self._collected_at is None:
                return True
            return self._now() - self._collected_at > self.ttl


_monitoring_cache = _DataCache(CACHE_TTL_SECONDS)
_health_cache = _DataCache(CACHE_TTL_SECONDS)


def _refresh_monitoring_cache() -> Dict[str, Any]:
    return _monitoring_cache.refresh(lambda: collect_monitoring_data(CONFIG, logger=logger))


def _refresh_health_cache() -> Dict[str, Any]:
    return _health_cache.refresh(lambda: collect_health_data(CONFIG, logger=logger))


def _get_monitoring_payload() -> Dict[str, Any]:
    payload = _monitoring_cache.get_cached()
    if payload is None:
        logger.info("Cache de monitoramento vazio. Coletando dados iniciais.")
        return _refresh_monitoring_cache()
    if _monitoring_cache.is_expired():
        logger.warning("Cache de monitoramento expirado. Atualizando dados sob demanda.")
        return _refresh_monitoring_cache()
    return payload


def _get_health_payload() -> Dict[str, Any]:
    payload = _health_cache.get_cached()
    if payload is None:
        logger.info("Cache de health-check vazio. Coletando dados iniciais.")
        return _refresh_health_cache()
    if _health_cache.is_expired():
        logger.warning("Cache de health-check expirado. Atualizando dados sob demanda.")
        return _refresh_health_cache()
    return payload


def _refresh_all_caches() -> None:
    try:
        _refresh_monitoring_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache de monitoramento")
    try:
        _refresh_health_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache de health-check")


async def _cache_refresh_loop(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    logger.info(
        "Atualização periódica de caches iniciada. Intervalo=%ss",
        CACHE_REFRESH_INTERVAL_SECONDS,
    )
    while not stop_event.is_set():
        started_at = loop.time()
        try:
            await asyncio.to_thread(_refresh_all_caches)
        except Exception:
            logger.exception("Erro inesperado ao atualizar caches")
        elapsed = loop.time() - started_at
        wait_seconds = max(0, CACHE_REFRESH_INTERVAL_SECONDS - elapsed)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=wait_seconds)
        except asyncio.TimeoutError:
            continue
    logger.info("Atualização periódica de caches finalizada")


_cache_refresh_task: Optional[asyncio.Task] = None
_cache_refresh_stop: Optional[asyncio.Event] = None


alert_manager = AlertManager(
    CONFIG,
    fetch_monitoring=_get_monitoring_payload,
    fetch_health=_get_health_payload,
    logger=logger,
)


async def _start_cache_refresh() -> None:
    global _cache_refresh_task, _cache_refresh_stop
    if _cache_refresh_task is not None and not _cache_refresh_task.done():
        return

    stop_event = asyncio.Event()
    _cache_refresh_stop = stop_event
    await asyncio.to_thread(_refresh_all_caches)
    _cache_refresh_task = asyncio.create_task(_cache_refresh_loop(stop_event))


async def _stop_cache_refresh() -> None:
    global _cache_refresh_task, _cache_refresh_stop
    task = _cache_refresh_task
    stop_event = _cache_refresh_stop
    if task is None:
        return
    if stop_event is not None:
        stop_event.set()
    try:
        await task
    except Exception:
        logger.exception("Erro ao finalizar a atualização periódica de caches")
    finally:
        _cache_refresh_task = None
        _cache_refresh_stop = None


@app.on_event("startup")
async def _start_cache_manager():
    await _start_cache_refresh()


@app.on_event("startup")
async def _start_alert_manager():
    await alert_manager.start()


@app.on_event("shutdown")
async def _stop_alert_manager():
    await alert_manager.stop()


@app.on_event("shutdown")
async def _shutdown_cache_manager():
    await _stop_cache_refresh()


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
    payload = _get_monitoring_payload()
    return JSONResponse(payload)


@app.get("/api/health")
def get_health(user: str = Depends(verify_user_required_api)):
    payload = _get_health_payload()
    return JSONResponse(payload)

@app.exception_handler(AuthenticationError)
def handle_authentication_error(request: Request, exc: AuthenticationError):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "message": exc.message},
        status_code=401,
    )


def _redirect_admin_users(success: Optional[str] = None, error: Optional[str] = None) -> RedirectResponse:
    params = {}
    if success:
        params["success"] = success
    if error:
        params["error"] = error
    query = urlencode(params)
    url = "/admin/users"
    if query:
        url = f"{url}?{query}"
    return RedirectResponse(url=url, status_code=303)


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

    success_message = request.query_params.get("success")
    error_message = request.query_params.get("error")

    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "users": mapped,
            "user": user,
            "success": success_message,
            "error": error_message,
        },
    )

@app.get("/users/admin", response_class=HTMLResponse)
def legacy_admin_users_page(request: Request, user: str = Depends(verify_user_required_page)):
    """Mantém compatibilidade com a rota legada /users/admin."""
    return admin_users_page(request, user)


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
        return _redirect_admin_users(error="Já existe um usuário com esse nome.")
    finally:
        con.close()
    return _redirect_admin_users(success=f"Usuário {username} criado com sucesso.")

@app.post("/users/admin/create")
def legacy_admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), is_admin_flag: str = Form(None), user: str = Depends(verify_user_required_page)):
    return admin_create_user(request, username, password, is_admin_flag, user)


@app.post("/admin/users/toggle")
def admin_toggle_user(request: Request, user_id: int = Form(...), field: str = Form(...), user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem alterar usuários."},
            status_code=403,
        )
    if field not in ("is_active", "is_admin"):
        return _redirect_admin_users(error="Ação inválida para o usuário selecionado.")
    con = _con()
    cur = con.cursor()
    try:
        cur.execute(
            "SELECT username, is_active, COALESCE(is_admin,0) as is_admin FROM users WHERE id=?",
            (user_id,),
        )
        row = cur.fetchone()
        if not row:
            return _redirect_admin_users(error="Usuário não encontrado.")
        target_username = row["username"]
        if target_username == user:
            if field == "is_active" and int(row["is_active"]) == 1:
                return _redirect_admin_users(error="Você não pode desativar o seu próprio usuário.")
            if field == "is_admin" and int(row["is_admin"]) == 1:
                return _redirect_admin_users(error="Você não pode remover suas próprias permissões de administrador.")
        cur.execute(
            f"UPDATE users SET {field}=CASE {field} WHEN 1 THEN 0 ELSE 1 END WHERE id=?",
            (user_id,),
        )
        con.commit()
    finally:
        con.close()
    if field == "is_active":
        return _redirect_admin_users(success=f"Status de atividade atualizado para {target_username}.")
    return _redirect_admin_users(success=f"Permissão de administrador atualizada para {target_username}.")


@app.post("/admin/users/reset-password")
def admin_reset_user_password(
    request: Request,
    user_id: int = Form(...),
    new_password: str = Form(...),
    user: str = Depends(verify_user_required_page),
):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem alterar usuários."},
            status_code=403,
        )
    sanitized = new_password.strip()
    if len(sanitized) < 6:
        return _redirect_admin_users(error="A nova senha deve ter pelo menos 6 caracteres.")
    con = _con()
    cur = con.cursor()
    try:
        cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        if not row:
            return _redirect_admin_users(error="Usuário não encontrado.")
        cur.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(sanitized), user_id),
        )
        con.commit()
        target_username = row["username"]
    finally:
        con.close()
    return _redirect_admin_users(success=f"Senha redefinida para {target_username}.")


@app.post("/admin/users/delete")
def admin_delete_user(
    request: Request,
    user_id: int = Form(...),
    user: str = Depends(verify_user_required_page),
):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem alterar usuários."},
            status_code=403,
        )
    con = _con()
    cur = con.cursor()
    try:
        cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        if not row:
            return _redirect_admin_users(error="Usuário não encontrado.")
        target_username = row["username"]
        if target_username == user:
            return _redirect_admin_users(error="Você não pode excluir o seu próprio usuário.")
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        con.commit()
    finally:
        con.close()
    return _redirect_admin_users(success=f"Usuário {target_username} removido com sucesso.")

@app.post("/users/admin/toggle")
def legacy_admin_toggle_user(request: Request, user_id: int = Form(...), field: str = Form(...), user: str = Depends(verify_user_required_page)):
    return admin_toggle_user(request, user_id, field, user)


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


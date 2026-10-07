import asyncio
import csv
import io
import json
import logging
import secrets
import sqlite3
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
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
    ensure_user_schema,
    list_permissions,
    set_user_permissions,
)
import requests
from requests.exceptions import RequestException

from .collectors import collect_crowdstrike_monitoring_data, collect_health_data, collect_monitoring_data
from .alerts import AlertManager
from .services import environment_store
from .services.jira_client import JiraClient
from .services.ssh_client import SSHClient

try:
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    InsecureRequestWarning = None

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "users.db"

with open(BASE_DIR / "config.json", "r", encoding="utf-8") as f:
    _RAW_CONFIG = json.load(f)

CONFIG = {key: value for key, value in _RAW_CONFIG.items() if key != "qradar_envs"}

DEFAULT_QRADAR_SIEM = "QRadar"
CROWDSTRIKE_SIEM = "Crowdstrike NG-SIEM"

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' https://unpkg.com 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = CSP_POLICY
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


app = FastAPI(title="QRadar Monitoring App", docs_url=None, redoc_url=None, openapi_url=None)
logger = logging.getLogger(__name__)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": "Requisição inválida."})
session_secret = CONFIG.get("session_secret", "qradar-app-secret")
runtime_secret = f"{session_secret}:{secrets.token_hex(16)}"
SESSION_MAX_AGE_SECONDS = 4 * 60 * 60
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
app.add_middleware(SecurityHeadersMiddleware)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.include_router(auth_router)


@app.get("/openapi.json", include_in_schema=False)
def protected_openapi(user: str = Depends(verify_user_required_page)):
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
def protected_swagger_ui(user: str = Depends(verify_user_required_page)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Swagger UI")


@app.get("/redoc", include_in_schema=False)
def protected_redoc(user: str = Depends(verify_user_required_page)):
    return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")


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

    def clear(self) -> None:
        with self._lock:
            self._payload = None
            self._collected_at = None

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
_crowdstrike_monitoring_cache = _DataCache(CACHE_TTL_SECONDS)
_health_cache = _DataCache(CACHE_TTL_SECONDS)
_jira_cache = _DataCache(CACHE_TTL_SECONDS)


def _invalidate_environment_caches() -> None:
    _monitoring_cache.clear()
    _crowdstrike_monitoring_cache.clear()
    _health_cache.clear()


def _refresh_monitoring_cache() -> Dict[str, Any]:
    return _monitoring_cache.refresh(
        lambda: collect_monitoring_data(
            _config_with_envs(siem_filter=DEFAULT_QRADAR_SIEM), logger=logger
        )
    )


def _refresh_crowdstrike_cache() -> Dict[str, Any]:
    return _crowdstrike_monitoring_cache.refresh(
        lambda: collect_crowdstrike_monitoring_data(
            _config_with_envs(siem_filter=CROWDSTRIKE_SIEM), logger=logger
        )
    )


def _refresh_health_cache() -> Dict[str, Any]:
    return _health_cache.refresh(
        lambda: collect_health_data(
            _config_with_envs(siem_filter=DEFAULT_QRADAR_SIEM), logger=logger
        )
    )


def _collect_jira_monitoring() -> Dict[str, Any]:
    config_with_envs = _config_with_envs()
    jira_config = (
        config_with_envs.get("jira")
        or config_with_envs.get("jira_alerts")
        or {}
    )

    warning_hours = max(1, int(jira_config.get("warning_hours", 24)))
    critical_hours = max(warning_hours, int(jira_config.get("critical_hours", 36)))
    now_local = datetime.now()
    payload: Dict[str, Any] = {
        "updated_at": now_local.strftime("%d/%m/%Y, %H:%M:%S"),
        "settings": {
            "warning_hours": warning_hours,
            "critical_hours": critical_hours,
            "window_hours": critical_hours,
        },
        "clients": [],
        "errors": [],
    }

    jira_clients = [
        str(c).strip() for c in (jira_config.get("clients") or []) if str(c).strip()
    ]

    if not jira_config:
        payload["errors"].append("Monitoramento do Jira não configurado.")
        return payload

    if not jira_clients:
        payload["errors"].append("Nenhum cliente configurado para monitoramento no Jira.")
        return payload

    try:
        jira_client = JiraClient(jira_config, logger=logger)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Falha ao inicializar cliente do Jira")
        payload["errors"].append(f"Configuração inválida do Jira: {exc}")
        return payload

    try:
        summary = jira_client.summarize_clients(
            jira_clients, window_hours=critical_hours
        )
    except Exception:  # noqa: BLE001
        logger.exception("Falha ao coletar status do Jira")
        payload["errors"].append("Não foi possível consultar o Jira no momento.")
        return payload

    for entry in summary:
        last_issue = entry.get("last_issue") or {}
        last_created_at = last_issue.get("created_at")
        hours_without = entry.get("hours_without_ticket")

        status = "normal"
        if hours_without is None:
            status = "critical"
        elif hours_without >= critical_hours:
            status = "critical"
        elif hours_without >= warning_hours:
            status = "warning"

        payload["clients"].append(
            {
                "name": entry.get("client") or "—",
                "issues_in_window": entry.get("issues_in_window", 0),
                "last_issue_key": last_issue.get("key"),
                "last_issue_summary": last_issue.get("summary"),
                "last_issue_created_at": last_created_at.isoformat()
                if last_created_at
                else None,
                "hours_without_ticket": hours_without,
                "status": status,
            }
        )

    status_order = {"critical": 0, "warning": 1, "normal": 2}
    payload["clients"].sort(
        key=lambda item: (
            status_order.get(item.get("status"), 3),
            item.get("hours_without_ticket")
            if item.get("hours_without_ticket") is not None
            else float("inf"),
            item.get("name", ""),
        )
    )

    return payload


def _refresh_jira_cache() -> Dict[str, Any]:
    return _jira_cache.refresh(_collect_jira_monitoring)


def _get_qradar_monitoring_payload() -> Dict[str, Any]:
    payload = _monitoring_cache.get_cached()
    if payload is None:
        logger.info("Cache de monitoramento vazio. Coletando dados iniciais.")
        return _refresh_monitoring_cache()
    if _monitoring_cache.is_expired():
        logger.warning("Cache de monitoramento expirado. Atualizando dados sob demanda.")
        return _refresh_monitoring_cache()
    return payload


def _get_crowdstrike_monitoring_payload() -> Dict[str, Any]:
    payload = _crowdstrike_monitoring_cache.get_cached()
    if payload is None:
        logger.info("Cache Crowdstrike vazio. Coletando dados iniciais.")
        return _refresh_crowdstrike_cache()
    if _crowdstrike_monitoring_cache.is_expired():
        logger.warning("Cache Crowdstrike expirado. Atualizando dados sob demanda.")
        return _refresh_crowdstrike_cache()
    return payload


def _build_placeholder_monitoring_payload(
    selected_siem: str, envs: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    return {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": [
            {
                "name": env.get("name"),
                "code": env.get("codigo") or env.get("code"),
                "siem": _resolved_env_siem(env),
            }
            for env in envs
        ],
    }


def _get_monitoring_payload(selected_siem: Optional[str] = None) -> Dict[str, Any]:
    envs = _load_environments_from_db()
    available_siems = _list_available_siems(envs)
    resolved_siem = _choose_siem(selected_siem, available_siems)
    is_qradar = resolved_siem.strip().lower() == DEFAULT_QRADAR_SIEM.lower()
    is_crowdstrike = resolved_siem.strip().lower() == CROWDSTRIKE_SIEM.lower()

    if is_qradar:
        base_payload = _get_qradar_monitoring_payload()
    elif is_crowdstrike:
        base_payload = _get_crowdstrike_monitoring_payload()
    else:
        filtered_envs = _filter_environments_by_siem(envs, resolved_siem)
        base_payload = _build_placeholder_monitoring_payload(resolved_siem, filtered_envs)

    payload = dict(base_payload)
    payload["available_siems"] = available_siems
    payload["selected_siem"] = resolved_siem
    payload["collection_enabled"] = is_qradar or is_crowdstrike
    return payload


def _get_alert_monitoring_payload() -> Dict[str, Any]:
    qradar_payload = _get_monitoring_payload(DEFAULT_QRADAR_SIEM)
    crowdstrike_payload = _get_monitoring_payload(CROWDSTRIKE_SIEM)

    rows: List[Dict[str, Any]] = []
    rows.extend(qradar_payload.get("rows") or [])
    rows.extend(crowdstrike_payload.get("rows") or [])

    return {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": rows,
    }


def _get_health_payload() -> Dict[str, Any]:
    payload = _health_cache.get_cached()
    if payload is None:
        logger.info("Cache de health-check vazio. Coletando dados iniciais.")
        return _refresh_health_cache()
    if _health_cache.is_expired():
        logger.warning("Cache de health-check expirado. Atualizando dados sob demanda.")
        return _refresh_health_cache()
    return payload


def _get_jira_payload() -> Dict[str, Any]:
    payload = _jira_cache.get_cached()
    if payload is None:
        logger.info("Cache do Jira vazio. Coletando dados iniciais.")
        return _refresh_jira_cache()
    if _jira_cache.is_expired():
        logger.warning("Cache do Jira expirado. Atualizando dados sob demanda.")
        return _refresh_jira_cache()
    return payload


def _refresh_all_caches() -> None:
    try:
        _refresh_monitoring_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache de monitoramento")
    try:
        _refresh_crowdstrike_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache Crowdstrike")
    try:
        _refresh_health_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache de health-check")
    try:
        _refresh_jira_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache do Jira")


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


def _con():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA foreign_keys = ON")
    except sqlite3.DatabaseError:
        pass
    return con


def _load_environments_from_db() -> List[Dict[str, Any]]:
    con = _con()
    try:
        environment_store.ensure_schema(con)
        return environment_store.list_environments(con)
    finally:
        con.close()


def _get_environment_from_db(env_id: int) -> Optional[Dict[str, Any]]:
    con = _con()
    try:
        environment_store.ensure_schema(con)
        return environment_store.get_environment(con, env_id)
    finally:
        con.close()


def _normalize_siem_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    return text or None


def _resolved_env_siem(env: Dict[str, Any]) -> str:
    value = _normalize_siem_value(env.get("siem"))
    return value or DEFAULT_QRADAR_SIEM


def _filter_environments_by_siem(
    envs: Sequence[Dict[str, Any]], siem_filter: Optional[str]
) -> List[Dict[str, Any]]:
    if not siem_filter:
        return list(envs)
    try:
        normalized = str(siem_filter).strip().lower()
    except Exception:
        normalized = ""
    return [
        env
        for env in envs
        if _resolved_env_siem(env).strip().lower() == normalized
    ]


def _list_available_siems(envs: Optional[Sequence[Dict[str, Any]]] = None) -> List[str]:
    environments = list(envs) if envs is not None else _load_environments_from_db()
    seen: set[str] = set()
    values: List[str] = []
    for env in environments:
        siem_label = _resolved_env_siem(env)
        key = siem_label.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        values.append(siem_label)
    return sorted(values, key=lambda value: value.lower())


def _choose_siem(requested: Optional[str], available: Sequence[str]) -> str:
    if requested:
        try:
            requested_norm = str(requested).strip().lower()
        except Exception:
            requested_norm = ""
        for candidate in available:
            if candidate and candidate.strip().lower() == requested_norm:
                return candidate
    for candidate in available:
        if candidate and candidate.strip().lower() == DEFAULT_QRADAR_SIEM.lower():
            return candidate
    if available:
        return available[0]
    return DEFAULT_QRADAR_SIEM


def _config_with_envs(*, siem_filter: Optional[str] = None) -> Dict[str, Any]:
    config = dict(CONFIG)
    db_envs = _load_environments_from_db()
    filtered_envs = _filter_environments_by_siem(db_envs, siem_filter) if siem_filter else db_envs
    config["qradar_envs"] = filtered_envs

    api_conf = dict(config.get("qradar_api") or {})
    tokens_map: Dict[str, str] = {}
    for env in filtered_envs:
        code = env.get("codigo") or env.get("code")
        api_token = env.get("api_token")
        if code and api_token:
            tokens_map[str(code)] = api_token

    for key, value in (api_conf.get("tokens") or {}).items():
        if key and value and key not in tokens_map:
            tokens_map[str(key)] = str(value)

    if tokens_map:
        api_conf["tokens"] = tokens_map
    config["qradar_api"] = api_conf
    return config


_cache_refresh_task: Optional[asyncio.Task] = None
_cache_refresh_stop: Optional[asyncio.Event] = None


alert_manager = AlertManager(
    _config_with_envs(siem_filter=DEFAULT_QRADAR_SIEM),
    fetch_monitoring=_get_alert_monitoring_payload,
    fetch_health=_get_health_payload,
    logger=logger,
)


async def _start_cache_refresh() -> None:
    global _cache_refresh_task, _cache_refresh_stop
    if _cache_refresh_task is not None and not _cache_refresh_task.done():
        return

    stop_event = asyncio.Event()
    _cache_refresh_stop = stop_event
    # A primeira coleta roda dentro do próprio _cache_refresh_loop, em background.
    # Não aguardamos aqui para não travar o startup do Uvicorn até todos os
    # ambientes serem coletados (isso chegava a levar minutos com muitos ambientes).
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


@app.on_event("startup")
async def _prepare_user_tables():
    await asyncio.to_thread(ensure_user_schema)


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


def _parse_json_array(raw: Any) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return []
    return []


def _safe_environment_payload_for_log(payload: Dict[str, Any]) -> Dict[str, Any]:
    safe = dict(payload or {})
    for key in ("api_token", "client_secret", "ssh_key"):
        if safe.get(key):
            safe[key] = "***"
    return safe


def _normalize_environment_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    def _normalize_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    license_gb_day = _normalize_text(
        data.get("license_gb_day")
        or data.get("licenseGbDay")
        or data.get("license_gb_dia")
    )
    if license_gb_day:
        license_gb_day = license_gb_day.replace(",", ".")

    payload = {
        "name": _normalize_text(data.get("name")) or "",
        "host": _normalize_text(data.get("host")),
        "collector": _normalize_text(data.get("collector")),
        "ssh_user": _normalize_text(data.get("ssh_user")),
        "ssh_key": _normalize_text(data.get("ssh_key")),
        "jmx_port": data.get("jmx_port"),
        "jmx_bean": _normalize_text(data.get("jmx_bean")),
        "appliances": _parse_json_array(data.get("appliances")),
        "connectivity_targets": _parse_json_array(data.get("connectivity_targets")),
        "codigo": _normalize_text(data.get("codigo")),
        "siem": _normalize_text(data.get("siem")),
        "api_token": _normalize_text(data.get("api_token")),
        "client_id": _normalize_text(data.get("client_id")),
        "client_secret": _normalize_text(data.get("client_secret")),
        "license_gb_day": license_gb_day,
        "base_url": _normalize_text(data.get("base_url")),
    }
    return payload


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
    context = {
        "request": request,
        "user": user,
        "title": "Monitoramento",
        "is_admin": is_admin(user) if user != "__wallboard__" else False,
    }
    return templates.TemplateResponse("index.html", context)


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
        for e in _load_environments_from_db()
    ]
    return JSONResponse(clients)

@app.get("/api/monitor")
def get_monitoring(
    request: Request, user: str = Depends(verify_user_required_api)
):
    selected_siem = request.query_params.get("siem") if hasattr(request, "query_params") else None
    payload = _get_monitoring_payload(selected_siem)
    return JSONResponse(payload)


@app.get("/api/health")
def get_health(user: str = Depends(verify_user_required_api)):
    payload = _get_health_payload()
    return JSONResponse(payload)


@app.get("/api/jira")
def get_jira(user: str = Depends(verify_user_required_api)):
    payload = _get_jira_payload()
    return JSONResponse(payload)

@app.exception_handler(AuthenticationError)
def handle_authentication_error(request: Request, exc: AuthenticationError):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "message": exc.message},
        status_code=401,
    )


async def _extract_request_json(request: Request) -> Dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON inválido")
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="JSON inválido")
    return data


@app.get("/api/admin/environments")
def api_list_environments(user: str = Depends(verify_user_required_api)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    return _load_environments_from_db()


@app.get("/api/admin/environments/{env_id}")
def api_get_environment(env_id: int, user: str = Depends(verify_user_required_api)):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    con = _con()
    try:
        environment_store.ensure_schema(con)
        env = environment_store.get_environment(con, env_id)
        if not env:
            raise HTTPException(status_code=404, detail="Ambiente não encontrado")
        return env
    finally:
        con.close()


@app.post("/api/admin/environments")
async def api_create_environment(
    request: Request, user: str = Depends(verify_user_required_api)
):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    raw_payload = await _extract_request_json(request)
    payload = _normalize_environment_payload(raw_payload)
    logger.warning(
        "[ENV_ADMIN] Criando ambiente payload_raw=%s payload_normalized=%s",
        _safe_environment_payload_for_log(raw_payload),
        _safe_environment_payload_for_log(payload),
    )
    if not payload.get("name"):
        raise HTTPException(status_code=400, detail="Nome do ambiente é obrigatório")
    con = _con()
    try:
        environment_store.ensure_schema(con)
        env_id = environment_store.save_environment(con, payload)
        saved = environment_store.get_environment(con, env_id)
        logger.warning(
            "[ENV_ADMIN] Ambiente criado id=%s name=%s license_gb_day=%s",
            env_id,
            payload.get("name"),
            (saved or {}).get("license_gb_day"),
        )
    finally:
        con.close()
    _invalidate_environment_caches()
    return {"id": env_id}


@app.put("/api/admin/environments/{env_id}")
async def api_update_environment(
    env_id: int, request: Request, user: str = Depends(verify_user_required_api)
):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    raw_payload = await _extract_request_json(request)
    payload = _normalize_environment_payload(raw_payload)
    if not payload.get("name"):
        raise HTTPException(status_code=400, detail="Nome do ambiente é obrigatório")
    con = _con()
    try:
        environment_store.ensure_schema(con)
        existing = environment_store.get_environment(con, env_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Ambiente não encontrado")
        if payload.get("license_gb_day") is None:
            payload["license_gb_day"] = existing.get("license_gb_day")
        logger.warning(
            "[ENV_ADMIN] Atualizando ambiente id=%s payload_raw=%s payload_normalized=%s existing_license=%s",
            env_id,
            _safe_environment_payload_for_log(raw_payload),
            _safe_environment_payload_for_log(payload),
            existing.get("license_gb_day"),
        )
        environment_store.save_environment(con, payload, env_id=env_id)
        updated = environment_store.get_environment(con, env_id)
        logger.warning(
            "[ENV_ADMIN] Ambiente atualizado id=%s name=%s license_gb_day=%s",
            env_id,
            payload.get("name"),
            (updated or {}).get("license_gb_day"),
        )
    finally:
        con.close()
    _invalidate_environment_caches()
    return {"id": env_id}


_LUCENE_CLEANUP_ALLOWED_DAYS = (5, 10, 15)
_lucene_cleanup_jobs: Dict[int, Dict[str, Any]] = {}
_lucene_cleanup_lock = Lock()


def _patch_monitoring_cache_storage(env_id: int, storage_pct: float) -> None:
    """Atualiza o storage de um ambiente já coletado no cache de monitoramento,
    sem esperar o próximo ciclo de coleta completo (que consulta todas as
    consoles via SSH/Zabbix e é caro demais para rodar só por causa de 1 valor)."""
    payload = _monitoring_cache.get_cached()
    if not payload:
        return
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return
    changed = False
    for row in rows:
        if isinstance(row, dict) and row.get("id") == env_id:
            row["storage"] = f"{storage_pct:.1f}%"
            changed = True
    if changed:
        _monitoring_cache.store(payload)


def _run_lucene_cleanup_job(env_id: int, env: Dict[str, Any], days: int, job: Dict[str, Any]) -> None:
    ssh = SSHClient()
    exit_code = None
    error_message = None
    try:
        result = ssh.run_cleanup_lucene(env, days)
        exit_code = result.get("exit_code")
        job["exit_code"] = exit_code
        job["stdout"] = (result.get("stdout") or "")[-4000:]
        job["stderr"] = (result.get("stderr") or "")[-4000:]
        if exit_code != 0:
            error_message = f"Script retornou código de saída {exit_code}."
    except Exception as exc:
        logger.exception(
            "Falha ao executar cleanup_lucene.sh ambiente_id=%s dias=%s", env_id, days
        )
        error_message = str(exc)

    # Reconsulta o storage e atualiza o cache de monitoramento ANTES de marcar
    # o job como concluído. Assim, quando o front detectar o status terminal
    # (e parar de dar polling) e recarregar o /api/monitor, o valor novo já
    # está disponível — sem essa ordem haveria uma corrida em que o front
    # buscaria o storage antigo por ainda não ter sido atualizado.
    try:
        fresh_pct = ssh.read_storage_percent(env)
    except Exception:
        fresh_pct = None
        logger.exception(
            "Falha ao reconsultar storage pós-limpeza ambiente_id=%s", env_id
        )
    if fresh_pct is not None:
        job["storage_after"] = fresh_pct
        _patch_monitoring_cache_storage(env_id, fresh_pct)

    job["status"] = "error" if error_message else "success"
    job["error"] = error_message
    job["finished_at"] = datetime.now(timezone.utc).isoformat()
    logger.info(
        "Limpeza de índices Lucene finalizada ambiente_id=%s dias=%s exit_code=%s storage_pos=%s",
        env_id,
        days,
        exit_code,
        job.get("storage_after"),
    )


@app.post("/api/admin/environments/{env_id}/cleanup-lucene")
async def api_run_cleanup_lucene(
    env_id: int, request: Request, user: str = Depends(verify_user_required_api)
):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")

    payload = await _extract_request_json(request)
    try:
        days = int(payload.get("days"))
    except Exception:
        raise HTTPException(status_code=400, detail="Parâmetro 'days' inválido")
    if days not in _LUCENE_CLEANUP_ALLOWED_DAYS:
        raise HTTPException(
            status_code=400,
            detail=f"Valor de dias não permitido. Use um destes: {_LUCENE_CLEANUP_ALLOWED_DAYS}",
        )

    con = _con()
    try:
        environment_store.ensure_schema(con)
        env = environment_store.get_environment(con, env_id)
    finally:
        con.close()
    if not env:
        raise HTTPException(status_code=404, detail="Ambiente não encontrado")
    if (env.get("siem") or "QRadar").strip().lower() != "qradar":
        raise HTTPException(
            status_code=400, detail="Ação disponível apenas para ambientes QRadar"
        )

    with _lucene_cleanup_lock:
        existing = _lucene_cleanup_jobs.get(env_id)
        if existing and existing.get("status") == "running":
            raise HTTPException(
                status_code=409,
                detail="Já existe uma limpeza de índices Lucene em execução para este ambiente",
            )
        job: Dict[str, Any] = {
            "status": "running",
            "days": days,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "exit_code": None,
            "error": None,
            "triggered_by": user,
        }
        _lucene_cleanup_jobs[env_id] = job

    logger.info(
        "Limpeza de índices Lucene iniciada ambiente_id=%s ambiente=%s dias=%s usuario=%s",
        env_id,
        env.get("name"),
        days,
        user,
    )
    Thread(target=_run_lucene_cleanup_job, args=(env_id, env, days, job), daemon=True).start()
    return job


@app.get("/api/admin/environments/{env_id}/cleanup-lucene")
def api_get_cleanup_lucene_status(
    env_id: int, user: str = Depends(verify_user_required_api)
):
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin required")
    job = _lucene_cleanup_jobs.get(env_id)
    if not job:
        return {"status": "idle"}
    return job


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


@app.post("/admin/alerts/run")
async def run_alerts_now(
    request: Request, user: str = Depends(verify_user_required_page)
) -> Response:
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "message": "Você não tem permissão para acessar esta área.",
            },
            status_code=403,
        )
    try:
        await asyncio.to_thread(_refresh_all_caches)
        await asyncio.to_thread(alert_manager.run_once, force_send=True)
    except Exception:
        logger.exception(
            "Alerta - Erro ao executar rotina de alertas a partir do painel admin"
        )
        return _redirect_admin_users(
            error="Falha ao executar a rotina de alertas. Verifique os logs."
        )
    return _redirect_admin_users(
        success="Rotina de alertas executada. Consulte os logs para detalhes."
    )


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request, user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Você não tem permissão para acessar esta área."},
            status_code=403,
        )
    ensure_user_schema()
    available_permissions = list_permissions()
    permission_select_size = max(1, min(len(available_permissions), 4))

    con = _con()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, username, is_active, COALESCE(is_admin,0) as is_admin
        FROM users
        ORDER BY username
        """
    )
    users = cur.fetchall()
    cur.execute(
        """
        SELECT up.user_id, p.code, p.name
        FROM user_permissions up
        JOIN permissions p ON p.id = up.permission_id
        """
    )
    permission_rows = cur.fetchall()
    con.close()

    permission_map: Dict[int, list[Dict[str, str]]] = {}
    for row in permission_rows:
        entry = {"code": row["code"], "name": row["name"]}
        permission_map.setdefault(row["user_id"], []).append(entry)

    mapped = []
    for u in users:
        assigned = list(permission_map.get(u["id"], []))
        assigned_sorted = sorted(
            assigned,
            key=lambda item: item["name"].lower(),
        )
        mapped.append(
            {
                "id": u["id"],
                "username": u["username"],
                "is_active": int(u["is_active"]) == 1,
                "is_admin": int(u["is_admin"]) == 1,
                "permission_codes": [item["code"] for item in assigned_sorted],
                "permission_labels": [item["name"] for item in assigned_sorted],
            }
        )

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
            "available_permissions": available_permissions,
            "permission_select_size": permission_select_size,
        },
    )

@app.get("/users/admin", response_class=HTMLResponse)
def legacy_admin_users_page(request: Request, user: str = Depends(verify_user_required_page)):
    """Mantém compatibilidade com a rota legada /users/admin."""
    return admin_users_page(request, user)


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin_flag: str = Form(None),
    permissions: List[str] = Form([]),
    user: str = Depends(verify_user_required_page),
):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem criar usuários."},
            status_code=403,
        )
    is_admin_val = 1 if (is_admin_flag in ("on", "true", "1", "yes")) else 0
    permission_codes = sorted(
        {code.strip() for code in permissions if str(code).strip()}
    )
    ensure_user_schema()
    con = _con()
    cur = con.cursor()
    new_user_id: Optional[int] = None
    try:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, is_active, is_admin)
            VALUES (?,?,1,?)
            """,
            (username, hash_password(password), is_admin_val),
        )
        con.commit()
        new_user_id = int(cur.lastrowid)
    except sqlite3.IntegrityError:
        return _redirect_admin_users(error="Já existe um usuário com esse nome.")
    finally:
        con.close()
    if new_user_id is not None:
        try:
            set_user_permissions(new_user_id, permission_codes)
        except ValueError as exc:
            return _redirect_admin_users(error=str(exc))
    return _redirect_admin_users(success=f"Usuário {username} criado com sucesso.")

@app.post("/users/admin/create")
def legacy_admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin_flag: str = Form(None),
    permissions: List[str] = Form([]),
    user: str = Depends(verify_user_required_page),
):
    return admin_create_user(
        request,
        username,
        password,
        is_admin_flag,
        permissions,
        user,
    )


@app.post("/admin/users/toggle")
def admin_toggle_user(request: Request, user_id: int = Form(...), field: str = Form(...), user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "message": "Somente administradores podem alterar usuários."},
            status_code=403,
        )
    allowed_fields = {
        "is_active": "Status de atividade atualizado para {username}.",
        "is_admin": "Permissão de administrador atualizada para {username}.",
    }
    if field not in allowed_fields:
        return _redirect_admin_users(error="Ação inválida para o usuário selecionado.")
    con = _con()
    cur = con.cursor()
    target_username: Optional[str] = None
    try:
        cur.execute(
            """
            SELECT username, is_active,
                   COALESCE(is_admin,0) as is_admin
            FROM users
            WHERE id=?
            """,
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
    message_template = allowed_fields[field]
    return _redirect_admin_users(success=message_template.format(username=target_username or ""))


@app.post("/admin/users/permissions")
def admin_update_user_permissions(
    request: Request,
    user_id: int = Form(...),
    permissions: List[str] = Form([]),
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
    finally:
        con.close()
    try:
        set_user_permissions(user_id, permissions)
    except ValueError as exc:
        return _redirect_admin_users(error=str(exc))
    return _redirect_admin_users(success=f"Permissões atualizadas para {target_username}.")


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
    cur.execute(
        """
        SELECT username,
               COALESCE(is_admin,0) as is_admin,
               is_active
        FROM users
        ORDER BY username
        """
    )
    data = [
        {
            "username": r[0],
            "is_admin": int(r[1]) == 1,
            "is_active": int(r[2]) == 1,
        }
        for r in cur.fetchall()
    ]
    con.close()
    return data

@app.get("/healthz")
def healthz():
    return {"ok": True}

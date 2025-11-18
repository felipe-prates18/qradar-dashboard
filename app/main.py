import asyncio
import json
import logging
import secrets
import sqlite3
from urllib.parse import urlencode
from datetime import datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
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
    has_threat_hunting_access,
    ensure_user_schema,
    list_permissions,
    set_user_permissions,
    get_user_permission_codes,
    THREAT_HUNTING_PERMISSION_CODE,
)
import requests
from requests.exceptions import RequestException

from .collectors import collect_monitoring_data, collect_health_data
from .alerts import AlertManager
from . import threat_hunting
from .services import environment_store, qradar_rules

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

THREAT_HUNTING_TECHNOLOGY_SUGGESTIONS = [
    "Firewall",
    "Windows",
    "Linux",
    "WAF",
    "EDR",
    "Cloud",
    "VPN",
    "Proxy",
    "Email",
    "Banco de Dados",
]

THREAT_HUNTING_SIEM_SUGGESTIONS = [
    "QRadar",
    "Elastic",
    "Microsoft Sentinel",
    "Splunk",
    "Wazuh",
    "Crowdstrike NG-SIEM",
    "Google SecOps",
    "Cortex SIEM",
]

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
_health_cache = _DataCache(CACHE_TTL_SECONDS)
_threat_hunting_cache = _DataCache(CACHE_TTL_SECONDS)


def _invalidate_environment_caches() -> None:
    _monitoring_cache.clear()
    _health_cache.clear()
    _threat_hunting_cache.clear()


def _refresh_monitoring_cache() -> Dict[str, Any]:
    return _monitoring_cache.refresh(
        lambda: collect_monitoring_data(_config_with_envs(), logger=logger)
    )


def _refresh_health_cache() -> Dict[str, Any]:
    return _health_cache.refresh(
        lambda: collect_health_data(_config_with_envs(), logger=logger)
    )


def _collect_threat_hunting_counts() -> Dict[str, Any]:
    config_with_envs = _config_with_envs()
    try:
        (
            environment_counts,
            _unused_monthly_counts,
            summary_errors,
        ) = qradar_rules.collect_rule_statistics(config_with_envs, logger=logger)
    except Exception:
        logger.exception("Falha ao consultar totais de regras do QRadar")
        environment_counts = []
        monthly_counts = {}
        summary_errors = [
            "Não foi possível consultar o endpoint /analytics/rules do QRadar no momento."
        ]
    try:
        (
            log_source_types,
            log_source_errors,
        ) = qradar_rules.collect_log_source_types(config_with_envs, logger=logger)
    except Exception:
        logger.exception(
            "Falha ao consultar tecnologias de log source do QRadar"
        )
        log_source_types = {}
        log_source_errors = {}
    monthly_counts: Dict[str, Dict[str, int]] = {}
    con: Optional[sqlite3.Connection] = None
    try:
        con = _con()
        threat_hunting.ensure_schema(con)
        now = datetime.utcnow()
        month_key = f"{now.year:04d}-{now.month:02d}"
        snapshot_required = threat_hunting.should_record_monthly_snapshot(now)
        if not snapshot_required:
            try:
                snapshot_required = not threat_hunting.month_snapshot_exists(
                    con, month_key
                )
            except Exception:
                logger.exception(
                    "Falha ao verificar existência de totais mensais para %s",
                    month_key,
                )
                snapshot_required = True
        if environment_counts:
            totals_map: Dict[str, int] = {}
            for item in environment_counts:
                env_name = item.get("environment")
                if not env_name:
                    continue
                try:
                    total_value = int(item.get("total"))
                except Exception:
                    continue
                totals_map[str(env_name)] = total_value
            if totals_map and snapshot_required:
                try:
                    threat_hunting.record_monthly_totals(
                        con,
                        month_key,
                        totals_map,
                        collected_at=now,
                    )
                except Exception:
                    logger.exception(
                        "Falha ao registrar totais mensais de casos de uso no banco local"
                    )
        monthly_counts = threat_hunting.list_monthly_totals(con)
    except Exception:
        logger.exception(
            "Falha ao carregar totais mensais de casos de uso para o Threat Hunting"
        )
    finally:
        if con is not None:
            con.close()
    return {
        "environment_counts": environment_counts,
        "monthly_counts": monthly_counts,
        "summary_errors": summary_errors,
        "log_source_types": log_source_types,
        "log_source_errors": log_source_errors,
    }


def _refresh_threat_hunting_cache() -> Dict[str, Any]:
    return _threat_hunting_cache.refresh(_collect_threat_hunting_counts)


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


def _get_threat_hunting_payload() -> Dict[str, Any]:
    payload = _threat_hunting_cache.get_cached()
    if payload is None:
        logger.info("Cache de Threat Hunting vazio. Coletando dados iniciais.")
        return _refresh_threat_hunting_cache()
    if _threat_hunting_cache.is_expired():
        logger.warning("Cache de Threat Hunting expirado. Atualizando dados sob demanda.")
        return _refresh_threat_hunting_cache()
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
    try:
        _refresh_threat_hunting_cache()
    except Exception:
        logger.exception("Falha ao atualizar o cache de Threat Hunting")


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


def _config_with_envs() -> Dict[str, Any]:
    config = dict(CONFIG)
    db_envs = _load_environments_from_db()
    config["qradar_envs"] = db_envs

    api_conf = dict(config.get("qradar_api") or {})
    tokens_map: Dict[str, str] = {}
    for env in db_envs:
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
    _config_with_envs(),
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


@app.on_event("startup")
async def _prepare_user_tables():
    await asyncio.to_thread(ensure_user_schema)


@app.on_event("startup")
async def _prepare_threat_hunting_tables():
    await asyncio.to_thread(_prepare_threat_hunting_schema)


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


def _prepare_threat_hunting_schema() -> None:
    con = _con()
    try:
        threat_hunting.ensure_schema(con)
    finally:
        con.close()


def _environment_name_map() -> Dict[str, str]:
    envs = _load_environments_from_db()
    mapping: Dict[str, str] = {}
    for env in envs:
        raw_name = env.get("name")
        if not raw_name:
            continue
        name = str(raw_name).strip()
        if not name:
            continue
        lowered_name = name.lower()
        mapping[lowered_name] = name
        for key in ("codigo", "code"):
            alias = env.get(key)
            if not alias:
                continue
            alias_text = str(alias).strip()
            if not alias_text:
                continue
            mapping[alias_text.lower()] = name
    return mapping


def _normalize_environment_value(
    value: Optional[str],
    mapping: Optional[Dict[str, str]] = None,
) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    lookup = (mapping or _environment_name_map()).get(text.lower())
    if lookup:
        return lookup
    return text


def _environment_suggestions() -> list[str]:
    mapping = _environment_name_map()
    names = {value for value in mapping.values() if value}
    return sorted(names, key=str.lower)


_MONTH_NAMES_PT = [
    "Jan",
    "Fev",
    "Mar",
    "Abr",
    "Mai",
    "Jun",
    "Jul",
    "Ago",
    "Set",
    "Out",
    "Nov",
    "Dez",
]


def _format_month_label_pt(year: int, month: int) -> str:
    if 1 <= month <= 12:
        return f"{_MONTH_NAMES_PT[month - 1]}/{year}"
    return f"{month:02d}/{year}"


def _parse_month_key(value: str) -> Optional[Tuple[int, int]]:
    parts = str(value or "").split("-", 1)
    if len(parts) != 2:
        return None
    try:
        year = int(parts[0])
        month = int(parts[1])
    except ValueError:
        return None
    if month < 1 or month > 12:
        return None
    return year, month


def _iterate_month_range(
    start_year: int, start_month: int, end_year: int, end_month: int
) -> Iterable[Tuple[int, int]]:
    year, month = start_year, start_month
    while (year, month) <= (end_year, end_month):
        yield year, month
        month += 1
        if month > 12:
            month = 1
            year += 1


def _build_environment_config_lookup(
    env_name_map: Dict[str, str]
) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for env in _load_environments_from_db() or []:
        if not isinstance(env, dict):
            continue
        keys: set[str] = set()
        raw_name = env.get("name")
        normalized_name = _normalize_environment_value(raw_name, env_name_map)
        if normalized_name:
            keys.add(normalized_name.lower())
        for alias_key in ("codigo", "code"):
            alias_value = env.get(alias_key)
            if not alias_value:
                continue
            alias_text = str(alias_value).strip()
            if not alias_text:
                continue
            keys.add(alias_text.lower())
            normalized_alias = _normalize_environment_value(alias_text, env_name_map)
            if normalized_alias:
                keys.add(normalized_alias.lower())
        for key in keys:
            lookup.setdefault(key, env)
    return lookup


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


def _normalize_environment_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    def _normalize_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

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
    }
    return payload


def _build_monthly_series(
    month_counts: Optional[Dict[str, int]], current_year: int, current_month: int
) -> List[Dict[str, Any]]:
    if not month_counts:
        return []
    parsed = [_parse_month_key(key) for key in month_counts.keys()]
    valid = [item for item in parsed if item]
    if not valid:
        return []
    start_year, start_month = min(valid)
    end_year, end_month = max(valid)
    if (end_year, end_month) < (current_year, current_month):
        end_year, end_month = current_year, current_month
    series: List[Dict[str, Any]] = []
    for year, month in _iterate_month_range(start_year, start_month, end_year, end_month):
        key = f"{year:04d}-{month:02d}"
        count = int(month_counts.get(key, 0))
        series.append(
            {
                "month": key,
                "label": _format_month_label_pt(year, month),
                "count": count,
            }
        )
    return series


def _build_environment_summary(
    environment_counts: List[Dict[str, Any]],
    monthly_counts: Dict[str, Dict[str, int]],
    env_name_map: Dict[str, str],
    log_source_lookup: Dict[str, List[str]],
    log_source_errors: Dict[str, str],
) -> Dict[str, Any]:
    config_lookup = _build_environment_config_lookup(env_name_map)
    now = datetime.now()
    current_year, current_month = now.year, now.month
    summary: Dict[str, Any] = {}
    for item in environment_counts:
        env_name = _normalize_environment_value(item.get("environment"), env_name_map)
        if not env_name:
            continue
        key = env_name.lower()
        config = config_lookup.get(key)
        code_value = None
        if isinstance(config, dict):
            code_value = config.get("codigo") or config.get("code")
        log_types = log_source_lookup.get(key, [])
        month_data = monthly_counts.get(env_name)
        series = _build_monthly_series(month_data, current_year, current_month)
        api_total_raw = item.get("total")
        api_total = None
        if isinstance(api_total_raw, (int, float)):
            api_total = int(api_total_raw)
        notes: List[str] = []
        source_value = str(item.get("source") or "api").lower()
        source_label = (
            "Fonte: Cadastro local" if source_value == "local" else "Fonte: API do QRadar"
        )
        notes.append(source_label)
        if item.get("error"):
            notes.append(str(item["error"]))
        if api_total is None:
            notes.append("Total de casos ativos indisponível na API do QRadar.")
        log_error = log_source_errors.get(key)
        if log_error:
            notes.append(f"Tecnologias: {log_error}")
        summary[env_name] = {
            "name": env_name,
            "code": code_value,
            "active_use_cases_api": api_total,
            "log_source_types": log_types,
            "use_case_monthly_series": series,
            "notes": notes,
            "source": source_value,
        }
    return summary


def _threat_hunting_allowed(username: Optional[str]) -> bool:
    if not username:
        return False
    if username == "__wallboard__":
        return False
    return is_admin(username) or has_threat_hunting_access(username)


def _require_threat_hunting_page_access(
    user: str = Depends(verify_user_required_page),
) -> str:
    if not _threat_hunting_allowed(user):
        raise AuthenticationError(
            "Você não tem permissão para acessar o módulo de Threat Hunting."
        )
    return user


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
        "can_access_threat_hunting": _threat_hunting_allowed(user),
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
    if not payload.get("name"):
        raise HTTPException(status_code=400, detail="Nome do ambiente é obrigatório")
    con = _con()
    try:
        environment_store.ensure_schema(con)
        env_id = environment_store.save_environment(con, payload)
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
        environment_store.save_environment(con, payload, env_id=env_id)
    finally:
        con.close()
    _invalidate_environment_caches()
    return {"id": env_id}


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


def _redirect_threat_hunting(
    success: Optional[str] = None,
    error: Optional[str] = None,
    extra_params: Optional[Dict[str, str]] = None,
) -> RedirectResponse:
    params: Dict[str, str] = {}
    if success:
        params["success"] = success
    if error:
        params["error"] = error
    if extra_params:
        params.update({k: v for k, v in extra_params.items() if v is not None})
    query = urlencode(params)
    url = "/threat-hunting"
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
    permission_name_map = {
        perm["code"]: perm["name"] for perm in available_permissions
    }
    permission_select_size = max(1, min(len(available_permissions), 4))

    con = _con()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, username, is_active, COALESCE(is_admin,0) as is_admin,
               COALESCE(can_access_threat_hunting,0) as can_access_threat_hunting
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
        assigned_codes = {item["code"] for item in assigned}
        has_threat = (
            THREAT_HUNTING_PERMISSION_CODE in assigned_codes
            or int(u["can_access_threat_hunting"]) == 1
        )
        if has_threat and THREAT_HUNTING_PERMISSION_CODE not in assigned_codes:
            assigned.append(
                {
                    "code": THREAT_HUNTING_PERMISSION_CODE,
                    "name": permission_name_map.get(
                        THREAT_HUNTING_PERMISSION_CODE,
                        "Threat Hunting",
                    ),
                }
            )
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
                "can_access_threat_hunting": has_threat,
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


@app.get("/threat-hunting", response_class=HTMLResponse)
def threat_hunting_page(
    request: Request,
    user: str = Depends(_require_threat_hunting_page_access),
):
    params = request.query_params
    success_message = params.get("success")
    error_message = params.get("error")

    threat_cache_payload = _get_threat_hunting_payload()
    environment_counts = threat_cache_payload.get("environment_counts") or []
    summary_errors = threat_cache_payload.get("summary_errors") or []

    monthly_use_case_counts: Dict[str, Dict[str, int]] = {}
    env_name_map = _environment_name_map()

    con = _con()
    try:
        threat_hunting.ensure_schema(con)
    finally:
        con.close()

    api_monthly_counts_raw = threat_cache_payload.get("monthly_counts") or {}
    api_monthly_counts: Dict[str, Dict[str, int]] = {}
    if isinstance(api_monthly_counts_raw, dict):
        for raw_env, month_map in api_monthly_counts_raw.items():
            normalized_env = _normalize_environment_value(raw_env, env_name_map)
            env_key = normalized_env or (str(raw_env).strip() if raw_env else "")
            if not env_key or not isinstance(month_map, dict):
                continue
            target_map = api_monthly_counts.setdefault(env_key, {})
            for month_key, value in month_map.items():
                parsed = _parse_month_key(month_key)
                if not parsed:
                    parsed = _parse_month_key(str(month_key))
                if not parsed:
                    continue
                year, month = parsed
                normalized_key = f"{year:04d}-{month:02d}"
                try:
                    count_value = int(value)
                except Exception:
                    try:
                        count_value = int(float(value))
                    except Exception:
                        continue
                target_map[normalized_key] = target_map.get(normalized_key, 0) + max(0, count_value)

    monthly_use_case_counts = api_monthly_counts

    def _normalise_env_key(raw_env: Any) -> Optional[str]:
        normalized_env = _normalize_environment_value(raw_env, env_name_map)
        if normalized_env:
            return normalized_env.lower()
        if isinstance(raw_env, str):
            stripped = raw_env.strip()
            if stripped:
                return stripped.lower()
        return None

    raw_log_source_types = threat_cache_payload.get("log_source_types") or {}
    log_source_type_lookup: Dict[str, List[str]] = {}
    if isinstance(raw_log_source_types, dict):
        for raw_env, values in raw_log_source_types.items():
            key = _normalise_env_key(raw_env)
            if not key:
                continue
            collected: List[str] = []
            if isinstance(values, (list, tuple, set)):
                for value in values:
                    try:
                        text = str(value).strip()
                    except Exception:
                        continue
                    if text and text not in collected:
                        collected.append(text)
            elif isinstance(values, str):
                text = values.strip()
                if text:
                    collected.append(text)
            if collected:
                log_source_type_lookup[key] = sorted(
                    collected, key=lambda item: item.lower()
                )

    raw_log_source_errors = threat_cache_payload.get("log_source_errors") or {}
    log_source_error_lookup: Dict[str, str] = {}
    if isinstance(raw_log_source_errors, dict):
        for raw_env, value in raw_log_source_errors.items():
            key = _normalise_env_key(raw_env)
            if not key:
                continue
            try:
                text = str(value).strip()
            except Exception:
                continue
            if text:
                log_source_error_lookup[key] = text

    if environment_counts:
        for item in environment_counts:
            normalized_env = _normalize_environment_value(
                item.get("environment"), env_name_map
            )
            if normalized_env:
                item["environment"] = normalized_env
            source_value = str(item.get("source") or "api").lower()
            if source_value != "api":
                source_value = "api"
            item["source"] = source_value

    environment_summary_data = _build_environment_summary(
        environment_counts,
        monthly_use_case_counts,
        env_name_map,
        log_source_type_lookup,
        log_source_error_lookup,
    )
    environment_summary_json = json.dumps(environment_summary_data, ensure_ascii=False)

    env_suggestions = set(_environment_suggestions())
    env_suggestions.update(item.get("environment") for item in environment_counts)
    environment_options = {
        _normalize_environment_value(value, env_name_map)
        for value in env_suggestions
        if value
    }

    context = {
        "request": request,
        "user": user,
        "title": "Threat Hunting",
        "success": success_message,
        "error": error_message,
        "environment_counts": environment_counts,
        "summary_errors": summary_errors,
        "environment_options": sorted(
            filter(None, environment_options), key=str.lower
        ),
        "is_admin": is_admin(user),
        "environment_summary_json": environment_summary_json,
    }
    return templates.TemplateResponse("threat_hunting.html", context)


@app.post("/admin/users/create")
def admin_create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    is_admin_flag: str = Form(None),
    can_access_threat_hunting_flag: str = Form(None),
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
    permission_codes = list(permissions)
    if can_access_threat_hunting_flag in ("on", "true", "1", "yes"):
        permission_codes.append(THREAT_HUNTING_PERMISSION_CODE)
    permission_codes = sorted(
        {code.strip() for code in permission_codes if str(code).strip()}
    )
    threat_val = 1 if THREAT_HUNTING_PERMISSION_CODE in permission_codes else 0
    ensure_user_schema()
    con = _con()
    cur = con.cursor()
    new_user_id: Optional[int] = None
    try:
        cur.execute(
            """
            INSERT INTO users (username, password_hash, is_active, is_admin, can_access_threat_hunting)
            VALUES (?,?,1,?,?)
            """,
            (username, hash_password(password), is_admin_val, threat_val),
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
    can_access_threat_hunting_flag: str = Form(None),
    permissions: List[str] = Form([]),
    user: str = Depends(verify_user_required_page),
):
    return admin_create_user(
        request,
        username,
        password,
        is_admin_flag,
        can_access_threat_hunting_flag,
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
        "can_access_threat_hunting": "Permissões de Threat Hunting atualizadas para {username}.",
    }
    if field not in allowed_fields:
        return _redirect_admin_users(error="Ação inválida para o usuário selecionado.")
    con = _con()
    cur = con.cursor()
    new_permission_codes: Optional[Iterable[str]] = None
    target_username: Optional[str] = None
    try:
        cur.execute(
            """
            SELECT username, is_active,
                   COALESCE(is_admin,0) as is_admin,
                   COALESCE(can_access_threat_hunting,0) as can_access_threat_hunting
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
        if field == "can_access_threat_hunting":
            current_codes = set(get_user_permission_codes(user_id))
            has_permission = (
                THREAT_HUNTING_PERMISSION_CODE in current_codes
                or int(row["can_access_threat_hunting"]) == 1
            )
            if has_permission:
                current_codes.discard(THREAT_HUNTING_PERMISSION_CODE)
            else:
                current_codes.add(THREAT_HUNTING_PERMISSION_CODE)
            new_permission_codes = current_codes
        else:
            cur.execute(
                f"UPDATE users SET {field}=CASE {field} WHEN 1 THEN 0 ELSE 1 END WHERE id=?",
                (user_id,),
            )
            con.commit()
    finally:
        con.close()
    if field == "can_access_threat_hunting":
        try:
            set_user_permissions(user_id, new_permission_codes or [])
        except ValueError as exc:
            return _redirect_admin_users(error=str(exc))
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
               is_active,
               COALESCE(can_access_threat_hunting,0) as can_access_threat_hunting
        FROM users
        ORDER BY username
        """
    )
    data = [
        {
            "username": r[0],
            "is_admin": int(r[1]) == 1,
            "is_active": int(r[2]) == 1,
            "can_access_threat_hunting": int(r[3]) == 1,
        }
        for r in cur.fetchall()
    ]
    con.close()
    return data

@app.get("/healthz")
def healthz():
    return {"ok": True}


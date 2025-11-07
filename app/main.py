import json
import logging
import secrets
import sqlite3
from datetime import datetime
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
from .services.zabbix_client import ZabbixClient
from .services.ssh_client import SSHClient

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

def pct(v):
    try:
        return f"{float(v):.1f}%" if v is not None else "—"
    except Exception:
        return "—"


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
    zb_conf = CONFIG.get("zabbix", {})
    zbx = ZabbixClient(zb_conf)
    ssh = SSHClient()
    items_conf = CONFIG.get("items", {})
    data = []
    for env in CONFIG.get("qradar_envs", []):
        name = env.get("name")
        env_code = env.get("codigo") or env.get("code") or name or "desconhecido"
        logger.info("Iniciando coleta de métricas para ambiente=%s", env_code)
        metrics = zbx.get_metrics(
            hostname=name,
            items=items_conf,
            zabbix_host_override=env.get("zabbix_host_override"),
        )
        logger.info(
            "Métricas coletadas ambiente=%s cpu=%s memory=%s storage=%s",
            env_code,
            metrics.get("cpu"),
            metrics.get("memory"),
            metrics.get("storage"),
        )

        appliances_out = []
        for appliance in env.get("appliances", []):
            appliance_name = appliance.get("name") or appliance.get("hostname") or appliance.get("zabbix_host") or "—"
            appliance_host_hint = appliance.get("hostname") or appliance.get("name") or appliance_name
            appliance_override = appliance.get("zabbix_host") or appliance.get("zabbix_host_override")
            logger.info(
                "Iniciando coleta de appliance ambiente=%s appliance=%s host_hint=%s override=%s",
                env_code,
                appliance_name,
                appliance_host_hint,
                appliance_override,
            )
            appliance_metrics = zbx.get_metrics(
                hostname=appliance_host_hint,
                items=items_conf,
                zabbix_host_override=appliance_override,
            )
            logger.info(
                "Métricas de appliance coletadas ambiente=%s appliance=%s cpu=%s memory=%s storage=%s",
                env_code,
                appliance_name,
                appliance_metrics.get("cpu"),
                appliance_metrics.get("memory"),
                appliance_metrics.get("storage"),
            )
            appliances_out.append({
                "name": appliance_name,
                "cpu": pct(appliance_metrics.get("cpu")),
                "memory": pct(appliance_metrics.get("memory")),
                "storage": pct(appliance_metrics.get("storage")),
            })

        lic_eps, lic_exp = "Erro", "Erro"
        lic_exp_list, lic_breakdown = [], []
        try:
            logger.info("Coletando informações de licença ambiente=%s", env_code)
            lic = ssh.read_license(env)
            if isinstance(lic, dict):
                lic_eps = str(lic.get("license_eps", "Erro"))
                lic_exp = lic.get("license_expiration", "Erro")
                lic_exp_list = lic.get("license_expiration_list") or []
                lic_breakdown = lic.get("license_breakdown") or []
            logger.info(
                "Licença coletada ambiente=%s eps=%s expiracao=%s",
                env_code,
                lic_eps,
                lic_exp,
            )
        except Exception as exc:
            logger.exception("Erro ao coletar licença ambiente=%s", env_code)

        eps_cur, eps_max = "—", "—"
        try:
            logger.info("Coletando informações de EPS ambiente=%s", env_code)
            eps = ssh.read_eps(env)
            if isinstance(eps, dict):
                if eps.get("eps_current") is not None:
                    eps_cur = f"{int(eps['eps_current'])}"
                if eps.get("eps_max") is not None:
                    eps_max = f"{int(eps['eps_max'])}"
            logger.info(
                "EPS coletado ambiente=%s atual=%s max=%s",
                env_code,
                eps_cur,
                eps_max,
            )
        except Exception as exc:
            logger.exception("Erro ao coletar EPS ambiente=%s", env_code)

        data.append({
            "name": name,
            "code": env.get("codigo") or env.get("code"),
            "cpu": pct(metrics.get("cpu")),
            "memory": pct(metrics.get("memory")),
            "storage": pct(metrics.get("storage")),
            "eps_current": eps_cur,
            "eps_max": eps_max,
            "license_eps": lic_eps,
            "license_exp": lic_exp,
            "license_exp_list": lic_exp_list,
            "license_breakdown": lic_breakdown,
            "appliances": appliances_out,
        })
    return JSONResponse({"updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"), "rows": data})


@app.get("/api/health")
def get_health(user: str = Depends(verify_user_required_api)):
    health_conf = CONFIG.get("health", {}) or {}
    services = health_conf.get("services") or []
    ssh = SSHClient()

    def _connectivity_target(entry):
        if not entry:
            return None
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            for key in (
                "target",
                "host",
                "hostname",
                "ip",
                "address",
                "management_ip",
            ):
                value = entry.get(key)
                if value:
                    return value
        return None

    def _connectivity_name(entry):
        if not entry:
            return "Appliance"
        if isinstance(entry, str):
            return entry or "Appliance"
        if isinstance(entry, dict):
            return entry.get("name") or entry.get("label") or entry.get("target") or "Appliance"
        return "Appliance"

    rows = []
    for env in CONFIG.get("qradar_envs", []):
        env_name = env.get("name") or env.get("host") or "Ambiente"
        services_result = []
        connectivity_result = []
        errors = []

        client = None
        try:
            logger.info("Iniciando conexão SSH ambiente=%s", env_name)
            client = ssh.connect_env(env)
            logger.info("Conexão SSH estabelecida ambiente=%s", env_name)
        except Exception as exc:
            error_message = str(exc)
            errors.append(error_message)
            logger.exception("Falha ao conectar ao ambiente %s", env_name)
            if services:
                services_result = [
                    {
                        "name": service,
                        "status": "error",
                        "enabled": "unknown",
                        "sub_state": "",
                        "description": "",
                        "error": error_message,
                    }
                    for service in services
                ]
            targets = env.get("connectivity_targets") or []
            if targets:
                for target_entry in targets:
                    connectivity_result.append(
                        {
                            "name": _connectivity_name(target_entry),
                            "target": _connectivity_target(target_entry),
                            "reachable": False,
                            "latency_ms": None,
                            "packet_loss": None,
                            "status": "error",
                            "error": error_message,
                        }
                    )
            rows.append(
                {
                    "name": env_name,
                    "services": services_result,
                    "connectivity": connectivity_result,
                    "errors": errors,
                }
            )
            continue

        try:
            logger.info("Verificando serviços ambiente=%s", env_name)
            services_result = ssh.check_services(env, services, client=client)
            logger.info("Status de serviços coletados ambiente=%s total=%s", env_name, len(services_result))
            logger.info("Verificando conectividade ambiente=%s", env_name)
            connectivity_result = ssh.check_connectivity(env, client=client)
            logger.info("Resultados de conectividade coletados ambiente=%s total=%s", env_name, len(connectivity_result))
        except Exception as exc:
            errors.append(str(exc))
            logger.exception("Erro durante verificação de saúde do ambiente %s", env_name)
        finally:
            if client is not None:
                try:
                    client.close()
                    logger.info("Conexão SSH encerrada ambiente=%s", env_name)
                except Exception:
                    pass

        rows.append(
            {
                "name": env_name,
                "services": services_result,
                "connectivity": connectivity_result,
                "errors": errors,
            }
        )

    payload = {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": rows,
        "settings": {
            "latency_warning_ms": health_conf.get("latency_warning_ms", 150),
            "latency_critical_ms": health_conf.get("latency_critical_ms", 300),
            "packet_loss_warning": health_conf.get("packet_loss_warning", 5),
        },
    }

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


import json
import sqlite3
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from .auth import auth_router, verify_user_required_page, verify_user_required_api, is_admin
from .services.zabbix_client import ZabbixClient
from .services.ssh_client import SSHClient

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR.parent / "users.db"

with open(BASE_DIR / "config.json", "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

app = FastAPI(title="QRadar Monitoring App")
app.add_middleware(SessionMiddleware, secret_key=CONFIG.get("session_secret", "qradar-app-secret"), same_site="lax")
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.include_router(auth_router)

def _con():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con

def pct(v):
    try:
        return f"{float(v):.1f}%" if v is not None else "—"
    except Exception:
        return "—"

@app.get("/", response_class=HTMLResponse)
def home(request: Request, user: str = Depends(verify_user_required_page)):
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "title": "Monitoramento & Execução"})

@app.get("/api/clients")
def get_clients(user: str = Depends(verify_user_required_api)):
    clients = [{"name": e.get("name", ""), "host": e.get("host", "")} for e in CONFIG.get("qradar_envs", [])]
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
        metrics = zbx.get_metrics(hostname=name, items=items_conf, zabbix_host_override=env.get("zabbix_host_override"))

        lic_eps, lic_exp = "Erro", "Erro"
        try:
            lic = ssh.read_license(env)
            if isinstance(lic, dict):
                lic_eps = str(lic.get("license_eps", "Erro"))
                lic_exp = lic.get("license_expiration", "Erro")
        except Exception:
            pass

        eps_cur, eps_max = "—", "—"
        try:
            eps = ssh.read_eps(env)
            if isinstance(eps, dict):
                if eps.get("eps_current") is not None:
                    eps_cur = f"{int(eps['eps_current'])}"
                if eps.get("eps_max") is not None:
                    eps_max = f"{int(eps['eps_max'])}"
        except Exception:
            pass

        data.append({
            "name": name,
            "cpu": pct(metrics.get("cpu")),
            "memory": pct(metrics.get("memory")),
            "storage": pct(metrics.get("storage")),
            "eps_current": eps_cur,
            "eps_max": eps_max,
            "license_eps": lic_eps,
            "license_exp": lic_exp,
        })
    return JSONResponse({"updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"), "rows": data})

@app.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(request: Request, user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        html = f"""<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
        <title>Acesso restrito</title><link rel="stylesheet" href="/static/style.css"></head>
        <body><div class="wrap"><header><div class="brand">
        <img src="/static/logo-asper.png"><div class="title"><h1>Acesso restrito</h1><div class="sub">Área administrativa</div></div></div>
        <div class="row"><span class="small">Usuário: {user}</span><a class="btn secondary" href="/">Voltar</a></div></header>
        <section class="card"><div class="alert warn">Você não tem permissão para acessar esta área.</div></section></div></body></html>"""
        return HTMLResponse(content=html, status_code=403)

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

    body_rows = "".join([
        f"""<tr>
          <td>{u['username']}</td>
          <td>{"Sim" if int(u["is_active"])==1 else "Não"}</td>
          <td>{"Sim" if int(u["is_admin"])==1 else "Não"}</td>
          <td class="row">
            <form method="post" action="/admin/users/toggle" style="display:inline">
              <input type="hidden" name="user_id" value="{u['id']}">
              <input type="hidden" name="field" value="is_active">
              <button class="btn small secondary">Toggle Ativo</button>
            </form>
            <form method="post" action="/admin/users/toggle" style="display:inline; margin-left:6px">
              <input type="hidden" name="user_id" value="{u['id']}">
              <input type="hidden" name="field" value="is_admin">
              <button class="btn small secondary">Toggle Admin</button>
            </form>
          </td>
        </tr>"""
        for u in users
    ])

    html = f"""
    <!doctype html><html lang="pt-br"><head><meta charset="utf-8"><title>Admin • Usuários</title>
    <link rel="stylesheet" href="/static/style.css"></head><body><div class="wrap"><header><div class="brand">
    <img src="/static/logo-asper.png" alt="ASPER"><div class="title"><h1>Administração</h1><div class="sub">Gerenciar usuários</div></div></div>
    <div class="row"><a class="btn secondary" href="/">Voltar</a><a class="btn secondary" href="/logout">Sair</a></div></header>
    <section class="card"><h3>Cadastrar novo usuário</h3>
    <form method="post" action="/admin/users/create" class="row">
      <input type="text" name="username" placeholder="username" required>
      <input type="password" name="password" placeholder="senha" required>
      <label class="small" style="display:flex;align-items:center;gap:6px"><input type="checkbox" name="is_admin"> Admin</label>
      <button class="btn">Criar</button>
    </form></section>
    <section class="card" style="margin-top:14px"><h3>Usuários</h3>
    <table><thead><tr><th>Usuário</th><th>Ativo</th><th>Admin</th><th>Ações</th></tr></thead><tbody>{body_rows}</tbody></table>
    </section></div></body></html>
    """
    return HTMLResponse(content=html)

@app.post("/admin/users/create")
def admin_create_user(request: Request, username: str = Form(...), password: str = Form(...), is_admin_flag: str = Form(None), user: str = Depends(verify_user_required_page)):
    if not is_admin(user):
        return RedirectResponse(url="/admin/users", status_code=302)
    is_admin_val = 1 if (is_admin_flag in ("on", "true", "1", "yes")) else 0
    con = _con()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_active, is_admin) VALUES (?,?,1,?)",
            (username, __import__("hashlib").sha256(password.encode()).hexdigest(), is_admin_val)
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
        return RedirectResponse(url="/admin/users", status_code=302)
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


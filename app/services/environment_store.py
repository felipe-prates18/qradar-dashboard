import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlite3 import Connection


def ensure_schema(con: Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS environments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            host TEXT,
            collector TEXT,
            ssh_user TEXT,
            ssh_key TEXT,
            jmx_port INTEGER,
            jmx_bean TEXT,
            appliances_json TEXT,
            connectivity_targets_json TEXT,
            codigo TEXT,
            siem TEXT,
            api_token TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_environments_name
        ON environments(name)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_environments_codigo
        ON environments(codigo)
        """
    )
    cur.execute("PRAGMA table_info(environments)")
    existing_columns = {row[1] for row in cur.fetchall()}
    if "api_token" not in existing_columns:
        cur.execute("ALTER TABLE environments ADD COLUMN api_token TEXT")
    con.commit()


def _loads_json(raw: Optional[str]) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
        if isinstance(value, list):
            return value
        return []
    except Exception:
        return []


def _dumps_json(value: Any) -> str:
    try:
        return json.dumps(value or [])
    except Exception:
        return "[]"


def _serialize_row(row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "host": row["host"],
        "collector": row["collector"],
        "ssh_user": row["ssh_user"],
        "ssh_key": row["ssh_key"],
        "jmx_port": row["jmx_port"],
        "jmx_bean": row["jmx_bean"],
        "appliances": _loads_json(row["appliances_json"]),
        "connectivity_targets": _loads_json(row["connectivity_targets_json"]),
        "codigo": row["codigo"],
        "siem": row["siem"],
        "api_token": row["api_token"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_environments(con: Connection) -> List[Dict[str, Any]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, host, collector, ssh_user, ssh_key, jmx_port, jmx_bean,
               appliances_json, connectivity_targets_json, codigo, siem,
               api_token, created_at, updated_at
        FROM environments
        ORDER BY name COLLATE NOCASE
        """
    )
    return [_serialize_row(row) for row in cur.fetchall()]


def get_environment(con: Connection, env_id: int) -> Optional[Dict[str, Any]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, host, collector, ssh_user, ssh_key, jmx_port, jmx_bean,
               appliances_json, connectivity_targets_json, codigo, siem,
               api_token, created_at, updated_at
        FROM environments
        WHERE id=?
        LIMIT 1
        """,
        (env_id,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return _serialize_row(row)


def get_environment_by_name(con: Connection, name: str) -> Optional[Dict[str, Any]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, host, collector, ssh_user, ssh_key, jmx_port, jmx_bean,
               appliances_json, connectivity_targets_json, codigo, siem,
               api_token, created_at, updated_at
        FROM environments
        WHERE name=?
        LIMIT 1
        """,
        (name,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return _serialize_row(row)


def save_environment(con: Connection, payload: Dict[str, Any], env_id: Optional[int] = None) -> int:
    ensure_schema(con)
    now = datetime.utcnow().isoformat()
    appliances_json = _dumps_json(payload.get("appliances"))
    connectivity_json = _dumps_json(payload.get("connectivity_targets"))
    jmx_port = payload.get("jmx_port")
    try:
        jmx_port_val = int(jmx_port) if jmx_port not in (None, "", False) else None
    except Exception:
        jmx_port_val = None

    fields = (
        payload.get("name"),
        payload.get("host"),
        payload.get("collector"),
        payload.get("ssh_user"),
        payload.get("ssh_key"),
        jmx_port_val,
        payload.get("jmx_bean"),
        appliances_json,
        connectivity_json,
        payload.get("codigo"),
        payload.get("siem"),
        payload.get("api_token"),
    )

    cur = con.cursor()
    if env_id:
        cur.execute(
            """
            UPDATE environments
            SET name=?, host=?, collector=?, ssh_user=?, ssh_key=?, jmx_port=?,
                jmx_bean=?, appliances_json=?, connectivity_targets_json=?,
                codigo=?, siem=?, api_token=?, updated_at=?
            WHERE id=?
            """,
            (*fields, now, env_id),
        )
        con.commit()
        return env_id

    cur.execute(
        """
        INSERT INTO environments (
            name, host, collector, ssh_user, ssh_key, jmx_port, jmx_bean,
            appliances_json, connectivity_targets_json, codigo, siem,
            api_token, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (*fields, now, now),
    )
    con.commit()
    return int(cur.lastrowid)


def delete_environment(con: Connection, env_id: int) -> None:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute("DELETE FROM environments WHERE id=?", (env_id,))
    con.commit()


def upsert_many(con: Connection, items: Iterable[Dict[str, Any]]) -> int:
    ensure_schema(con)
    inserted = 0
    for item in items:
        env_id = None
        name = item.get("name")
        if name:
            existing = get_environment_by_name(con, str(name))
            if existing:
                env_id = existing.get("id")
        save_environment(con, item, env_id=env_id)
        inserted += 1
    return inserted

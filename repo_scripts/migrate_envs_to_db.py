"""
Migra ambientes configurados no config.json para o banco SQLite (users.db).

Uso:
    python repo_scripts/migrate_envs_to_db.py
"""

import json
import sqlite3
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
APP_DIR = ROOT_DIR / "app"
CONFIG_PATH = APP_DIR / "config.json"
DB_PATH = ROOT_DIR / "users.db"

sys.path.append(str(ROOT_DIR))

from app.services import environment_store  # noqa: E402


def main() -> None:
    if not CONFIG_PATH.exists():
        raise SystemExit(f"Config não encontrado em {CONFIG_PATH}")

    with CONFIG_PATH.open("r", encoding="utf-8") as fp:
        config = json.load(fp)
    envs = config.get("qradar_envs") or []
    tokens_map = {
        str(key): str(value)
        for key, value in (config.get("qradar_api", {}).get("tokens") or {}).items()
        if key and value
    }

    enriched_envs = []
    migrated_tokens = 0
    for env in envs:
        item = dict(env)
        code = item.get("codigo") or item.get("code")
        if code and not item.get("api_token"):
            token = tokens_map.get(str(code))
            if token:
                item["api_token"] = token
                migrated_tokens += 1
        enriched_envs.append(item)

    con = sqlite3.connect(str(DB_PATH))
    try:
        con.row_factory = sqlite3.Row
        environment_store.ensure_schema(con)
        inserted = environment_store.upsert_many(con, enriched_envs)
    finally:
        con.close()

    print(f"{inserted} ambientes migrados para {DB_PATH}")
    if migrated_tokens:
        print(f"{migrated_tokens} tokens associados aos ambientes")


if __name__ == "__main__":
    main()

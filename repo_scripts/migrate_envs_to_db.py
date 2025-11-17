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

    con = sqlite3.connect(str(DB_PATH))
    try:
        con.row_factory = sqlite3.Row
        inserted = environment_store.upsert_many(con, envs)
    finally:
        con.close()

    print(f"{inserted} ambientes migrados para {DB_PATH}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import sqlite3
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR.parent / "users.db"


def open_connection() -> sqlite3.Connection:
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    return con


def ensure_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ingestion_daily (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            environment_id INTEGER NOT NULL,
            siem TEXT,
            sample_date TEXT NOT NULL,
            value REAL NOT NULL,
            unit TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ingestion_daily_unique
        ON ingestion_daily(environment_id, sample_date, unit)
        """
    )
    con.commit()


def record_daily_ingestion(
    env_id: Optional[int],
    siem: Optional[str],
    value: Optional[float],
    unit: str,
    *,
    sample_date: Optional[date] = None,
) -> bool:
    if env_id is None or value is None:
        return False

    day = sample_date or datetime.utcnow().date()
    created_at = datetime.utcnow().isoformat()

    con = open_connection()
    try:
        ensure_schema(con)
        cur = con.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO ingestion_daily (
                environment_id, siem, sample_date, value, unit, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                env_id,
                siem,
                day.isoformat(),
                float(value),
                unit,
                created_at,
            ),
        )
        con.commit()
        return cur.rowcount > 0
    finally:
        con.close()


def fetch_ingestion_samples(
    env_id: Optional[int],
    start_date: date,
    end_date: date,
    unit: str,
) -> List[Dict[str, Any]]:
    if env_id is None:
        return []

    con = open_connection()
    try:
        ensure_schema(con)
        cur = con.cursor()
        cur.execute(
            """
            SELECT sample_date, value
            FROM ingestion_daily
            WHERE environment_id=? AND unit=? AND sample_date BETWEEN ? AND ?
            ORDER BY sample_date ASC
            """,
            (env_id, unit, start_date.isoformat(), end_date.isoformat()),
        )
        rows = cur.fetchall()
        samples: List[Dict[str, Any]] = []
        for row in rows:
            raw_date = row["sample_date"]
            parsed_date: Optional[date]
            try:
                parsed_date = date.fromisoformat(raw_date)
            except Exception:
                parsed_date = None
            if not parsed_date:
                continue
            samples.append({"sample_date": parsed_date, "value": float(row["value"])})
        return samples
    finally:
        con.close()


def fetch_daily_ingestion(
    env_id: Optional[int],
    sample_date: date,
    unit: str,
) -> Optional[Dict[str, Any]]:
    if env_id is None:
        return None

    con = open_connection()
    try:
        ensure_schema(con)
        cur = con.cursor()
        cur.execute(
            """
            SELECT sample_date, value, created_at
            FROM ingestion_daily
            WHERE environment_id=? AND unit=? AND sample_date=?
            LIMIT 1
            """,
            (env_id, unit, sample_date.isoformat()),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "sample_date": row["sample_date"],
            "value": float(row["value"]),
            "created_at": row["created_at"],
        }
    finally:
        con.close()


def fetch_latest_ingestion(env_id: Optional[int], unit: str) -> Optional[Dict[str, Any]]:
    if env_id is None:
        return None

    con = open_connection()
    try:
        ensure_schema(con)
        cur = con.cursor()
        cur.execute(
            """
            SELECT sample_date, value, created_at
            FROM ingestion_daily
            WHERE environment_id=? AND unit=?
            ORDER BY sample_date DESC, created_at DESC
            LIMIT 1
            """,
            (env_id, unit),
        )
        row = cur.fetchone()
        if not row:
            return None
        return {
            "sample_date": row["sample_date"],
            "value": float(row["value"]),
            "created_at": row["created_at"],
        }
    finally:
        con.close()

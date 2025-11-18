from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Dict, Optional


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _normalise_month_key(value: str) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if len(text) != 7 or text[4] != "-":
        return None
    year_part, month_part = text.split("-", 1)
    if not (year_part.isdigit() and month_part.isdigit()):
        return None
    year = int(year_part)
    month = int(month_part)
    if year < 0 or not (1 <= month <= 12):
        return None
    return f"{year:04d}-{month:02d}"


def ensure_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS use_case_monthly_totals (
            environment TEXT NOT NULL,
            month TEXT NOT NULL,
            total INTEGER NOT NULL,
            collected_at TEXT NOT NULL,
            PRIMARY KEY (environment, month)
        )
        """
    )
    con.commit()


def should_record_monthly_snapshot(moment: Optional[datetime] = None) -> bool:
    instant = moment or datetime.utcnow()
    return instant.day == 1


def month_snapshot_exists(con: sqlite3.Connection, month_key: str) -> bool:
    """Return ``True`` if there is at least one snapshot for ``month_key``."""

    ensure_schema(con)
    normalized = _normalise_month_key(month_key)
    if not normalized:
        return False
    cur = con.cursor()
    cur.execute(
        "SELECT 1 FROM use_case_monthly_totals WHERE month = ? LIMIT 1",
        (normalized,),
    )
    return cur.fetchone() is not None


def record_monthly_totals(
    con: sqlite3.Connection,
    month_key: str,
    totals_by_environment: Dict[str, int],
    *,
    collected_at: Optional[datetime] = None,
) -> int:
    ensure_schema(con)
    normalized_month = _normalise_month_key(month_key)
    if not normalized_month:
        raise ValueError("Formato de mês inválido para armazenar totais mensais")
    if not totals_by_environment:
        return 0
    if collected_at is None:
        timestamp = _utc_now_iso()
    else:
        trimmed = collected_at.replace(microsecond=0).isoformat()
        if collected_at.tzinfo is None:
            timestamp = trimmed + "Z"
        else:
            timestamp = trimmed.replace("+00:00", "Z")
    cur = con.cursor()
    affected = 0
    for raw_env, total_value in totals_by_environment.items():
        environment = (raw_env or "").strip()
        if not environment:
            continue
        try:
            total_int = int(total_value)
        except Exception:
            continue
        cur.execute(
            """
            INSERT INTO use_case_monthly_totals (environment, month, total, collected_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(environment, month)
            DO UPDATE SET total = excluded.total, collected_at = excluded.collected_at
            """,
            (environment, normalized_month, total_int, timestamp),
        )
        affected += cur.rowcount
    con.commit()
    return affected


def list_monthly_totals(con: sqlite3.Connection) -> Dict[str, Dict[str, int]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT environment, month, total
        FROM use_case_monthly_totals
        ORDER BY LOWER(environment), month
        """
    )
    results: Dict[str, Dict[str, int]] = {}
    for row in cur.fetchall():
        environment = (row["environment"] or "").strip()
        month_key = _normalise_month_key(row["month"] or "")
        if not environment or not month_key:
            continue
        try:
            total_value = int(row["total"])
        except Exception:
            continue
        env_map = results.setdefault(environment, {})
        env_map[month_key] = total_value
    return results

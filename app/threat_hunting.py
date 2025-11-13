"""Utilities for managing Threat Hunting use cases."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Sequence

REQUIRED_FIELDS = ("name", "description", "technology", "siem", "environment")
_VALID_DISTINCT_COLUMNS = {"technology", "siem", "environment"}


def _utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse stored timestamp values into ``datetime`` objects."""

    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue
    return None


def ensure_schema(con: sqlite3.Connection) -> None:
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS use_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            logic TEXT,
            technology TEXT NOT NULL,
            siem TEXT NOT NULL,
            environment TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS use_case_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            use_case_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_by TEXT,
            created_at TEXT,
            FOREIGN KEY (use_case_id) REFERENCES use_cases(id) ON DELETE CASCADE
        )
        """
    )
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
    cur.execute("PRAGMA table_info(use_cases)")
    columns = {row[1] for row in cur.fetchall()}
    altered = False
    for column, definition in (
        ("logic", "TEXT"),
        ("created_by", "TEXT"),
        ("created_at", "TEXT"),
        ("updated_at", "TEXT"),
    ):
        if column not in columns:
            cur.execute(f"ALTER TABLE use_cases ADD COLUMN {column} {definition}")
            altered = True
    con.commit()


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


def should_record_monthly_snapshot(moment: Optional[datetime] = None) -> bool:
    instant = moment or datetime.utcnow()
    return instant.day == 1


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


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Optional[str]]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "logic": row["logic"],
        "technology": row["technology"],
        "siem": row["siem"],
        "environment": row["environment"],
        "is_active": bool(row["is_active"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _comment_row_to_dict(row: sqlite3.Row) -> Dict[str, Optional[str]]:
    return {
        "id": row["id"],
        "use_case_id": row["use_case_id"],
        "comment": row["comment"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def list_use_cases(
    con: sqlite3.Connection,
    *,
    search: Optional[str] = None,
    technology: Optional[str] = None,
    siem: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Optional[str]]]:
    ensure_schema(con)
    clauses: List[str] = []
    params: List[str] = []
    if search:
        clauses.append("LOWER(name) LIKE ?")
        params.append(f"%{search.lower()}%")
    if technology:
        clauses.append("LOWER(technology) = ?")
        params.append(technology.lower())
    if siem:
        clauses.append("LOWER(siem) = ?")
        params.append(siem.lower())
    if status == "active":
        clauses.append("is_active = 1")
    elif status == "inactive":
        clauses.append("is_active = 0")

    query = "SELECT id, name, description, logic, technology, siem, environment, is_active, created_by, created_at, updated_at FROM use_cases"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY LOWER(name)"

    cur = con.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    return [_row_to_dict(row) for row in rows]


def get_use_case(con: sqlite3.Connection, use_case_id: int) -> Optional[Dict[str, Optional[str]]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, description, logic, technology, siem, environment, is_active, created_by, created_at, updated_at
        FROM use_cases
        WHERE id=?
        LIMIT 1
        """,
        (use_case_id,),
    )
    row = cur.fetchone()
    return _row_to_dict(row) if row else None


def list_comments(con: sqlite3.Connection, use_case_id: int) -> List[Dict[str, Optional[str]]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, use_case_id, comment, created_by, created_at
        FROM use_case_comments
        WHERE use_case_id = ?
        ORDER BY datetime(created_at) ASC, id ASC
        """,
        (use_case_id,),
    )
    return [_comment_row_to_dict(row) for row in cur.fetchall()]


def add_comment(
    con: sqlite3.Connection,
    use_case_id: int,
    comment: str,
    created_by: Optional[str],
) -> int:
    ensure_schema(con)
    text = (comment or "").strip()
    if not text:
        raise ValueError("O comentário não pode estar vazio.")
    cur = con.cursor()
    cur.execute("SELECT 1 FROM use_cases WHERE id = ?", (use_case_id,))
    if not cur.fetchone():
        raise ValueError("Caso de uso não encontrado para comentar.")
    timestamp = _utc_now_iso()
    cur.execute(
        """
        INSERT INTO use_case_comments (use_case_id, comment, created_by, created_at)
        VALUES (?,?,?,?)
        """,
        (use_case_id, text, created_by, timestamp),
    )
    con.commit()
    return int(cur.lastrowid)


def _sanitize_payload(payload: Dict[str, str]) -> Dict[str, str]:
    sanitized = {key: (value.strip() if value is not None else "") for key, value in payload.items()}
    missing = [field for field in REQUIRED_FIELDS if not sanitized.get(field)]
    if missing:
        raise ValueError(
            "Campos obrigatórios ausentes: " + ", ".join(sorted(missing))
        )
    sanitized.setdefault("logic", sanitized.get("logic", ""))
    return sanitized


def create_use_case(
    con: sqlite3.Connection,
    payload: Dict[str, str],
) -> int:
    ensure_schema(con)
    data = _sanitize_payload(payload)
    timestamp = _utc_now_iso()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO use_cases (
            name,
            description,
            logic,
            technology,
            siem,
            environment,
            is_active,
            created_by,
            created_at,
            updated_at
        )
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            data["name"],
            data["description"],
            data.get("logic"),
            data["technology"],
            data["siem"],
            data["environment"],
            int(data.get("is_active", "1") in ("1", "true", "on", 1, True)),
            data.get("created_by"),
            timestamp,
            timestamp,
        ),
    )
    con.commit()
    return int(cur.lastrowid)


def update_use_case(
    con: sqlite3.Connection,
    use_case_id: int,
    payload: Dict[str, str],
) -> bool:
    ensure_schema(con)
    existing = get_use_case(con, use_case_id)
    if not existing:
        return False
    data = _sanitize_payload(payload)
    timestamp = _utc_now_iso()
    cur = con.cursor()
    cur.execute(
        """
        UPDATE use_cases
        SET name=?, description=?, logic=?, technology=?, siem=?, environment=?, is_active=?, updated_at=?, created_by=COALESCE(created_by, ?)
        WHERE id=?
        """,
        (
            data["name"],
            data["description"],
            data.get("logic"),
            data["technology"],
            data["siem"],
            data["environment"],
            int(data.get("is_active", existing["is_active"]) in ("1", "true", "on", 1, True)),
            timestamp,
            data.get("created_by"),
            use_case_id,
        ),
    )
    con.commit()
    return True


def count_active_by_environment(con: sqlite3.Connection) -> List[Dict[str, int]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT environment, COUNT(*) as total
        FROM use_cases
        WHERE is_active = 1
        GROUP BY environment
        ORDER BY LOWER(environment)
        """
    )
    rows = cur.fetchall()
    return [
        {"environment": row["environment"], "total": int(row["total"]) if row["total"] is not None else 0}
        for row in rows
    ]


def count_total_by_environment(con: sqlite3.Connection) -> List[Dict[str, int]]:
    """Count total use cases (any status) grouped by environment."""

    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT environment, COUNT(*) as total
        FROM use_cases
        GROUP BY environment
        ORDER BY LOWER(environment)
        """
    )
    rows = cur.fetchall()
    return [
        {"environment": row["environment"], "total": int(row["total"]) if row["total"] is not None else 0}
        for row in rows
    ]


def count_creations_by_month(con: sqlite3.Connection) -> Dict[str, Dict[str, int]]:
    """Return the number of created use cases per month for each environment."""

    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT environment, created_at
        FROM use_cases
        WHERE created_at IS NOT NULL AND TRIM(created_at) <> ''
        """
    )
    rows = cur.fetchall()
    counts: Dict[str, Dict[str, int]] = {}
    for row in rows:
        environment = row["environment"] or ""
        timestamp = parse_timestamp(row["created_at"])
        if not timestamp:
            continue
        month_key = f"{timestamp.year:04d}-{timestamp.month:02d}"
        env_counts = counts.setdefault(environment, {})
        env_counts[month_key] = env_counts.get(month_key, 0) + 1
    return counts


def delete_use_case(con: sqlite3.Connection, use_case_id: int) -> bool:
    """Remove um Use Case pelo identificador."""

    ensure_schema(con)
    cur = con.cursor()
    cur.execute("DELETE FROM use_case_comments WHERE use_case_id = ?", (use_case_id,))
    cur.execute("DELETE FROM use_cases WHERE id=?", (use_case_id,))
    con.commit()
    return cur.rowcount > 0


def distinct_values(con: sqlite3.Connection, column: str) -> Sequence[str]:
    if column not in _VALID_DISTINCT_COLUMNS:
        raise ValueError("Coluna inválida para consulta distinta")
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        f"SELECT DISTINCT {column} as value FROM use_cases WHERE {column} IS NOT NULL AND TRIM({column}) <> '' ORDER BY LOWER({column})"
    )
    return [row["value"] for row in cur.fetchall()]


def list_active_use_cases(con: sqlite3.Connection) -> List[Dict[str, Optional[str]]]:
    ensure_schema(con)
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, description, logic, technology, siem, environment, is_active, created_by, created_at, updated_at
        FROM use_cases
        WHERE is_active = 1
        ORDER BY LOWER(name)
        """
    )
    return [_row_to_dict(row) for row in cur.fetchall()]

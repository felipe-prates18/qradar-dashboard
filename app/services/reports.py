"""Helpers to build period reports per environment and SIEM."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
import time as time_module
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .crowdstrike_client import CrowdstrikeApiError, CrowdstrikeAuthError, CrowdstrikeClient
from . import ingestion_store

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_NGSIEM_REPOSITORY = "search-all"
DEFAULT_NGSIEM_QUERY = r"""#repo=xdr_indicatorsrepo
| Ngsiem.event.type="ngsiem-rule-trigger-event"
| stats(function=count(rule.name))
"""
DEFAULT_NGSIEM_SEVERITY_QUERY = r"""#repo=xdr_indicatorsrepo
| Ngsiem.event.type="ngsiem-rule-trigger-event"
| groupBy(Vendor.SeverityName)
"""
DEFAULT_NGSIEM_EVENTS_QUERY = "count()"


@dataclass
class ReportResult:
    type: str
    label: str
    count: Optional[int]
    status: str
    message: str
    details: Sequence[str]
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "label": self.label,
            "count": self.count,
            "status": self.status,
            "message": self.message,
            "details": list(self.details or []),
            "extra": dict(self.extra or {}),
        }


@dataclass
class EnvironmentReport:
    environment: Dict[str, Any]
    siem: str
    start: datetime
    end: datetime
    results: Sequence[ReportResult]

    def to_dict(self) -> Dict[str, Any]:
        total = sum(result.count or 0 for result in self.results)
        worst_status = _resolve_overall_status(self.results)
        return {
            "environment": {
                "id": self.environment.get("id"),
                "name": self.environment.get("name"),
                "code": self.environment.get("codigo") or self.environment.get("code"),
                "siem": self.siem,
            },
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "total": total,
            "status": worst_status,
            "results": [result.to_dict() for result in self.results],
        }


def _build_session() -> requests.Session:
    retry = Retry(
        total=DEFAULT_MAX_RETRIES,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _resolve_overall_status(results: Sequence[ReportResult]) -> str:
    rank = {"error": 3, "warning": 2, "ok": 1}
    worst = "ok"
    for result in results:
        value = rank.get(result.status, 1)
        if value > rank.get(worst, 1):
            worst = result.status
    return worst


def _normalize_connector_status(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "other"
    if text in {"ok", "active", "enabled", "running", "on"}:
        return "active"
    if text in {"error", "failed", "failure", "critical"}:
        return "error"
    if text in {"paused", "suspended", "stopped"}:
        return "paused"
    if text in {"pending", "new", "waiting", "queued"}:
        return "pending"
    return text


def _normalize_timestamp_value(value: Any) -> Tuple[Optional[datetime], Optional[str]]:
    if value is None:
        return None, None

    if isinstance(value, (int, float)):
        try:
            ts = float(value)
            if ts > 10**12:
                ts = ts / 1000.0
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt, dt.isoformat()
        except Exception:
            return None, str(value)

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None
        try:
            normalized = text.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt, dt.isoformat()
        except Exception:
            try:
                ts = float(text)
                if ts > 10**12:
                    ts = ts / 1000.0
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                return dt, dt.isoformat()
            except Exception:
                return None, text

    return None, None


def _summarize_ingestion_average(
    env: Dict[str, Any],
    start: datetime,
    end: datetime,
    unit: str,
    logger: logging.Logger,
) -> Dict[str, Any]:
    env_id = env.get("id")
    if env_id is None:
        return {
            "average": None,
            "unit": unit,
            "status": "warning",
            "message": "Não foi possível calcular a média de ingestão (ambiente sem ID).",
        }

    try:
        samples = ingestion_store.fetch_ingestion_samples(
            env_id,
            start.date(),
            end.date(),
            unit,
        )
    except Exception:
        logger.exception("Erro ao consultar ingestão armazenada ambiente=%s", env.get("name"))
        return {
            "average": None,
            "unit": unit,
            "status": "warning",
            "message": "Falha ao consultar a ingestão armazenada para o período.",
        }

    if not samples:
        return {
            "average": None,
            "unit": unit,
            "status": "warning",
            "message": "Não há dados de ingestão armazenados para o período selecionado.",
        }

    values = [item["value"] for item in samples if item.get("value") is not None]
    if not values:
        return {
            "average": None,
            "unit": unit,
            "status": "warning",
            "message": "Não há dados de ingestão válidos para o período selecionado.",
        }

    average = sum(values) / len(values)
    expected_days = (end.date() - start.date()).days + 1
    status = "ok"
    message = ""

    if len(values) < expected_days:
        start_label = samples[0]["sample_date"].strftime("%d/%m/%Y")
        end_label = samples[-1]["sample_date"].strftime("%d/%m/%Y")
        message = (
            "Dados insuficientes para o período selecionado. "
            f"Média calculada de {start_label} a {end_label}."
        )
        status = "warning"

    return {
        "average": average,
        "unit": unit,
        "status": status,
        "message": message,
    }


def _crowdstrike_connectors_summary(
    env: Dict[str, Any],
    start: datetime,
    end: datetime,
    logger: logging.Logger,
) -> List[ReportResult]:
    base_url = env.get("base_url") or env.get("api_base_url")
    client_id = env.get("client_id")
    client_secret = env.get("client_secret")
    results: List[ReportResult] = []

    try:
        client = CrowdstrikeClient(
            base_url=base_url or "",
            client_id=client_id or "",
            client_secret=client_secret or "",
            logger=logger,
        )
    except ValueError as exc:
        return [
            ReportResult(
                type="connectors",
                label="Conectores",
                count=None,
                status="error",
                message=str(exc),
                details=[],
            )
        ]

    try:
        logger.info("Solicitando token OAuth2 Crowdstrike ambiente=%s para conectores", env.get("name"))
        bearer = client.fetch_token()
        logger.info("Token OAuth2 obtido ambiente=%s", env.get("name"))
        logger.info("Listando conexões NG-SIEM ambiente=%s", env.get("name"))
        connections_payload = client.list_all_connections(bearer)
        connectors = client.map_connectors(connections_payload.get("resources", []))
        ingestion_summary = client.summarize_ingestion(connections_payload)
    except (CrowdstrikeApiError, requests.RequestException) as exc:
        logger.exception("Erro ao consultar conectores do Crowdstrike ambiente=%s", env.get("name"))
        return [
            ReportResult(
                type="connectors",
                label="Conectores",
                count=None,
                status="error",
                message=f"Falha ao consultar conectores: {exc}",
                details=[],
            )
        ]

    connectors_count = len(connectors)
    status_counter: Dict[str, int] = {}
    details: List[str] = []
    connector_entries: List[Dict[str, Any]] = []
    latest_last_ingested: Optional[datetime] = None
    for item in connectors:
        status_raw = item.get("status") or "unknown"
        status_norm = _normalize_connector_status(status_raw)
        status_counter[status_norm] = status_counter.get(status_norm, 0) + 1
        name = item.get("name") or item.get("id") or "Conector"
        vendor = item.get("vendor") or item.get("product")
        last_ingested_dt, last_ingested_str = _normalize_timestamp_value(item.get("last_ingested_at"))
        if last_ingested_dt and (latest_last_ingested is None or last_ingested_dt > latest_last_ingested):
            latest_last_ingested = last_ingested_dt
        connector_entries.append(
            {
                "id": item.get("id"),
                "name": name,
                "vendor": vendor,
                "product": item.get("product"),
                "type": item.get("type"),
                "status": status_norm,
                "status_raw": status_raw,
                "last_ingested_at": last_ingested_str,
                "last_ingested_volume_one_day": item.get("last_ingested_volume_one_day"),
                "last_ingested_volume_bytes": item.get("last_ingested_volume_bytes"),
            }
        )
        detail_parts = [f"{name} ({vendor or '—'}) – Status: {status_raw}"]
        if last_ingested_str:
            detail_parts.append(f"Última ingestão: {last_ingested_str}")
        details.append(" | ".join(detail_parts))

    ingestion_gb = ingestion_summary.get("total_gb_one_day_decimal")
    ingestion_avg = _summarize_ingestion_average(env, start, end, "GB", logger)
    ingestion_msg = (
        f"Ingestão 24h: {ingestion_avg['average']:.2f} GB"
        if ingestion_avg.get("average") is not None
        else "Ingestão 24h: —"
    )
    latest_ingested_str = latest_last_ingested.isoformat() if latest_last_ingested else None

    status_labels = {
        "active": "Ativos",
        "error": "Com erro",
        "paused": "Pausados",
        "pending": "Pendentes",
    }
    breakdown_readable = "; ".join(
        f"{status_labels.get(status, status.title())}: {count}"
        for status, count in status_counter.items()
    )
    status_sentence = breakdown_readable if breakdown_readable else "Nenhum conector retornado."
    latest_ingestion_sentence = f"Última ingestão: {latest_last_ingested.strftime('%d/%m/%Y %H:%M UTC')}" if latest_last_ingested else "Última ingestão não informada."

    warning_messages: List[str] = []
    if connectors_count == 0:
        warning_messages.append("Nenhum conector retornado pela API.")
    if ingestion_avg.get("status") == "warning" and ingestion_avg.get("message"):
        warning_messages.append(ingestion_avg["message"])

    status = "warning" if warning_messages else "ok"
    message = (
        " ".join(warning_messages)
        if warning_messages
        else f"{connectors_count} conector(es). {status_sentence}. {latest_ingestion_sentence} {ingestion_msg}"
    )

    results.append(
        ReportResult(
            type="connectors",
            label="Conectores",
            count=connectors_count,
            status=status,
            message=message,
            details=details,
            extra={
                "status_breakdown": status_counter,
                "connectors": connector_entries,
                "latest_last_ingested_at": latest_ingested_str,
                "ingestion_gb_one_day": ingestion_gb,
                "ingestion_value": ingestion_avg.get("average"),
                "ingestion_unit": ingestion_avg.get("unit"),
            },
        )
    )
    return results


def _to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "sim", "habilitado"}:
            return True
        if lowered in {"0", "false", "no", "off", "nao", "não", "desabilitado"}:
            return False
    return default


def _parse_timeout(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _normalize_dt(value: Any, *, end_of_day: bool = False) -> datetime:
    if isinstance(value, datetime):
        dt_obj = value
    elif isinstance(value, date):
        dt_obj = datetime.combine(value, time.max if end_of_day else time.min)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Data vazia.")
        try:
            dt_obj = datetime.fromisoformat(text)
        except Exception as exc:
            # Try parsing date-only values like YYYY-MM-DD.
            try:
                parsed_date = datetime.strptime(text, "%Y-%m-%d").date()
                dt_obj = datetime.combine(parsed_date, time.max if end_of_day else time.min)
            except Exception:
                raise ValueError(f"Data inválida: {text}") from exc
    else:
        raise ValueError("Data inválida.")

    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)

    if end_of_day:
        return dt_obj.replace(hour=23, minute=59, second=59, microsecond=999999)
    return dt_obj


def parse_date_range(start: Any, end: Any) -> Tuple[datetime, datetime]:
    start_dt = _normalize_dt(start, end_of_day=False)
    end_dt = _normalize_dt(end, end_of_day=True)
    if start_dt > end_dt:
        raise ValueError("Data inicial não pode ser maior que a data final.")
    return start_dt, end_dt


def _parse_total_from_content_range(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        suffix = value.rsplit("/", 1)[-1].strip()
        if suffix == "*":
            return None
        return int(suffix)
    except Exception:
        return None


def _resolve_qradar_token(env: Dict[str, Any], api_conf: Dict[str, Any]) -> Optional[str]:
    if env.get("api_token"):
        return str(env.get("api_token"))
    lookup_keys = (
        env.get("codigo"),
        env.get("code"),
        env.get("name"),
        env.get("host"),
    )
    tokens_map = api_conf.get("tokens") or {}
    for key in lookup_keys:
        if key is None:
            continue
        token = tokens_map.get(str(key))
        if token:
            return str(token)
    return None


def _build_qradar_base_url(env: Dict[str, Any], api_conf: Dict[str, Any]) -> Optional[str]:
    base_url = env.get("api_base_url") or env.get("base_url")
    host = env.get("host")
    if base_url:
        return str(base_url).rstrip("/")

    template = api_conf.get("base_url")
    if template:
        try:
            candidate = str(template).format(host=host or "")
        except Exception:
            candidate = str(template)
        if candidate:
            return candidate.rstrip("/")

    if host:
        return f"https://{host}/api"
    return None


def _format_period_label(start: datetime, end: datetime) -> str:
    return f"Período: {start.strftime('%d/%m/%Y')} - {end.strftime('%d/%m/%Y')}"


def _qradar_offense_report(
    env: Dict[str, Any], start: datetime, end: datetime, api_conf: Dict[str, Any], logger: logging.Logger
) -> ReportResult:
    token = _resolve_qradar_token(env, api_conf)
    if not token:
        return ReportResult(
            type="offenses",
            label="Ofensas",
            count=None,
            status="error",
            message="Token da API do QRadar não configurado.",
            details=[],
        )

    base_url = _build_qradar_base_url(env, api_conf)
    if not base_url:
        return ReportResult(
            type="offenses",
            label="Ofensas",
            count=None,
            status="error",
            message="Host/Base URL do QRadar não configurado.",
            details=[],
        )

    verify_tls = _to_bool(env.get("api_verify_tls"), _to_bool(api_conf.get("verify_tls"), False))
    timeout = _parse_timeout(env.get("api_timeout"), api_conf.get("timeout", DEFAULT_TIMEOUT))
    version = env.get("api_version") or api_conf.get("version")

    start_ms = int(start.timestamp() * 1000)
    end_ms = int(end.timestamp() * 1000)
    params = {
        "filter": f"start_time>={start_ms} and start_time<={end_ms}",
        "fields": "id,start_time,last_updated_time,status,severity",
    }
    headers = {
        "SEC": token,
        "Accept": "application/json",
        "Range": "items=0-0",
    }
    if version:
        headers["Version"] = str(version)

    url = f"{base_url}/siem/offenses"
    try:
        logger.info("Consultando ofensas do QRadar ambiente=%s", env.get("name") or env.get("host"))
        response = requests.get(url, headers=headers, params=params, timeout=timeout, verify=verify_tls)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.exception("Erro ao consultar ofensas do QRadar ambiente=%s", env.get("name"))
        return ReportResult(
            type="offenses",
            label="Ofensas",
            count=None,
            status="error",
            message=f"Falha ao consultar ofensas: {exc}",
            details=[_format_period_label(start, end)],
        )

    total = _parse_total_from_content_range(response.headers.get("Content-Range"))
    if total is None:
        total = len(payload) if isinstance(payload, list) else 0

    if total > 0:
        status = "ok"
        message = f"{total} ofensa(s) no período informado."
    else:
        status = "warning"
        message = "Nenhuma ofensa encontrada no período selecionado."

    return ReportResult(
        type="offenses",
        label="Ofensas",
        count=total,
        status=status,
        message=message,
        details=[_format_period_label(start, end)],
    )


def _qradar_log_sources_summary(
    env: Dict[str, Any], start: datetime, end: datetime, api_conf: Dict[str, Any], logger: logging.Logger
) -> ReportResult:
    token = _resolve_qradar_token(env, api_conf)
    if not token:
        return ReportResult(
            type="connectors",
            label="Log sources",
            count=None,
            status="error",
            message="Token da API do QRadar não configurado.",
            details=[],
        )

    base_url = _build_qradar_base_url(env, api_conf)
    if not base_url:
        return ReportResult(
            type="connectors",
            label="Log sources",
            count=None,
            status="error",
            message="Host/Base URL do QRadar não configurado.",
            details=[],
        )

    verify_tls = _to_bool(env.get("api_verify_tls"), _to_bool(api_conf.get("verify_tls"), False))
    timeout = _parse_timeout(env.get("api_timeout"), api_conf.get("timeout", DEFAULT_TIMEOUT))
    version = env.get("api_version") or api_conf.get("version")

    headers = {
        "SEC": token,
        "Accept": "application/json",
    }
    if version:
        headers["Version"] = str(version)

    url = f"{base_url}/config/event_sources/log_source_management/log_sources"
    try:
        logger.info("Consultando log sources do QRadar ambiente=%s", env.get("name") or env.get("host"))
        response = requests.get(url, headers=headers, timeout=timeout, verify=verify_tls)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.exception("Erro ao consultar log sources do QRadar ambiente=%s", env.get("name"))
        return ReportResult(
            type="connectors",
            label="Log sources",
            count=None,
            status="error",
            message=f"Falha ao consultar log sources: {exc}",
            details=[],
        )

    log_sources = payload if isinstance(payload, list) else []
    connectors_count = len(log_sources)
    status_counter: Dict[str, int] = {}
    connector_entries: List[Dict[str, Any]] = []
    details: List[str] = []
    latest_last_ingested: Optional[datetime] = None

    for item in log_sources:
        name = item.get("name") or item.get("description") or f"Log source {item.get('id')}"
        description = item.get("description")
        status_obj = item.get("status") or {}
        status_raw = status_obj.get("status") or ("enabled" if item.get("enabled") else "disabled")
        status_norm = _normalize_connector_status(status_raw)
        status_counter[status_norm] = status_counter.get(status_norm, 0) + 1

        last_ingested_dt, last_ingested_str = _normalize_timestamp_value(item.get("last_event_time"))
        if last_ingested_dt and (latest_last_ingested is None or last_ingested_dt > latest_last_ingested):
            latest_last_ingested = last_ingested_dt

        average_eps = item.get("average_eps")
        avg_eps_value = None
        try:
            if average_eps is not None:
                avg_eps_value = float(average_eps)
        except Exception:
            avg_eps_value = None
        if avg_eps_value == 0:
            avg_eps_value = None

        connector_entries.append(
            {
                "id": item.get("id"),
                "name": name,
                "vendor": description,
                "product": item.get("type_id"),
                "status": status_norm,
                "status_raw": status_raw,
                "last_ingested_at": last_ingested_str,
                "last_ingested_volume_one_day": f"{avg_eps_value:.0f} EPS" if avg_eps_value is not None else None,
            }
        )

        detail_parts = [f"{name} ({description or '—'}) – Status: {status_raw}"]
        if last_ingested_str:
            detail_parts.append(f"Última ingestão: {last_ingested_str}")
        details.append(" | ".join(detail_parts))

    ingestion_avg = _summarize_ingestion_average(env, start, end, "EPS", logger)
    latest_ingested_str = latest_last_ingested.isoformat() if latest_last_ingested else None

    warning_messages: List[str] = []
    if connectors_count == 0:
        warning_messages.append("Nenhum log source retornado pela API.")
    if ingestion_avg.get("status") == "warning" and ingestion_avg.get("message"):
        warning_messages.append(ingestion_avg["message"])

    status = "warning" if warning_messages else "ok"
    message = " ".join(warning_messages) if warning_messages else f"{connectors_count} log source(s) ativos."

    return ReportResult(
        type="connectors",
        label="Log sources",
        count=connectors_count,
        status=status,
        message=message,
        details=details,
        extra={
            "status_breakdown": status_counter,
            "connectors": connector_entries,
            "latest_last_ingested_at": latest_ingested_str,
            "ingestion_value": ingestion_avg.get("average"),
            "ingestion_unit": ingestion_avg.get("unit"),
        },
    )


def _crowdstrike_detections_report(
    env: Dict[str, Any], start: datetime, end: datetime, logger: logging.Logger
) -> List[ReportResult]:
    repository = env.get("ngsiem_repository") or DEFAULT_NGSIEM_REPOSITORY
    query_string = env.get("ngsiem_query") or DEFAULT_NGSIEM_QUERY
    severity_query = env.get("ngsiem_severity_query") or DEFAULT_NGSIEM_SEVERITY_QUERY
    events_query = env.get("ngsiem_events_query") or DEFAULT_NGSIEM_EVENTS_QUERY

    def _normalize_base_url(raw: Any) -> Optional[str]:
        if not raw:
            return None
        try:
            from urllib.parse import urlsplit, urlunsplit

            parts = urlsplit(str(raw))
            if not parts.scheme or not parts.netloc:
                return str(raw).rstrip("/")
            cleaned = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
            return cleaned.rstrip("/")
        except Exception:
            return str(raw).rstrip("/")

    base_url = _normalize_base_url(env.get("base_url") or env.get("api_base_url"))
    client_id = env.get("client_id")
    client_secret = env.get("client_secret")
    if not base_url or not client_id or not client_secret:
        return ReportResult(
            type="detections",
            label="Detecções",
            count=None,
            status="error",
            message="Configurações do Crowdstrike incompletas (base_url, client_id ou client_secret).",
            details=[],
        )

    timeout = _parse_timeout(env.get("api_timeout"), DEFAULT_TIMEOUT)
    session = _build_session()

    token_url = f"{str(base_url).rstrip('/')}/oauth2/token"
    try:
        token_resp = session.post(
            token_url,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=timeout,
        )
        if token_resp.status_code not in (200, 201):
            raise CrowdstrikeAuthError(
                f"Erro ao autenticar no Crowdstrike (HTTP {token_resp.status_code})."
            )
        token_payload = token_resp.json()
        bearer = token_payload.get("access_token")
        if not bearer:
            raise CrowdstrikeAuthError("access_token não retornado pelo OAuth2 do Crowdstrike")
    except (requests.RequestException, ValueError, CrowdstrikeAuthError) as exc:
        logger.exception("Erro ao autenticar no Crowdstrike ambiente=%s", env.get("name"))
        return ReportResult(
            type="detections",
            label="Detecções",
            count=None,
            status="error",
            message=f"Falha na autenticação do Crowdstrike: {exc}",
            details=[_format_period_label(start, end)],
        )

    start_ms = int(start.astimezone(timezone.utc).timestamp() * 1000)
    end_ms = int(end.astimezone(timezone.utc).timestamp() * 1000)

    def _start_ngsiem_search(token: str, query: str) -> str:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs"
        payload = {
            "isLive": False,
            "start": start_ms,
            "end": end_ms,
            "queryString": query,
            "timeZone": "America/Sao_Paulo",
            "showQueryEventDistribution": False,
        }
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        resp = session.post(url, json=payload, headers=headers, timeout=timeout)
        try:
            logger.info("Resposta start search NG-SIEM ambiente=%s status=%s body=%s", env.get("name"), resp.status_code, resp.text)
        except Exception:
            pass
        if resp.status_code not in (200, 201):
            raise CrowdstrikeApiError(
                f"Erro ao iniciar search NG-SIEM (HTTP {resp.status_code}): {resp.text}"
            )
        data = resp.json()
        search_id = data.get("id")
        if not search_id:
            raise CrowdstrikeApiError("Resposta sem id de search job.")
        return search_id

    def _poll_ngsiem_search(token: str, search_id: str, poll_interval: int = 5, max_polls: int = 30) -> Dict[str, Any]:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs/{search_id}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        for attempt in range(1, max_polls + 1):
            resp = session.get(url, headers=headers, timeout=timeout)
            try:
                logger.info(
                    "Polling NG-SIEM search ambiente=%s attempt=%s status=%s body=%s",
                    env.get("name"),
                    attempt,
                    resp.status_code,
                    resp.text,
                )
            except Exception:
                pass
            if resp.status_code not in (200, 201):
                raise CrowdstrikeApiError(
                    f"Erro ao fazer polling do search (HTTP {resp.status_code}): {resp.text}"
                )
            data = resp.json()
            done = data.get("done", False)
            if done:
                return data
            time_module.sleep(poll_interval)
        raise CrowdstrikeApiError("Query NG-SIEM não finalizou dentro do tempo limite.")

    def _extract_count(result: Dict[str, Any]) -> Optional[int]:
        if not isinstance(result, dict):
            return None

        # Preferred: events array returned by the results endpoint.
        events = result.get("events")
        if isinstance(events, list) and events:
            for event in events:
                if not isinstance(event, dict):
                    continue
                attrs = event.get("attributes") or event.get("data") or {}
                if "_count" in event and isinstance(event.get("_count"), (int, float, str)):
                    try:
                        return int(event.get("_count"))
                    except Exception:
                        pass
                if isinstance(attrs, dict):
                    for value in attrs.values():
                        if isinstance(value, (int, float)):
                            return int(value)

        # Sometimes the result map contains the numeric aggregation directly.
        result_map = result.get("result") if isinstance(result.get("result"), dict) else None
        if isinstance(result_map, dict):
            for value in result_map.values():
                if isinstance(value, (int, float)):
                    return int(value)

        # Last resort: check meta statistics if available.
        meta = result.get("meta")
        if isinstance(meta, dict):
            stats = meta.get("statistics")
            if isinstance(stats, dict):
                for value in stats.values():
                    if isinstance(value, (int, float)):
                        return int(value)

        return None

    def _run_query(query: str, *, poll_interval: int = 5, max_polls: int = 30) -> Tuple[Optional[int], Dict[str, Any]]:
        try:
            logger.info("Iniciando search NG-SIEM ambiente=%s repo=%s", env.get("name"), repository)
            search_id = _start_ngsiem_search(bearer, query)
            result = _poll_ngsiem_search(bearer, search_id, poll_interval=poll_interval, max_polls=max_polls)
            count_value = _extract_count(result)
            return count_value, result
        except (requests.RequestException, ValueError, CrowdstrikeApiError) as exc:
            logger.exception("Erro ao consultar detecções do Crowdstrike ambiente=%s", env.get("name"))
            raise

    results: List[ReportResult] = []

    # Detecções totais
    try:
        det_count, det_result = _run_query(query_string)
    except Exception as exc:
        return [
            ReportResult(
                type="detections",
                label="Detecções",
                count=None,
                status="error",
                message=f"Falha ao consultar detecções: {exc}",
                details=[_format_period_label(start, end)],
            )
        ]

    det_total = det_count or 0
    det_status = "ok" if det_total > 0 else "warning"
    det_message = f"{det_total} detecção(ões) no período informado." if det_total > 0 else "Nenhuma detecção encontrada no período selecionado."
    results.append(
        ReportResult(
            type="detections",
            label="Detecções",
            count=det_total,
            status=det_status,
            message=det_message,
            details=[_format_period_label(start, end)],
        )
    )

    # Severidade (alertas por severidade)
    try:
        sev_count, sev_result = _run_query(severity_query)
        sev_events = sev_result.get("events") if isinstance(sev_result, dict) else []
        sev_breakdown = []
        if isinstance(sev_events, list):
            for item in sev_events:
                if not isinstance(item, dict):
                    continue
                sev_label = item.get("Vendor.SeverityName") or item.get("vendor.severityname") or "Desconhecido"
                sev_val = item.get("_count")
                try:
                    sev_val_int = int(sev_val) if sev_val is not None else 0
                except Exception:
                    sev_val_int = 0
                sev_breakdown.append(f"{sev_label}: {sev_val_int}")
        sev_message = "; ".join(sev_breakdown) if sev_breakdown else "Nenhuma severidade retornada."
        results.append(
            ReportResult(
                type="severity",
                label="Alertas por severidade",
                count=sev_count if sev_count is not None else 0,
                status="ok",
                message=sev_message,
                details=sev_breakdown or [_format_period_label(start, end)],
            )
        )
    except Exception as exc:
        results.append(
            ReportResult(
                type="severity",
                label="Alertas por severidade",
                count=None,
                status="error",
                message=f"Falha ao consultar severidade: {exc}",
                details=[_format_period_label(start, end)],
            )
        )

    # Total de eventos (consulta mais pesada)
    try:
        events_count, _ = _run_query(events_query, poll_interval=5, max_polls=60)
        events_total = events_count if events_count is not None else 0
        results.append(
            ReportResult(
                type="events",
                label="Total de eventos",
                count=events_total,
                status="ok",
                message=f"{events_total} evento(s) no período informado.",
                details=[_format_period_label(start, end)],
            )
        )
    except Exception as exc:
        results.append(
            ReportResult(
                type="events",
                label="Total de eventos",
                count=None,
                status="error",
                message=f"Falha ao consultar eventos: {exc}",
                details=[_format_period_label(start, end)],
            )
        )

    # Conectores e ingestão
    connectors_results = _crowdstrike_connectors_summary(env, start, end, logger)
    results.extend(connectors_results)

    return results


def build_environment_report(
    env: Dict[str, Any],
    start: datetime,
    end: datetime,
    api_conf: Optional[Dict[str, Any]],
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    logger = logger or logging.getLogger(__name__)
    siem_value = str(env.get("siem") or "").strip() or "QRadar"
    normalized_siem = siem_value.lower()
    api_conf = api_conf or {}

    if normalized_siem == "qradar":
        results = [
            _qradar_offense_report(env, start, end, api_conf, logger),
            _qradar_log_sources_summary(env, start, end, api_conf, logger),
        ]
    elif normalized_siem == "crowdstrike ng-siem":
        results = _crowdstrike_detections_report(env, start, end, logger)
    else:
        results = [
            ReportResult(
                type="unsupported",
                label="SIEM não suportado",
                count=None,
                status="error",
                message=f"Consultas para o SIEM '{siem_value}' ainda não são suportadas.",
                details=[],
            )
        ]

    return EnvironmentReport(env, siem_value, start, end, results).to_dict()

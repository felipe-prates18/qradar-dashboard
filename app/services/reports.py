"""Helpers to build period reports per environment and SIEM."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .crowdstrike_client import CrowdstrikeApiError, CrowdstrikeAuthError

DEFAULT_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_NGSIEM_REPOSITORY = "search-all"
DEFAULT_NGSIEM_QUERY = r"""#repo=xdr_indicatorsrepo
| Ngsiem.event.type="ngsiem-rule-trigger-event"
| stats(function=count(rule.name))
"""


@dataclass
class ReportResult:
    type: str
    label: str
    count: Optional[int]
    status: str
    message: str
    details: Sequence[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "label": self.label,
            "count": self.count,
            "status": self.status,
            "message": self.message,
            "details": list(self.details or []),
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


def _crowdstrike_detections_report(
    env: Dict[str, Any], start: datetime, end: datetime, logger: logging.Logger
) -> ReportResult:
    repository = env.get("ngsiem_repository") or DEFAULT_NGSIEM_REPOSITORY
    query_string = env.get("ngsiem_query") or DEFAULT_NGSIEM_QUERY

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

    def _start_ngsiem_search(token: str) -> str:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs"
        payload = {
            "isLive": False,
            "start": start_ms,
            "end": end_ms,
            "queryString": query_string,
            "timeZone": "America/Sao_Paulo",
            "showQueryEventDistribution": False,
        }
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        resp = session.post(url, json=payload, headers=headers, timeout=timeout)
        if resp.status_code not in (200, 201):
            raise CrowdstrikeApiError(
                f"Erro ao iniciar search NG-SIEM (HTTP {resp.status_code}): {resp.text}"
            )
        data = resp.json()
        search_id = data.get("id")
        if not search_id:
            raise CrowdstrikeApiError("Resposta sem id de search job.")
        return search_id

    def _poll_ngsiem_search(token: str, search_id: str) -> Dict[str, Any]:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs/{search_id}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        attempts = 0
        while attempts < 12:
            attempts += 1
            resp = session.get(url, headers=headers, timeout=timeout)
            if resp.status_code not in (200, 201):
                raise CrowdstrikeApiError(
                    f"Erro ao fazer polling do search (HTTP {resp.status_code}): {resp.text}"
                )
            data = resp.json()
            if data.get("done"):
                return data
            time.sleep(5)
        raise CrowdstrikeApiError("Query NG-SIEM não finalizou dentro do tempo limite.")

    def _fetch_ngsiem_results(token: str, search_id: str) -> Dict[str, Any]:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs/{search_id}/results"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        resp = session.get(url, headers=headers, timeout=timeout)
        if resp.status_code not in (200, 201):
            raise CrowdstrikeApiError(
                f"Erro ao buscar resultados do search (HTTP {resp.status_code}): {resp.text}"
            )
        return resp.json()

    def _ensure_job_completion(token: str, search_id: str) -> None:
        url = f"{str(base_url).rstrip('/')}/humio/api/v1/repositories/{repository}/queryjobs/{search_id}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        resp = session.patch(
            url,
            json={"state": "DONE"},
            headers=headers,
            timeout=timeout,
        )
        # best effort; do not fail if PATCH is not supported

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

    try:
        logger.info("Iniciando search NG-SIEM ambiente=%s repo=%s", env.get("name"), repository)
        search_id = _start_ngsiem_search(bearer)
        poll_result = _poll_ngsiem_search(bearer, search_id)
        _ensure_job_completion(bearer, search_id)
        result = _fetch_ngsiem_results(bearer, search_id)
    except (requests.RequestException, ValueError, CrowdstrikeApiError) as exc:
        logger.exception("Erro ao consultar detecções do Crowdstrike ambiente=%s", env.get("name"))
        return ReportResult(
            type="detections",
            label="Detecções",
            count=None,
            status="error",
            message=f"Falha ao consultar detecções: {exc}",
            details=[_format_period_label(start, end)],
        )

    total_int = _extract_count(result)
    if total_int is None:
        total_int = 0

    if total_int > 0:
        status = "ok"
        message = f"{total_int} detecção(ões) no período informado."
    else:
        status = "warning"
        message = "Nenhuma detecção encontrada no período selecionado."

    return ReportResult(
        type="detections",
        label="Detecções",
        count=total_int,
        status=status,
        message=message,
        details=[_format_period_label(start, end)],
    )


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
        results = [_qradar_offense_report(env, start, end, api_conf, logger)]
    elif normalized_siem == "crowdstrike ng-siem":
        results = [_crowdstrike_detections_report(env, start, end, logger)]
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

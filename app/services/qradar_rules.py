"""Helpers to interact with the QRadar analytics rules endpoint."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests import Session
from requests.exceptions import RequestException

_DEFAULT_BASE_TEMPLATE = "https://{host}/api"
_MAX_LOG_BODY_LENGTH = 2000
_MODULE_LOGGER = logging.getLogger(__name__)


@dataclass
class _EnvironmentConfig:
    name: str
    host: Optional[str]
    code: Optional[str]
    token: Optional[str]
    base_url: Optional[str]
    verify_tls: Optional[bool]
    timeout: int
    version: Optional[str]


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
    if value is None:
        return int(default)
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(str(value))
    except Exception:
        return int(default)


def _resolve_token(env: Dict[str, Any], tokens_map: Dict[str, str]) -> Optional[str]:
    for key in (
        env.get("analytics_rules_token"),
        env.get("use_case_manager_token"),
        env.get("api_token"),
        env.get("token"),
    ):
        if key:
            return str(key)
    for lookup in (
        env.get("codigo"),
        env.get("code"),
        env.get("name"),
        env.get("host"),
    ):
        if not lookup:
            continue
        token = tokens_map.get(str(lookup))
        if token:
            return str(token)
    return None


def _build_base_url(env: Dict[str, Any], api_conf: Dict[str, Any]) -> Optional[str]:
    for key in (
        "analytics_rules_base_url",
        "analytics_base_url",
        "api_base_url",
        "base_url",
    ):
        candidate = env.get(key) or api_conf.get(key)
        if candidate:
            return str(candidate).rstrip("/")

    template = (
        api_conf.get("analytics_rules_base_template")
        or api_conf.get("base_template")
        or _DEFAULT_BASE_TEMPLATE
    )
    host = env.get("host") or env.get("console_host")
    if not host and "{host}" not in str(template):
        base = str(template)
    else:
        try:
            base = str(template).format(
                host=host or "",
                codigo=env.get("codigo") or env.get("code") or "",
                code=env.get("code") or env.get("codigo") or "",
                name=env.get("name") or "",
            )
        except Exception:
            base = str(template)
    if not base:
        return None
    return base.rstrip("/")


def _normalise_env(
    env: Dict[str, Any],
    *,
    api_conf: Dict[str, Any],
    tokens_map: Dict[str, str],
) -> _EnvironmentConfig:
    token = _resolve_token(env, tokens_map)
    base_url = _build_base_url(env, api_conf)
    verify_tls = _to_bool(env.get("verify_tls"), _to_bool(api_conf.get("verify_tls"), False))
    timeout = _parse_timeout(env.get("timeout"), api_conf.get("timeout", 20))
    version = env.get("version") or api_conf.get("version")

    return _EnvironmentConfig(
        name=str(env.get("name") or env.get("codigo") or env.get("code") or env.get("host") or "Ambiente"),
        host=env.get("host"),
        code=env.get("codigo") or env.get("code"),
        token=token,
        base_url=base_url,
        verify_tls=verify_tls,
        timeout=timeout,
        version=version,
    )


def _session_for(env: _EnvironmentConfig) -> Session:
    session = requests.Session()
    session.verify = env.verify_tls if env.verify_tls is not None else False
    headers = {
        "SEC": env.token or "",
        "Accept": "application/json",
    }
    if env.version:
        headers["Version"] = str(env.version)
    session.headers.update(headers)
    return session


def _truncate_log_body(body: str) -> str:
    if len(body) <= _MAX_LOG_BODY_LENGTH:
        return body
    return body[: _MAX_LOG_BODY_LENGTH - 1] + "…"


def _parse_total_from_content_range(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    match = re.search(r"/(\d+|\*)\s*$", value)
    if not match:
        return None
    total = match.group(1)
    if total == "*":
        return None
    try:
        return int(total)
    except Exception:
        return None


def _extract_items(data: Any) -> Optional[List[Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rules", "items", "results", "data", "content"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


def _is_enabled(item: Any) -> bool:
    if not isinstance(item, dict):
        return False

    if "enabled" not in item:
        return True

    enabled = item.get("enabled")
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, (int, float)):
        return bool(enabled)
    if isinstance(enabled, str):
        lowered = enabled.strip().lower()
        return lowered in {"1", "true", "yes", "on"}
    return False


def _fetch_enabled_count(
    env: _EnvironmentConfig,
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Optional[int], Optional[str]]:
    active_logger = logger or _MODULE_LOGGER
    if not env.base_url:
        if active_logger:
            active_logger.warning(
                "Ambiente %s sem URL configurada para a API do QRadar.", env.name
            )
        return None, "URL da API não configurada."
    if not env.token:
        if active_logger:
            active_logger.warning(
                "Ambiente %s sem token configurado para a API do QRadar.", env.name
            )
        return None, "Token da API não configurado."

    session = _session_for(env)
    url = f"{env.base_url.rstrip('/')}/analytics/rules"
    offset = 0
    page_size = 200
    total_enabled = 0
    max_iterations = 1000

    while max_iterations > 0:
        headers = {"Range": f"items={offset}-{offset + page_size - 1}"}
        params = {"fields": "id,enabled"}
        try:
            if active_logger:
                active_logger.debug(
                    "Consultando QRadar Analytics Rules (%s) para %s com params=%s headers=%s",
                    url,
                    env.name,
                    params,
                    headers,
                )
            response = session.get(url, params=params, headers=headers, timeout=env.timeout)
        except RequestException as exc:
            if active_logger:
                active_logger.warning(
                    "Falha ao consultar QRadar Analytics Rules para %s: %s", env.name, exc
                )
            return None, str(exc)

        if active_logger:
            try:
                body_text = _truncate_log_body(response.text or "")
            except Exception:
                body_text = "<conteúdo não textual>"
            active_logger.debug(
                "Resposta do QRadar Analytics Rules para %s: status=%s content-range=%s corpo=%s",
                env.name,
                response.status_code,
                response.headers.get("Content-Range"),
                body_text,
            )

        if response.status_code == 204:
            break

        if response.status_code == 401:
            return None, "Token inválido ou sem permissão."
        if response.status_code == 404:
            return None, "Endpoint /analytics/rules não encontrado."
        if response.status_code == 416:
            break

        try:
            response.raise_for_status()
        except RequestException as exc:
            if active_logger:
                active_logger.warning(
                    "Resposta inesperada da API do QRadar para %s: %s", env.name, exc
                )
            return None, str(exc)

        try:
            data = response.json()
        except ValueError:
            if active_logger:
                active_logger.warning(
                    "Não foi possível decodificar JSON da resposta do QRadar para %s.",
                    env.name,
                )
            return None, "Resposta inválida da API do QRadar."

        items = _extract_items(data)
        if items is None:
            return None, "Formato de resposta inesperado da API do QRadar."

        batch_count = len(items)
        if batch_count == 0:
            break

        if batch_count > page_size:
            batch_items = items[:page_size]
        else:
            batch_items = items

        enabled_in_batch = 0
        for item in batch_items:
            if _is_enabled(item):
                enabled_in_batch += 1
        if enabled_in_batch == 0 and batch_items:
            enabled_in_batch = len(batch_items)

        total_enabled += enabled_in_batch

        offset += batch_count
        total_items = _parse_total_from_content_range(response.headers.get("Content-Range"))
        max_iterations -= 1

        if total_items is not None:
            if offset >= total_items:
                break
        else:
            if batch_count < page_size:
                break

    if max_iterations <= 0:
        return total_enabled, "Limite de paginação excedido ao consultar a API."

    return total_enabled, None


def count_active_use_cases(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Count enabled QRadar analytics rules per environment."""

    active_logger = logger or _MODULE_LOGGER
    envs = config.get("qradar_envs") or []
    api_conf = config.get("qradar_api", {}) or {}
    tokens_map = {
        str(key): str(value)
        for key, value in (api_conf.get("tokens") or {}).items()
        if key is not None and value is not None
    }

    totals: List[Dict[str, Any]] = []
    errors: List[str] = []

    for env in envs:
        normalised = _normalise_env(env, api_conf=api_conf, tokens_map=tokens_map)
        if active_logger:
            active_logger.debug(
                "Iniciando coleta de regras habilitadas para %s (host=%s)",
                normalised.name,
                normalised.host,
            )
        total, error = _fetch_enabled_count(normalised, logger=active_logger)
        entry: Dict[str, Any] = {"environment": normalised.name, "total": None}
        if total is not None:
            try:
                entry["total"] = int(total)
            except Exception:
                entry["total"] = None
        if error:
            entry["error"] = error
            errors.append(f"{normalised.name}: {error}")
        totals.append(entry)

    return totals, errors

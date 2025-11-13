"""Integration helpers for the QRadar Use Case Manager API."""

from __future__ import annotations

"""Helper utilities to interact with the QRadar Use Case Manager API."""

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests import Session
from requests.exceptions import RequestException

_DEFAULT_BASE_TEMPLATE = (
    "https://{host}/console/plugins/app_proxy/application/UseCaseManager_service/api"
)


@dataclass
class _EnvironmentConfig:
    name: str
    host: Optional[str]
    code: Optional[str]
    token: Optional[str]
    base_url: Optional[str]
    verify_tls: Optional[bool]
    timeout: Optional[int]
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


def _build_base_url(env: Dict[str, Any], base_template: str) -> Optional[str]:
    base_url = env.get("use_case_manager_base_url") or env.get("api_base_url")
    if base_url:
        return str(base_url).rstrip("/")

    host = env.get("host") or env.get("console_host")
    if not host and "{host}" not in base_template:
        return str(base_template).rstrip("/") if base_template else None

    try:
        candidate = str(base_template).format(
            host=host or "",
            codigo=env.get("codigo") or env.get("code") or "",
            code=env.get("code") or env.get("codigo") or "",
            name=env.get("name") or "",
        )
    except Exception:
        candidate = str(base_template)
    if not candidate:
        return None
    return candidate.rstrip("/")


def _normalise_env(
    env: Dict[str, Any],
    *,
    api_conf: Dict[str, Any],
    tokens_map: Dict[str, str],
) -> _EnvironmentConfig:
    token = _resolve_token(env, tokens_map)
    base_template = (
        env.get("use_case_manager_base_template")
        or api_conf.get("use_case_manager_base_url")
        or api_conf.get("use_case_manager_base_template")
        or api_conf.get("use_case_manager_url")
        or api_conf.get("use_case_manager_api")
        or _DEFAULT_BASE_TEMPLATE
    )
    base_url = _build_base_url(env, base_template)
    verify_tls = _to_bool(
        env.get("use_case_manager_verify_tls"),
        _to_bool(api_conf.get("use_case_manager_verify_tls"), _to_bool(api_conf.get("verify_tls"), False)),
    )
    timeout = _parse_timeout(
        env.get("use_case_manager_timeout"),
        _parse_timeout(api_conf.get("use_case_manager_timeout"), api_conf.get("timeout", 20)),
    )
    version = env.get("use_case_manager_version") or api_conf.get("use_case_manager_version") or api_conf.get("version")

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


def _extract_total(data: Any) -> Optional[int]:
    numeric_keys = (
        "total",
        "total_count",
        "totalCount",
        "count",
        "result_count",
        "resultCount",
        "matching",
        "matchingCount",
        "matching_count",
        "active",
        "activeCount",
        "active_count",
    )
    if isinstance(data, dict):
        for key in numeric_keys:
            value = data.get(key)
            if isinstance(value, (int, float)):
                return int(value)
        pagination = data.get("pagination")
        if isinstance(pagination, dict):
            for key in numeric_keys:
                value = pagination.get(key)
                if isinstance(value, (int, float)):
                    return int(value)
        for collection_key in ("use_cases", "items", "results", "data", "content"):
            value = data.get(collection_key)
            if isinstance(value, list):
                total = data.get("total") or data.get("count")
                if isinstance(total, (int, float)):
                    return int(total)
                return len(value)
    elif isinstance(data, list):
        return len(data)
    return None


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


def _fetch_active_count(
    env: _EnvironmentConfig,
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Optional[int], Optional[str]]:
    if not env.base_url:
        return None, "URL da API não configurada."
    if not env.token:
        return None, "Token da API não configurado."

    session = _session_for(env)
    try:
        endpoints: List[Tuple[str, str, Iterable[Any]]] = [
            (
                "POST",
                f"{env.base_url}/use_case_explorer/search",
                (
                    {"statuses": ["ENABLED", "ACTIVE"], "page": 0, "pageSize": 1},
                    {"filters": {"status": ["ENABLED", "ACTIVE"]}, "page": 0, "pageSize": 1},
                    {"filter": {"status": ["ENABLED", "ACTIVE"]}, "page": 0, "page_size": 1},
                ),
            ),
            (
                "GET",
                f"{env.base_url}/use_case_explorer/use_cases",
                (
                    {"status": "ENABLED", "page": 0, "page_size": 1},
                    {"status": "ACTIVE", "page": 0, "page_size": 1},
                    {"status": "ENABLED"},
                ),
            ),
            (
                "GET",
                f"{env.base_url}/use_case_explorer/summary",
                (None,),
            ),
        ]
        last_error: Optional[str] = None
        for method, url, payloads in endpoints:
            for payload in payloads:
                try:
                    if method == "POST":
                        response = session.post(url, json=payload, timeout=env.timeout)
                    else:
                        params = payload if isinstance(payload, dict) else None
                        response = session.get(url, params=params, timeout=env.timeout)
                except RequestException as exc:
                    last_error = str(exc)
                    if logger:
                        logger.warning(
                            "Falha ao consultar Use Case Manager (%s %s): %s", method, url, exc
                        )
                    continue

                if response.status_code == 404:
                    if logger:
                        logger.debug("Endpoint %s não encontrado para %s", url, env.name)
                    break
                if response.status_code == 401:
                    return None, "Token inválido ou sem permissão."

                try:
                    response.raise_for_status()
                except RequestException as exc:
                    last_error = str(exc)
                    if logger:
                        logger.warning(
                            "Resposta inesperada do Use Case Manager (%s %s): %s", method, url, exc
                        )
                    continue

                try:
                    data = response.json()
                except ValueError:
                    last_error = "Resposta inválida do Use Case Manager."
                    if logger:
                        logger.warning(
                            "Não foi possível decodificar JSON da resposta (%s %s)", method, url
                        )
                    continue

                if method == "GET" and payload is None and isinstance(data, dict):
                    for key in ("activeCount", "active_count", "active"):
                        value = data.get(key)
                        if isinstance(value, (int, float)):
                            return int(value), None

                total = _extract_total(data)
                if total is not None:
                    return total, None

        return None, last_error or "Não foi possível obter o total de casos ativos."
    finally:
        session.close()


def count_active_use_cases(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Return active use case totals per environment using the QRadar API."""

    api_conf = config.get("qradar_api", {}) or {}
    tokens_map = api_conf.get("tokens") or {}
    envs = config.get("qradar_envs", []) or []

    results: List[Dict[str, Any]] = []
    warnings: List[str] = []

    for env in envs:
        normalised = _normalise_env(env, api_conf=api_conf, tokens_map=tokens_map)
        count, error = _fetch_active_count(normalised, logger=logger)
        if error:
            warnings.append(f"{normalised.name}: {error}")
        results.append(
            {
                "environment": normalised.name,
                "code": normalised.code,
                "host": normalised.host,
                "total": count,
                "error": error,
            }
        )

    results.sort(key=lambda item: item.get("environment", "").lower())
    return results, warnings

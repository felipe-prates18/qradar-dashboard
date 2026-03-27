from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import requests
from requests import Session
from requests.exceptions import RequestException

from ..constants import QRADAR_CONSOLE_INTERNAL_LOG_SOURCE_TYPES

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


def _filter_console_log_source_types(values: Iterable[str]) -> List[str]:
    filtered: List[str] = []
    seen: Set[str] = set()
    for raw in values or []:
        if raw is None:
            continue
        try:
            text = str(raw).strip()
        except Exception:
            continue
        if not text:
            continue
        normalized = text.lower()
        if normalized in QRADAR_CONSOLE_INTERNAL_LOG_SOURCE_TYPES:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        filtered.append(text)
    return sorted(filtered, key=lambda item: item.lower())


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


def _extract_log_source_type_name(entry: Any) -> str:
    if isinstance(entry, dict):
        for key in (
            "name",
            "display_name",
            "displayValue",
            "description",
            "protocol_type",
            "type",
        ):
            if key not in entry:
                continue
            value = entry.get(key)
            if isinstance(value, dict):
                nested = _extract_log_source_type_name(value)
                if nested:
                    return nested
                continue
            try:
                text = str(value).strip()
            except Exception:
                continue
            if text:
                return text
    elif entry is not None:
        try:
            text = str(entry).strip()
            if text:
                return text
        except Exception:
            return ""
    return ""


def _extract_log_source_status_text(entry: Any) -> str:
    if entry is None:
        return ""
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        for key in (
            "display_value",
            "value",
            "status",
            "name",
            "description",
            "message",
        ):
            if key not in entry:
                continue
            value = entry.get(key)
            if value is None:
                continue
            text = _extract_log_source_status_text(value)
            if text:
                return text
        messages = entry.get("messages")
        if isinstance(messages, list):
            joined = ", ".join(
                text
                for text in (
                    _extract_log_source_status_text(item) for item in messages
                )
                if text
            )
            if joined:
                return joined
        return ""
    if isinstance(entry, list):
        parts: List[str] = []
        for item in entry:
            text = _extract_log_source_status_text(item)
            if text and text not in parts:
                parts.append(text)
        return ", ".join(parts)
    try:
        return str(entry)
    except Exception:
        return ""


def _is_status_ok(status_text: str) -> bool:

    if not status_text:
        return True

    normalized = status_text.strip().lower()
    if not normalized:
        return True

    tokens = [token for token in re.split(r"[^a-z0-9]+", normalized) if token]
    if not tokens:
        return True

    negative_tokens = {
        "error",
        "erro",
        "fail",
        "failed",
        "failure",
        "parado",
        "stopped",
        "offline",
        "critical",
        "danger",
        "alert",
        "warning",
        "warn",
        "not",
    }
    positive_tokens = {
        "ok",
        "success",
        "sucesso",
        "normal",
        "online",
    }

    if "nok" in tokens:
        return False
    if "not" in tokens and "ok" in tokens:
        return False
    if any(token in negative_tokens for token in tokens):
        return False
    if any(token in positive_tokens for token in tokens):
        return True

    return True


def _extract_log_source_type_id(entry: Any) -> Optional[str]:
    if not isinstance(entry, dict):
        return None

    def _normalise(value: Any) -> Optional[str]:
        if value is None:
            return None
        try:
            text = str(value).strip()
        except Exception:
            return None
        return text or None

    for key in (
        "type_id",
        "log_source_type_id",
        "typeId",
        "logSourceTypeId",
    ):
        if key in entry:
            text = _normalise(entry.get(key))
            if text:
                return text

    for key in ("type", "log_source_type"):
        value = entry.get(key)
        if isinstance(value, dict):
            for nested_key in (
                "type_id",
                "log_source_type_id",
                "typeId",
                "logSourceTypeId",
                "id",
                "value",
            ):
                text = _normalise(value.get(nested_key))
                if text:
                    return text
        else:
            text = _normalise(value)
            if text and text.isdigit():
                return text

    return None


def _fetch_log_source_type_ids(
    env: _EnvironmentConfig,
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Set[str], Optional[str]]:
    active_logger = logger or _MODULE_LOGGER
    if not env.base_url:
        return set(), "URL da API não configurada."
    if not env.token:
        return set(), "Token da API não configurado."

    session = _session_for(env)
    url = f"{env.base_url.rstrip('/')}/config/event_sources/log_source_management/log_sources"
    page_size = 200
    field_candidates = [
        "id,status,enabled,type_id,log_source_type_id,typeId,logSourceTypeId,protocol_type_id,type,log_source_type",
        "id,status,enabled,type_id,log_source_type_id,protocol_type_id",
        "id,status,enabled,typeId,logSourceTypeId,protocol_type_id",
        "id,status,enabled,type_id,log_source_type_id",
        "id,status,enabled,typeId,logSourceTypeId",
        "id,status,enabled,type_id",
        "id,status,enabled,typeId",
        "id,status,enabled",
        None,
    ]

    for idx, candidate in enumerate(field_candidates):
        offset = 0
        max_iterations = 1000
        type_ids: Set[str] = set()
        saw_unsupported_fields = False

        while max_iterations > 0:
            headers = {"Range": f"items={offset}-{offset + page_size - 1}"}
            params = {"fields": candidate} if candidate else {}
            try:
                if active_logger:
                    active_logger.debug(
                        "Consultando log sources do QRadar (%s) para %s com params=%s headers=%s",
                        url,
                        env.name,
                        params,
                        headers,
                    )
                response = session.get(
                    url, params=params, headers=headers, timeout=env.timeout
                )
            except RequestException as exc:
                if active_logger:
                    active_logger.warning(
                        "Falha ao consultar log sources do QRadar para %s: %s",
                        env.name,
                        exc,
                    )
                return set(), str(exc)

            if response.status_code == 204:
                break
            if response.status_code == 401:
                return set(), "Token inválido ou sem permissão."
            if response.status_code == 404:
                return set(), "Endpoint de log sources não encontrado."
            if response.status_code == 416:
                break
            if response.status_code == 422 and idx < len(field_candidates) - 1:
                if active_logger:
                    active_logger.warning(
                        "Campos de log sources não suportados para %s. Tentando conjunto reduzido (campos=%s).",
                        env.name,
                        candidate or "todos",
                    )
                saw_unsupported_fields = True
                break
            if response.status_code == 422:
                return set(), "Campos solicitados não são suportados pela API do QRadar."

            try:
                response.raise_for_status()
            except RequestException as exc:
                if active_logger:
                    active_logger.warning(
                        "Resposta inesperada da API de log sources para %s: %s",
                        env.name,
                        exc,
                    )
                return set(), str(exc)

            try:
                data = response.json()
            except ValueError:
                return set(), "Resposta inválida da API do QRadar."

            items = _extract_items(data)
            if items is None:
                return set(), "Formato de resposta inesperado da API do QRadar."
            if not items:
                break

            for entry in items:
                if not isinstance(entry, dict):
                    continue
                if not _is_enabled(entry):
                    continue
                status_text = _extract_log_source_status_text(entry.get("status"))
                if not _is_status_ok(status_text):
                    continue
                type_id = _extract_log_source_type_id(entry)
                if type_id:
                    type_ids.add(type_id)

            total_items = _parse_total_from_content_range(
                response.headers.get("Content-Range")
            )
            max_iterations -= 1
            if total_items is not None:
                offset += page_size
                if offset >= total_items:
                    break
            else:
                if len(items) < page_size:
                    break
                offset += page_size

            if max_iterations <= 0:
                break

        if max_iterations <= 0:
            return type_ids, "Limite de paginação excedido ao consultar a API."

        if saw_unsupported_fields and idx < len(field_candidates) - 1:
            continue

        return type_ids, None

    return set(), "Campos solicitados não são suportados pela API do QRadar."


def _fetch_single_log_source_type_name(
    session: Session,
    base_url: str,
    type_id: str,
    field_candidates: List[Optional[str]],
    timeout: int,
    logger: Optional[logging.Logger],
) -> Tuple[Optional[str], Optional[str]]:
    for candidate in field_candidates:
        params = {"fields": candidate} if candidate else {}
        target_url = f"{base_url}/{type_id}"
        try:
            if logger:
                logger.debug(
                    "Consultando log source type %s com params=%s",
                    target_url,
                    params,
                )
            response = session.get(target_url, params=params, timeout=timeout)
        except RequestException as exc:
            return None, str(exc)

        if response.status_code == 404:
            return None, None
        if response.status_code == 401:
            return None, "Token inválido ou sem permissão."
        if response.status_code == 422 and candidate is not None:
            continue
        if response.status_code == 422:
            return None, "Campos solicitados não são suportados pela API do QRadar."

        try:
            response.raise_for_status()
        except RequestException as exc:
            return None, str(exc)

        try:
            data = response.json()
        except ValueError:
            return None, "Resposta inválida da API do QRadar."

        name = _extract_log_source_type_name(data)
        if not name and isinstance(data, dict):
            for fallback_key in ("name", "description"):
                value = data.get(fallback_key)
                if value:
                    try:
                        name = str(value).strip()
                    except Exception:
                        name = ""
                    if name:
                        break
        if name:
            return name, None

    return None, "Nome do log source type indisponível na resposta."


def _fetch_log_source_type_names(
    env: _EnvironmentConfig,
    type_ids: Set[str],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[str], Optional[str]]:
    if not type_ids:
        return [], None
    active_logger = logger or _MODULE_LOGGER
    if not env.base_url:
        return [], "URL da API não configurada."
    if not env.token:
        return [], "Token da API não configurado."

    session = _session_for(env)
    base_url = (
        f"{env.base_url.rstrip('/')}/config/event_sources/log_source_management/log_source_types"
    )
    field_candidates: List[Optional[str]] = [
        "id,name,description",
        "id,name",
        "name",
        None,
    ]

    collected: Set[str] = set()
    errors: List[str] = []
    seen_ids: Set[str] = set()

    for raw_id in type_ids:
        try:
            type_id = str(raw_id).strip()
        except Exception:
            continue
        if not type_id or type_id in seen_ids:
            continue
        seen_ids.add(type_id)
        name, error = _fetch_single_log_source_type_name(
            session, base_url, type_id, field_candidates, env.timeout, active_logger
        )
        if name:
            collected.add(name)
        elif error:
            errors.append(f"{type_id}: {error}")

    error_message = "; ".join(errors) if errors else None
    return _filter_console_log_source_types(collected), error_message


def _fetch_rule_statistics(
    env: _EnvironmentConfig,
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Optional[int], Dict[str, int], Optional[str]]:
    active_logger = logger or _MODULE_LOGGER
    if not env.base_url:
        if active_logger:
            active_logger.warning(
                "Ambiente %s sem URL configurada para a API do QRadar.", env.name
            )
        return None, {}, "URL da API não configurada."
    if not env.token:
        if active_logger:
            active_logger.warning(
                "Ambiente %s sem token configurado para a API do QRadar.", env.name
            )
        return None, {}, "Token da API não configurado."

    session = _session_for(env)
    url = f"{env.base_url.rstrip('/')}/analytics/rules"
    page_size = 200
    field_candidates = [
        "id,enabled",
        None,
    ]

    for idx, candidate in enumerate(field_candidates):
        offset = 0
        total_enabled = 0
        max_iterations = 1000
        saw_unsupported_fields = False

        while max_iterations > 0:
            headers = {"Range": f"items={offset}-{offset + page_size - 1}"}
            params = {"fields": candidate} if candidate else {}
            try:
                if active_logger:
                    active_logger.debug(
                        "Consultando QRadar Analytics Rules (%s) para %s com params=%s headers=%s",
                        url,
                        env.name,
                        params,
                        headers,
                    )
                response = session.get(
                    url, params=params, headers=headers, timeout=env.timeout
                )
            except RequestException as exc:
                if active_logger:
                    active_logger.warning(
                        "Falha ao consultar QRadar Analytics Rules para %s: %s", env.name, exc
                    )
                return None, {}, str(exc)

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
                return None, {}, "Token inválido ou sem permissão."
            if response.status_code == 404:
                return None, {}, "Endpoint /analytics/rules não encontrado."
            if response.status_code == 416:
                break
            if response.status_code == 422 and idx < len(field_candidates) - 1:
                if active_logger:
                    active_logger.warning(
                        "Campos não suportados pela API do QRadar para %s. Tentando conjunto reduzido (campos=%s).",
                        env.name,
                        candidate or "todos",
                    )
                saw_unsupported_fields = True
                break
            if response.status_code == 422:
                return None, {}, "Campos solicitados não são suportados pela API do QRadar."

            try:
                response.raise_for_status()
            except RequestException as exc:
                if active_logger:
                    active_logger.warning(
                        "Resposta inesperada da API do QRadar para %s: %s", env.name, exc
                    )
                return None, {}, str(exc)

            try:
                data = response.json()
            except ValueError:
                if active_logger:
                    active_logger.warning(
                        "Não foi possível decodificar JSON da resposta do QRadar para %s.",
                        env.name,
                    )
                return None, {}, "Resposta inválida da API do QRadar."

            items = _extract_items(data)
            if items is None:
                return None, {}, "Formato de resposta inesperado da API do QRadar."

            batch_count = len(items)
            if batch_count == 0:
                break
            if response.status_code == 422:
                return [], "Campos solicitados não são suportados pela API do QRadar."

            batch_items = items[:page_size] if batch_count > page_size else items

            enabled_in_batch = 0
            for item in batch_items:
                if _is_enabled(item):
                    enabled_in_batch += 1
            if enabled_in_batch == 0 and batch_items:
                enabled_in_batch = len(batch_items)

            total_enabled += enabled_in_batch

            offset += batch_count
            total_items = _parse_total_from_content_range(
                response.headers.get("Content-Range")
            )
            max_iterations -= 1

            if total_items is not None:
                if offset >= total_items:
                    break
            else:
                if batch_count < page_size:
                    break

        if max_iterations <= 0:
            return total_enabled, {}, "Limite de paginação excedido ao consultar a API."

        if saw_unsupported_fields and idx < len(field_candidates) - 1:
            continue

        return total_enabled, {}, None

    return None, {}, "Campos solicitados não são suportados pela API do QRadar."


def _collect_rule_statistics_impl(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], List[str]]:
    active_logger = logger or _MODULE_LOGGER
    envs = config.get("qradar_envs") or []
    api_conf = config.get("qradar_api", {}) or {}
    tokens_map = {
        str(key): str(value)
        for key, value in (api_conf.get("tokens") or {}).items()
        if key is not None and value is not None
    }

    totals: List[Dict[str, Any]] = []
    monthly_counts: Dict[str, Dict[str, int]] = {}
    errors: List[str] = []

    for env in envs:
        normalised = _normalise_env(env, api_conf=api_conf, tokens_map=tokens_map)
        if active_logger:
            active_logger.debug(
                "Iniciando coleta de regras habilitadas para %s (host=%s)",
                normalised.name,
                normalised.host,
            )
        total, month_map, error = _fetch_rule_statistics(
            normalised, logger=active_logger
        )
        entry: Dict[str, Any] = {"environment": normalised.name, "total": None}
        if total is not None:
            try:
                entry["total"] = int(total)
            except Exception:
                entry["total"] = None
        if month_map:
            sanitized_months: Dict[str, int] = {}
            for raw_key, raw_value in month_map.items():
                key = str(raw_key).strip()
                if not key:
                    continue
                try:
                    sanitized_months[key] = int(raw_value)
                except Exception:
                    try:
                        sanitized_months[key] = int(float(raw_value))
                    except Exception:
                        continue
            if sanitized_months:
                monthly_counts[normalised.name] = sanitized_months
        if error:
            entry["error"] = error
            errors.append(f"{normalised.name}: {error}")
        if month_map:
            monthly_counts[normalised.name] = month_map
        totals.append(entry)

    return totals, monthly_counts, errors


def count_active_use_cases(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    totals, _monthly_counts, errors = _collect_rule_statistics_impl(
        config, logger=logger
    )
    return totals, errors


def collect_rule_statistics(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, int]], List[str]]:
    return _collect_rule_statistics_impl(config, logger=logger)


def collect_log_source_types(
    config: Dict[str, Any],
    *,
    logger: Optional[logging.Logger] = None,
) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    active_logger = logger or _MODULE_LOGGER
    envs = config.get("qradar_envs") or []
    api_conf = config.get("qradar_api", {}) or {}
    tokens_map = {
        str(key): str(value)
        for key, value in (api_conf.get("tokens") or {}).items()
        if key is not None and value is not None
    }

    results: Dict[str, List[str]] = {}
    errors: Dict[str, str] = {}

    for env in envs:
        normalised = _normalise_env(env, api_conf=api_conf, tokens_map=tokens_map)
        if active_logger:
            active_logger.debug(
                "Iniciando coleta de log source types para %s (host=%s)",
                normalised.name,
                normalised.host,
            )
        type_ids, id_error = _fetch_log_source_type_ids(
            normalised, logger=active_logger
        )
        combined_error: Optional[str] = None
        if id_error:
            combined_error = id_error
        if type_ids:
            type_names, type_error = _fetch_log_source_type_names(
                normalised, type_ids, logger=active_logger
            )
            if type_names:
                results[normalised.name] = type_names
            if type_error:
                combined_error = (
                    f"{combined_error}; {type_error}" if combined_error else type_error
                )
        if combined_error and combined_error.strip():
            errors[normalised.name] = combined_error.strip()

    return results, errors

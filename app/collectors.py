import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

from .constants import QRADAR_CONSOLE_INTERNAL_LOG_SOURCE_TYPES
from .services.crowdstrike_client import CrowdstrikeApiError, CrowdstrikeClient
from .services import ingestion_store
from .services.zabbix_client import ZabbixClient
from .services.ssh_client import SSHClient

# Lembra, por ambiente, qual conjunto de campos da API de log sources foi
# aceito da última vez, para não repetir o fallback 422 a cada ciclo.
_LOG_SOURCE_FIELD_CACHE: Dict[str, int] = {}


def _filter_console_log_source_types(values: Iterable[str]) -> List[str]:
    filtered: List[str] = []
    seen: set[str] = set()
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


def _pct(value: Any) -> str:
    try:
        return f"{float(value):.1f}%" if value is not None else "—"
    except Exception:
        return "—"


def _parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        text = str(value).strip().replace(",", ".")
    except Exception:
        return None
    if not text or text in {"—", "-", "Erro"}:
        return None
    try:
        return float(text)
    except Exception:
        return None


def _determine_workers(total: int, default: int = 4) -> int:
    if total <= 1:
        return 1
    return min(max(1, default), total)


def collect_monitoring_data(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """Collect monitoring metrics for consoles and appliances."""

    logger = logger or logging.getLogger(__name__)
    zb_conf = config.get("zabbix", {})
    zbx = ZabbixClient(zb_conf)
    ssh = SSHClient()
    items_conf = config.get("items", {})

    envs = list(config.get("qradar_envs", []))
    total_envs = len(envs)
    if total_envs == 0:
        return {
            "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            "rows": [],
        }

    rows: List[Optional[Dict[str, Any]]] = [None] * total_envs

    def _collect_env(idx_env: int, env: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        name = env.get("name")
        env_code = env.get("codigo") or env.get("code") or name or "desconhecido"
        logger.info("Iniciando coleta de métricas para ambiente=%s", env_code)
        metrics = zbx.get_metrics(
            hostname=name,
            items=items_conf,
            zabbix_host_override=env.get("zabbix_host_override"),
        )
        logger.info(
            "Métricas coletadas ambiente=%s cpu=%s memory=%s storage=%s",
            env_code,
            metrics.get("cpu"),
            metrics.get("memory"),
            metrics.get("storage"),
        )

        def _apply_ssh_override(metric_key: str, label: str, ssh_value: Optional[float]) -> None:
            if ssh_value is not None:
                logger.info(
                    "%s coletado via SSH ambiente=%s valor=%s (zabbix=%s)",
                    label,
                    env_code,
                    ssh_value,
                    metrics.get(metric_key),
                )
                metrics[metric_key] = ssh_value
            else:
                logger.warning(
                    "Coleta de %s via SSH indisponível ambiente=%s, mantendo valor do Zabbix=%s",
                    label,
                    env_code,
                    metrics.get(metric_key),
                )

        for metric_key, label, ssh_fn in (
            ("storage", "storage /store", ssh.read_storage_percent),
            ("cpu", "CPU", ssh.read_cpu_percent),
            ("memory", "memória", ssh.read_memory_percent),
        ):
            try:
                _apply_ssh_override(metric_key, label, ssh_fn(env))
            except Exception:
                logger.exception("Erro ao coletar %s via SSH ambiente=%s", label, env_code)

        appliances_out: List[Dict[str, Any]] = []

        appliances = list(env.get("appliances", []) or [])

        def _collect_appliance(appliance_entry: Dict[str, Any]) -> Dict[str, Any]:
            appliance_name = (
                appliance_entry.get("name")
                or appliance_entry.get("hostname")
                or appliance_entry.get("zabbix_host")
                or "—"
            )
            appliance_host_hint = appliance_entry.get("hostname") or appliance_entry.get("name") or appliance_name
            appliance_override = appliance_entry.get("zabbix_host") or appliance_entry.get("zabbix_host_override")
            logger.info(
                "Iniciando coleta de appliance ambiente=%s appliance=%s host_hint=%s override=%s",
                env_code,
                appliance_name,
                appliance_host_hint,
                appliance_override,
            )
            appliance_metrics = zbx.get_metrics(
                hostname=appliance_host_hint,
                items=items_conf,
                zabbix_host_override=appliance_override,
            )
            logger.info(
                "Métricas de appliance coletadas ambiente=%s appliance=%s cpu=%s memory=%s storage=%s",
                env_code,
                appliance_name,
                appliance_metrics.get("cpu"),
                appliance_metrics.get("memory"),
                appliance_metrics.get("storage"),
            )

            target_ip = ssh.resolve_appliance_ssh_target(env, appliance_entry)
            if not target_ip:
                logger.warning(
                    "Nenhum IP resolvido para appliance=%s ambiente=%s; usando apenas Zabbix",
                    appliance_name,
                    env_code,
                )
            else:
                for metric_key, label, ssh_fn in (
                    ("storage", "storage /store", ssh.read_appliance_storage_percent),
                    ("cpu", "CPU", ssh.read_appliance_cpu_percent),
                    ("memory", "memória", ssh.read_appliance_memory_percent),
                ):
                    try:
                        ssh_value = ssh_fn(env, target_ip)
                        if ssh_value is not None:
                            logger.info(
                                "%s de appliance coletado via SSH ambiente=%s appliance=%s valor=%s (zabbix=%s)",
                                label,
                                env_code,
                                appliance_name,
                                ssh_value,
                                appliance_metrics.get(metric_key),
                            )
                            appliance_metrics[metric_key] = ssh_value
                        else:
                            logger.warning(
                                "Coleta de %s via SSH indisponível ambiente=%s appliance=%s, mantendo Zabbix=%s",
                                label,
                                env_code,
                                appliance_name,
                                appliance_metrics.get(metric_key),
                            )
                    except Exception:
                        logger.exception(
                            "Erro ao coletar %s via SSH ambiente=%s appliance=%s",
                            label,
                            env_code,
                            appliance_name,
                        )

            return {
                "name": appliance_name,
                "cpu": _pct(appliance_metrics.get("cpu")),
                "memory": _pct(appliance_metrics.get("memory")),
                "storage": _pct(appliance_metrics.get("storage")),
            }

        if appliances:
            appliance_workers = _determine_workers(len(appliances), default=3)
            if appliance_workers > 1:
                with ThreadPoolExecutor(max_workers=appliance_workers) as appliance_executor:
                    future_to_index = {
                        appliance_executor.submit(_collect_appliance, appliance): idx
                        for idx, appliance in enumerate(appliances)
                    }
                    appliances_buffer: List[Optional[Dict[str, Any]]] = [None] * len(appliances)
                    for future in as_completed(future_to_index):
                        appliance_idx = future_to_index[future]
                        try:
                            appliances_buffer[appliance_idx] = future.result()
                        except Exception:
                            logger.exception(
                                "Erro ao coletar métricas do appliance ambiente=%s idx=%s",
                                env_code,
                                appliance_idx,
                            )
                            appliances_buffer[appliance_idx] = {
                                "name": (
                                    appliances[appliance_idx].get("name")
                                    or appliances[appliance_idx].get("hostname")
                                    or appliances[appliance_idx].get("zabbix_host")
                                    or "—"
                                ),
                                "cpu": "—",
                                "memory": "—",
                                "storage": "—",
                            }
                    appliances_out.extend([item for item in appliances_buffer if item])
            else:
                for appliance_entry in appliances:
                    appliances_out.append(_collect_appliance(appliance_entry))

        lic_eps, lic_exp = "Erro", "Erro"
        lic_exp_list: List[str] = []
        lic_breakdown: List[Dict[str, Any]] = []
        try:
            logger.info("Coletando informações de licença ambiente=%s", env_code)
            lic = ssh.read_license(env)
            if isinstance(lic, dict):
                lic_eps = str(lic.get("license_eps", "Erro"))
                lic_exp = lic.get("license_expiration", "Erro")
                lic_exp_list = lic.get("license_expiration_list") or []
                lic_breakdown = lic.get("license_breakdown") or []
            logger.info(
                "Licença coletada ambiente=%s eps=%s expiracao=%s",
                env_code,
                lic_eps,
                lic_exp,
            )
        except Exception:
            logger.exception("Erro ao coletar licença ambiente=%s", env_code)

        eps_cur, eps_max = "—", "—"
        try:
            logger.info("Coletando informações de EPS ambiente=%s", env_code)
            eps = ssh.read_eps(env)
            if isinstance(eps, dict):
                if eps.get("eps_current") is not None:
                    eps_cur = f"{int(eps['eps_current'])}"
                if eps.get("eps_max") is not None:
                    eps_max = f"{int(eps['eps_max'])}"
            logger.info(
                "EPS coletado ambiente=%s atual=%s max=%s",
                env_code,
                eps_cur,
                eps_max,
            )
        except Exception:
            logger.exception("Erro ao coletar EPS ambiente=%s", env_code)

        eps_value = _parse_float(eps_cur)
        if eps_value is not None:
            try:
                ingestion_store.record_daily_ingestion(
                    env.get("id"),
                    env.get("siem") or "QRadar",
                    eps_value,
                    "EPS",
                )
            except Exception:
                logger.exception("Erro ao registrar ingestão diária ambiente=%s", env_code)

        return (
            idx_env,
            {
                "id": env.get("id"),
                "name": name,
                "code": env.get("codigo") or env.get("code"),
                "siem": env.get("siem") or "QRadar",
                "cpu": _pct(metrics.get("cpu")),
                "memory": _pct(metrics.get("memory")),
                "storage": _pct(metrics.get("storage")),
                "eps_current": eps_cur,
                "eps_max": eps_max,
                "license_eps": lic_eps,
                "license_exp": lic_exp,
                "license_exp_list": lic_exp_list,
                "license_breakdown": lic_breakdown,
                "appliances": appliances_out,
            },
        )

    max_workers = _determine_workers(total_envs, default=4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(_collect_env, idx, env): idx for idx, env in enumerate(envs)
        }
        for future in as_completed(future_to_index):
            env_idx = future_to_index[future]
            try:
                idx_env, payload = future.result()
                rows[idx_env] = payload
            except Exception:
                logger.exception("Erro inesperado na coleta de métricas para idx=%s", env_idx)
                rows[env_idx] = {
                    "name": envs[env_idx].get("name"),
                    "code": envs[env_idx].get("codigo") or envs[env_idx].get("code"),
                    "siem": envs[env_idx].get("siem") or "QRadar",
                    "cpu": "—",
                    "memory": "—",
                    "storage": "—",
                    "eps_current": "—",
                    "eps_max": "—",
                    "license_eps": "Erro",
                    "license_exp": "Erro",
                    "license_exp_list": [],
                    "license_breakdown": [],
                    "appliances": [],
                }
    data: List[Dict[str, Any]] = [row for row in rows if row is not None]

    return {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": data,
    }


def collect_health_data(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """Collect health status, connectivity and offense information for environments."""

    logger = logger or logging.getLogger(__name__)
    health_conf = config.get("health", {}) or {}
    services = health_conf.get("services") or []
    ssh = SSHClient()

    api_conf = config.get("qradar_api", {}) or {}
    tokens_map = api_conf.get("tokens") or {}
    default_verify_tls = api_conf.get("verify_tls")
    default_timeout = api_conf.get("timeout", 20)
    default_version = api_conf.get("version")
    default_base_url = api_conf.get("base_url")

    def _to_bool(value, default=False):
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("1", "true", "yes", "on", "habilitado", "sim"):
                return True
            if lowered in ("0", "false", "no", "off", "desabilitado", "nao", "não"):
                return False
        return bool(value)

    def _format_dt_label(dt_obj):
        if not dt_obj:
            return ""
        try:
            return dt_obj.astimezone().strftime("%d/%m/%Y %H:%M")
        except Exception:
            try:
                return dt_obj.strftime("%d/%m/%Y %H:%M")
            except Exception:
                return str(dt_obj)

    def _parse_timestamp(value):
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        try:
            if isinstance(value, (int, float)):
                # Assume milliseconds when the value is large enough.
                if abs(value) > 10**12:
                    return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
                return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            pass

        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return None
            try:
                numeric = int(stripped)
                return _parse_timestamp(numeric)
            except Exception:
                pass
            iso_candidate = stripped.replace("Z", "+00:00")
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
                try:
                    dt_obj = datetime.strptime(iso_candidate, fmt)
                    if dt_obj.tzinfo is None:
                        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                    return dt_obj
                except Exception:
                    continue
            try:
                dt_obj = datetime.fromisoformat(iso_candidate)
                if dt_obj.tzinfo is None:
                    dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                return dt_obj
            except Exception:
                return None

        return None

    def _append_error_from_check(check, bucket, *, ignore_statuses: Optional[List[str]] = None):
        if not check:
            return
        status = str(check.get("status") or "").lower()
        if status in ("ok", "success"):
            return
        if ignore_statuses:
            ignore_set = {str(value).lower() for value in ignore_statuses if value is not None}
            if status in ignore_set:
                return
        message = check.get("message") or check.get("error")
        if message and message not in bucket:
            bucket.append(message)

    def _connectivity_target(entry):
        if not entry:
            return None
        if isinstance(entry, str):
            return entry
        if isinstance(entry, dict):
            for key in (
                "target",
                "host",
                "hostname",
                "ip",
                "address",
                "management_ip",
            ):
                value = entry.get(key)
                if value:
                    return value
        return None

    def _connectivity_name(entry):
        if not entry:
            return "Appliance"
        if isinstance(entry, str):
            return entry or "Appliance"
        if isinstance(entry, dict):
            return entry.get("name") or entry.get("label") or entry.get("target") or "Appliance"
        return "Appliance"

    def _resolve_api_token(env):
        token = env.get("api_token")
        if token:
            return token
        env_code = env.get("codigo") or env.get("code")
        env_name = env.get("name")
        host = env.get("host")
        for key in (env_code, env_name, host):
            if key and key in tokens_map and tokens_map[key]:
                return tokens_map[key]
        return None

    def _build_api_base_url(env):
        base_url = env.get("api_base_url")
        host = env.get("host")
        if base_url:
            return str(base_url).rstrip("/")
        if default_base_url:
            try:
                candidate = str(default_base_url).format(host=host or "")
            except Exception:
                candidate = str(default_base_url)
            if candidate:
                return candidate.rstrip("/")
        if not host:
            return None
        return f"https://{host}/api"

    def _check_log_sources(env):
        token = _resolve_api_token(env)
        if not token:
            message = "Token da API do QRadar não configurado."
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "total": None,
                "error": message,
                "items": [],
                "protocol_types": [],
                "log_source_types": [],
            }

        base_url = _build_api_base_url(env)
        if not base_url:
            message = "Host da console não configurado para consulta de log sources."
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "total": None,
                "error": message,
                "items": [],
                "protocol_types": [],
                "log_source_types": [],
            }

        verify_tls = _to_bool(env.get("api_verify_tls"), _to_bool(default_verify_tls, False))
        timeout = env.get("api_timeout")
        try:
            timeout = int(timeout)
        except Exception:
            timeout = default_timeout
        if not timeout:
            timeout = 20
        version = env.get("api_version") or default_version

        max_duration = env.get("log_sources_timeout_seconds")
        if max_duration is None:
            max_duration = api_conf.get("log_sources_timeout_seconds")
        try:
            max_duration = int(max_duration)
        except Exception:
            max_duration = None
        if max_duration is not None and max_duration <= 0:
            max_duration = None
        if max_duration is None:
            max_duration = max(30, timeout * 2)
        deadline = time.monotonic() + max_duration if max_duration else None

        logger.debug(
            "Iniciando coleta de log sources ambiente=%s timeout=%ss max_duration=%ss",
            env.get("name") or env.get("host"),
            timeout,
            max_duration,
        )

        url = f"{base_url}/config/event_sources/log_source_management/log_sources"
        headers = {
            "SEC": str(token),
            "Accept": "application/json",
        }
        if version:
            headers["Version"] = str(version)

        field_candidates = [
            "id,name,status,last_event_time,enabled,protocol_type_id,description",
            "id,name,status,last_event_time,enabled",
            None,
        ]
        cache_key = str(env.get("name") or env.get("host") or "")
        field_index = _LOG_SOURCE_FIELD_CACHE.get(cache_key, 0)
        if field_index >= len(field_candidates):
            field_index = 0

        def _build_params() -> Dict[str, str]:
            fields_value = field_candidates[field_index]
            if fields_value:
                return {"fields": fields_value}
            return {}

        def _extract_type_name(entry: Any) -> str:
            if not isinstance(entry, dict):
                return ""
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
                    nested = _extract_type_name(value)
                    if nested:
                        return nested
                    continue
                try:
                    text = str(value).strip()
                except Exception:
                    continue
                if text:
                    return text
            return ""

        def _extract_protocol_type_id(entry: Any) -> Optional[str]:
            if not isinstance(entry, dict):
                return None
            candidate_keys = (
                "type_id",
                "log_source_type_id",
                "typeId",
                "logSourceTypeId",
                "protocol_type_id",
                "protocol_type",
                "type",
                "log_source_type",
            )
            for key in candidate_keys:
                if key not in entry:
                    continue
                value = entry.get(key)
                if value is None:
                    continue
                if isinstance(value, dict):
                    for nested_key in (
                        "type_id",
                        "log_source_type_id",
                        "typeId",
                        "logSourceTypeId",
                        "id",
                        "value",
                        "protocol_type_id",
                    ):
                        nested_value = value.get(nested_key)
                        if nested_value is None:
                            continue
                        try:
                            text = str(nested_value).strip()
                        except Exception:
                            continue
                        if text and text.isdigit():
                            return text
                    continue
                try:
                    text = str(value).strip()
                except Exception:
                    continue
                if text and text.isdigit():
                    return text
            return None

        def _is_ok_status(status_text: str) -> bool:
            if not status_text:
                return False
            normalized = status_text.strip().lower()
            if not normalized:
                return False
            # Evita corresponder expressões como "not ok" ou "nok".
            tokens = [
                token
                for token in re.split(r"[^a-z0-9]+", normalized)
                if token
            ]
            if not tokens:
                return False
            if "not" in tokens and "ok" in tokens:
                return False
            if "nok" in tokens:
                return False
            return "ok" in tokens

        def _lookup_log_source_type_names(
            type_ids: set[str],
        ) -> Tuple[set[str], Optional[str]]:
            if not type_ids:
                return set(), None

            types_url = (
                f"{base_url}/config/event_sources/log_source_management/log_source_types"
            )
            collected_types: set[str] = set()
            errors: List[str] = []
            field_candidates = [
                "id,name,description",
                "id,name",
                "name",
                None,
            ]

            unique_ids: List[str] = []
            seen_ids: set[str] = set()
            for raw_id in type_ids:
                try:
                    text = str(raw_id).strip()
                except Exception:
                    continue
                if not text or text in seen_ids:
                    continue
                seen_ids.add(text)
                unique_ids.append(text)

            for type_id in unique_ids:
                name_found = False
                error_message: Optional[str] = None
                for candidate in field_candidates:
                    params: Dict[str, str] = {}
                    if candidate:
                        params["fields"] = candidate
                    target_url = f"{types_url}/{type_id}"
                    try:
                        response = requests.get(
                            target_url,
                            headers=headers,
                            params=params,
                            timeout=timeout,
                            verify=verify_tls,
                        )
                    except RequestException as exc:
                        error_message = str(exc)
                        break

                    if response.status_code == 404:
                        error_message = None
                        name_found = True
                        break
                    if response.status_code == 401:
                        error_message = "Token inválido ou sem permissão."
                        break
                    if (
                        response.status_code == 422
                        and candidate is not None
                    ):
                        # Tenta próximo conjunto de campos.
                        continue
                    if response.status_code == 422:
                        error_message = (
                            "Campos solicitados não são suportados pela API do QRadar."
                        )
                        break

                    try:
                        response.raise_for_status()
                    except RequestException as exc:
                        error_message = str(exc)
                        break

                    try:
                        payload = response.json()
                    except ValueError:
                        error_message = "Resposta inválida da API do QRadar."
                        break

                    name = _extract_type_name(payload)
                    if not name and isinstance(payload, dict):
                        for fallback_key in ("name", "description"):
                            value = payload.get(fallback_key)
                            if value:
                                try:
                                    name = str(value).strip()
                                except Exception:
                                    name = ""
                                if name:
                                    break
                    if name:
                        collected_types.add(name)
                        name_found = True
                        error_message = None
                        break
                if not name_found and error_message:
                    errors.append(f"{type_id}: {error_message}")

            combined_error = "; ".join(errors) if errors else None
            return collected_types, combined_error

        def _extract_status_text(status_entry: Any) -> str:
            if status_entry is None:
                return ""
            if isinstance(status_entry, str):
                return status_entry
            if isinstance(status_entry, dict):
                for key in (
                    "display_value",
                    "value",
                    "name",
                    "status",
                    "description",
                ):
                    value = status_entry.get(key)
                    if value:
                        return str(value)
                messages = status_entry.get("messages")
                if isinstance(messages, list):
                    joined = ", ".join(
                        text for text in (_extract_status_text(item) for item in messages) if text
                    )
                    if joined:
                        return joined
                return ""
            if isinstance(status_entry, list):
                parts = []
                for item in status_entry:
                    text = _extract_status_text(item)
                    if text and text not in parts:
                        parts.append(text)
                return ", ".join(parts)
            try:
                return str(status_entry)
            except Exception:
                return ""

        def _extract_protocol_label(entry: Any) -> str:
            if not isinstance(entry, dict):
                return ""
            candidate_keys = (
                "protocol_type",
                "protocol_type_id",
                "protocol_type_name",
                "protocol",
                "protocol_id",
            )
            for key in candidate_keys:
                if key not in entry:
                    continue
                value = entry.get(key)
                if value is None:
                    continue
                if isinstance(value, dict):
                    for nested_key in (
                        "display_value",
                        "name",
                        "value",
                        "label",
                        "description",
                    ):
                        nested_value = value.get(nested_key)
                        if nested_value:
                            text = str(nested_value).strip()
                            if text:
                                return text
                    continue
                try:
                    text = str(value).strip()
                except Exception:
                    continue
                if text:
                    return text
            return ""

        now = datetime.now(timezone.utc)
        stale_threshold = now - timedelta(hours=24)
        limit = 200
        start = 0
        enabled_total = 0
        problematic = 0
        skipped_disabled = 0
        items: List[Dict[str, Any]] = []
        protocol_types: set[str] = set()
        collected_log_source_types: set[str] = set()
        type_lookup_error: Optional[str] = None
        ok_type_ids: set[str] = set()

        def _collect_active_type_names() -> Tuple[set[str], Optional[str]]:
            """Resolve the names for the active log source type IDs."""
            if not ok_type_ids:
                return set(), None
            return _lookup_log_source_type_names(ok_type_ids)

        def _collect_log_source_types() -> Tuple[set[str], Optional[str]]:
            """Backward-compatible wrapper for the legacy helper name.

            Older versions of the health-check collector invoked
            ``_collect_log_source_types`` directly.  When the logic was
            refactored to gather active IDs first the helper was renamed but
            the call sites in some deployments were not updated, leading to a
            ``NameError`` at runtime.  Keeping this thin wrapper ensures both
            the new and legacy entry points map to the same implementation.
            """

            return _collect_active_type_names()

        timed_out = False

        try:
            try:
                _collect_log_source_types()
            except (RequestException, ValueError) as exc:
                logger.warning(
                    "Falha ao coletar tecnologias de log source ambiente=%s: %s",
                    env.get("name") or env.get("host"),
                    exc,
                )
            while True:
                if deadline and time.monotonic() >= deadline:
                    timed_out = True
                    logger.warning(
                        "Tempo limite atingido na coleta de log sources ambiente=%s",
                        env.get("name") or env.get("host"),
                    )
                    break
                range_header = f"items={start}-{start + limit - 1}"
                logger.info(
                    "Consultando log sources via API ambiente=%s range=%s",
                    env.get("name") or env.get("host"),
                    range_header,
                )
                current_params = _build_params()
                response = requests.get(
                    url,
                    headers={**headers, "Range": range_header},
                    params=current_params,
                    timeout=timeout,
                    verify=verify_tls,
                )
                if (
                    response.status_code == 422
                    and field_index < len(field_candidates) - 1
                ):
                    field_index += 1
                    logger.warning(
                        "Campos da API de log sources não suportados, tentando conjunto reduzido "
                        "ambiente=%s campos=%s",
                        env.get("name") or env.get("host"),
                        current_params.get("fields", "todos"),
                    )
                    continue
                response.raise_for_status()
                _LOG_SOURCE_FIELD_CACHE[cache_key] = field_index
                payload = response.json()
                if not isinstance(payload, list):
                    raise ValueError("Resposta inesperada da API de log sources")
                if not payload:
                    break

                for entry in payload:
                    if not isinstance(entry, dict):
                        continue
                    protocol_label = _extract_protocol_label(entry)
                    if protocol_label:
                        protocol_types.add(protocol_label)
                    enabled = _to_bool(entry.get("enabled"), True)
                    if enabled:
                        enabled_total += 1
                    else:
                        skipped_disabled += 1

                    last_event_raw = None
                    for key in (
                        "last_event_time",
                        "last_event_collected_time",
                        "last_event_received_time",
                        "last_event_received",
                    ):
                        if entry.get(key) is not None:
                            last_event_raw = entry.get(key)
                            break

                    last_event_dt = _parse_timestamp(last_event_raw)
                    status_text = _extract_status_text(entry.get("status")).strip()
                    status_key = status_text.lower()
                    has_error_status = "error" in status_key or status_key in (
                        "failed",
                        "misconfigured",
                    )
                    is_stale = enabled and (
                        not last_event_dt or last_event_dt < stale_threshold
                    )
                    if enabled and _is_ok_status(status_text):
                        type_id = _extract_protocol_type_id(entry)
                        if type_id:
                            ok_type_ids.add(type_id)

                    if enabled and (has_error_status or is_stale):
                        problematic += 1
                        items.append(
                            {
                                "id": entry.get("id"),
                                "name": entry.get("name"),
                                "status": status_text or "",
                                "enabled": enabled,
                                "reason": "Sem eventos há mais de 24h"
                                if is_stale and not has_error_status
                                else "Erro reportado",
                                "protocol_type": entry.get("protocol_type_id"),
                                "description": entry.get("description"),
                                "last_event_time": last_event_dt.isoformat()
                                if last_event_dt
                                else None,
                                "last_event_time_label": _format_dt_label(last_event_dt)
                                if last_event_dt
                                else "Nunca",
                            }
                        )

                if len(payload) < limit:
                    break
                start += limit
            try:
                collected_log_source_types, type_lookup_error = _collect_active_type_names()
            except (RequestException, ValueError) as exc:
                type_lookup_error = str(exc)
                logger.warning(
                    "Falha ao consultar tecnologias de log source ambiente=%s: %s",
                    env.get("name") or env.get("host"),
                    exc,
                )
        except (RequestException, ValueError) as exc:
            message = f"Falha ao consultar log sources do QRadar: {exc}"
            logger.exception(
                "Erro na consulta de log sources ambiente=%s",
                env.get("name") or env.get("host"),
            )
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "total": None,
                "error": message,
                "items": [],
                "protocol_types": sorted(
                    collected_log_source_types or protocol_types,
                    key=lambda item: item.lower(),
                ),
                "log_source_types": [],
            }

        evaluated_total = enabled_total or 0
        if timed_out:
            ratio = None
            healthy = None
            total_value = None
        elif evaluated_total:
            healthy = max(evaluated_total - problematic, 0)
            ratio = healthy / evaluated_total
            total_value = evaluated_total
        else:
            healthy = 0
            ratio = None
            total_value = evaluated_total

        if timed_out:
            message = "Tempo limite atingido na consulta de log sources do QRadar."
            status = "warning"
            error_message = "Coleta de log sources interrompida por tempo limite."
        elif problematic:
            message = (
                f"{problematic} log source(s) com erro ou sem eventos há mais de 24h."
            )
            status = "warning"
            error_message = None
        else:
            message = "Nenhum log source com erro ou atraso superior a 24h."
            status = "ok"
            error_message = None

        details = []
        if skipped_disabled:
            details.append(f"Ignorados (desativados): {skipped_disabled}")
        if timed_out:
            details.append(
                f"Coleta interrompida após {max_duration}s; fontes avaliadas: {enabled_total}"
            )
        details.append("Limite sem eventos: 24 horas")
        details.append(f"Atualizado em: {_format_dt_label(now)}")
        if type_lookup_error:
            details.append(f"Tecnologias: {type_lookup_error}")

        return {
            "status": status,
            "message": message,
            "details": details,
            "count": problematic,
            "total": total_value,
            "ratio": ratio,
            "healthy": healthy,
            "generated_at": now.isoformat(),
            "error": error_message,
            "items": items,
            "protocol_types": sorted(
                collected_log_source_types or protocol_types,
                key=lambda item: item.lower(),
            ),
            "log_source_types": [],
        }

    def _check_offenses(env):
        token = _resolve_api_token(env)
        if not token:
            message = "Token da API do QRadar não configurado."
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "error": message,
            }

        base_url = _build_api_base_url(env)
        if not base_url:
            message = "Host da console não configurado para consulta de ofensas."
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "error": message,
            }

        verify_tls = _to_bool(env.get("api_verify_tls"), _to_bool(default_verify_tls, False))
        timeout = env.get("api_timeout")
        try:
            timeout = int(timeout)
        except Exception:
            timeout = default_timeout
        if not timeout:
            timeout = 20
        version = env.get("api_version") or default_version

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        until = datetime.now(timezone.utc)
        since_ms = int(since.timestamp() * 1000)

        url = f"{base_url}/siem/offenses"
        headers = {
            "SEC": str(token),
            "Accept": "application/json",
        }
        if version:
            headers["Version"] = str(version)

        params = {
            "filter": f"start_time>={since_ms}",
            "fields": "id,start_time,last_updated_time,status,severity",
        }

        try:
            logger.info(
                "Consultando ofensas via API ambiente=%s url=%s",
                env.get("name") or env.get("host"),
                url,
            )
            response = requests.get(
                url,
                headers=headers,
                params=params,
                timeout=timeout,
                verify=verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError("Resposta inesperada da API de ofensas")
        except (RequestException, ValueError) as exc:
            message = f"Falha ao consultar ofensas do QRadar: {exc}"
            logger.exception(
                "Erro na consulta de ofensas ambiente=%s",
                env.get("name") or env.get("host"),
            )
            return {
                "status": "error",
                "message": message,
                "details": [],
                "count": None,
                "error": message,
            }

        count = len(payload)
        latest_ts = None
        for item in payload:
            ts_value = None
            if isinstance(item, dict):
                ts_value = item.get("last_updated_time") or item.get("start_time")
            if ts_value is None:
                continue
            try:
                ts_int = int(ts_value)
            except Exception:
                continue
            if latest_ts is None or ts_int > latest_ts:
                latest_ts = ts_int

        latest_dt = None
        if latest_ts is not None:
            try:
                latest_dt = datetime.fromtimestamp(latest_ts / 1000, tz=timezone.utc)
            except Exception:
                latest_dt = None

        window_label = f"Período avaliado: {_format_dt_label(since)} - {_format_dt_label(until)}"
        details = [window_label]
        if latest_dt:
            details.append(f"Última ofensa: {_format_dt_label(latest_dt)}")

        if count > 0:
            message = f"{count} ofensa(s) registradas nas últimas 24 horas."
            status = "ok"
            error_message = None
        else:
            message = "Nenhuma ofensa registrada nas últimas 24 horas."
            status = "error"
            error_message = message

        return {
            "status": status,
            "message": message,
            "details": details,
            "count": count,
            "since": since.isoformat(),
            "until": until.isoformat(),
            "latest": latest_dt.isoformat() if latest_dt else None,
            "error": error_message,
        }

    envs = list(config.get("qradar_envs", []))
    total_envs = len(envs)
    rows: List[Optional[Dict[str, Any]]] = [None] * total_envs

    def _collect_env(idx_env: int, env: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        env_name = env.get("name") or env.get("host") or "Ambiente"
        services_result: List[Dict[str, Any]] = []
        connectivity_result: List[Dict[str, Any]] = []
        errors: List[str] = []

        log_sources_check = _check_log_sources(env)

        offense_check = _check_offenses(env)
        _append_error_from_check(offense_check, errors)
        client = None
        try:
            logger.info("Iniciando conexão SSH ambiente=%s", env_name)
            client = ssh.connect_env(env)
            logger.info("Conexão SSH estabelecida ambiente=%s", env_name)
        except Exception as exc:
            error_message = str(exc)
            errors.append(error_message)
            logger.exception("Falha ao conectar ao ambiente %s", env_name)
            if services:
                services_result = [
                    {
                        "name": service,
                        "status": "error",
                        "enabled": "unknown",
                        "sub_state": "",
                        "description": "",
                        "error": error_message,
                    }
                    for service in services
                ]
            targets = env.get("connectivity_targets") or []
            if targets:
                for target_entry in targets:
                    connectivity_result.append(
                        {
                            "name": _connectivity_name(target_entry),
                            "target": _connectivity_target(target_entry),
                            "reachable": False,
                            "latency_ms": None,
                            "packet_loss": None,
                            "status": "error",
                            "error": error_message,
                        }
                    )
        else:
            try:
                logger.info("Verificando serviços ambiente=%s", env_name)
                services_result = ssh.check_services(env, services, client=client)
                logger.info(
                    "Status de serviços coletados ambiente=%s total=%s",
                    env_name,
                    len(services_result),
                )
            except Exception as exc:
                error_message = str(exc)
                errors.append(error_message)
                logger.exception("Erro ao verificar serviços do ambiente %s", env_name)

            try:
                logger.info("Verificando conectividade ambiente=%s", env_name)
                connectivity_result = ssh.check_connectivity(env, client=client)
                logger.info(
                    "Resultados de conectividade coletados ambiente=%s total=%s",
                    env_name,
                    len(connectivity_result),
                )
            except Exception as exc:
                error_message = str(exc)
                errors.append(error_message)
                logger.exception("Erro ao verificar conectividade do ambiente %s", env_name)
            finally:
                if client is not None:
                    try:
                        client.close()
                        logger.info("Conexão SSH encerrada ambiente=%s", env_name)
                    except Exception:
                        pass

        return (
            idx_env,
            {
                "name": env_name,
                "code": env.get("codigo") or env.get("code"),
                "services": services_result,
                "connectivity": connectivity_result,
                "log_sources_check": log_sources_check,
                "offense_check": offense_check,
                "errors": errors,
            },
        )

    if total_envs:
        max_workers = _determine_workers(total_envs, default=4)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(_collect_env, idx, env): idx for idx, env in enumerate(envs)
            }
            for future in as_completed(future_to_index):
                env_idx = future_to_index[future]
                try:
                    idx_env, payload = future.result()
                    rows[idx_env] = payload
                except Exception:
                    logger.exception("Erro inesperado na coleta de health check para idx=%s", env_idx)
                    rows[env_idx] = {
                        "name": envs[env_idx].get("name") or envs[env_idx].get("host") or "Ambiente",
                        "code": envs[env_idx].get("codigo") or envs[env_idx].get("code"),
                        "siem": envs[env_idx].get("siem") or "QRadar",
                        "services": [],
                        "connectivity": [],
                        "offense_check": {
                            "status": "error",
                            "message": "Falha inesperada na coleta",
                            "details": [],
                            "count": None,
                            "error": "Falha inesperada na coleta",
                        },
                        "errors": ["Falha inesperada na coleta"],
                    }

    payload = {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": [row for row in rows if row is not None],
        "settings": {
            "latency_warning_ms": health_conf.get("latency_warning_ms", 150),
            "latency_critical_ms": health_conf.get("latency_critical_ms", 300),
            "packet_loss_warning": health_conf.get("packet_loss_warning", 5),
        },
    }

    return payload


def collect_crowdstrike_monitoring_data(
    config: Dict[str, Any], logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """Collect connector counts and ingestion totals from Crowdstrike NG-SIEM."""

    logger = logger or logging.getLogger(__name__)
    envs = list(config.get("qradar_envs", []))
    total_envs = len(envs)
    if total_envs == 0:
        return {
            "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
            "rows": [],
        }

    rows: List[Optional[Dict[str, Any]]] = [None] * total_envs

    def _collect_env(idx_env: int, env: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        env_name = env.get("name") or env.get("host") or env.get("codigo") or "Ambiente"
        env_code = env.get("codigo") or env.get("code")
        env_id = env.get("id")
        now_local = datetime.now()
        today_local = now_local.date()
        errors: List[str] = []
        connectors: List[Dict[str, Any]] = []
        ingestion_summary: Dict[str, Any] = {}
        try:
            client = CrowdstrikeClient(
                base_url=env.get("base_url", ""),
                client_id=env.get("client_id", ""),
                client_secret=env.get("client_secret", ""),
                logger=logger,
            )
        except ValueError as exc:
            errors.append(str(exc))
            client = None

        if client:
            try:
                logger.info("Solicitando token OAuth2 Crowdstrike ambiente=%s", env_name)
                bearer = client.fetch_token()
                logger.info("Token OAuth2 obtido ambiente=%s", env_name)
                logger.info("Listando conexões NG-SIEM ambiente=%s", env_name)
                result = client.list_all_connections(bearer)
                connectors = client.map_connectors(result.get("resources", []))
                ingestion_summary = client.summarize_ingestion(result)
                logger.info(
                    "Conexões NG-SIEM coletadas ambiente=%s total=%s",
                    env_name,
                    ingestion_summary.get("connectors_count"),
                )
            except (CrowdstrikeApiError, RequestException) as exc:
                errors.append(str(exc))
                logger.exception("Erro ao consultar API do Crowdstrike ambiente=%s", env_name)
            except Exception:
                logger.exception("Erro inesperado na coleta Crowdstrike ambiente=%s", env_name)
                errors.append("Erro inesperado ao consultar a API do Crowdstrike.")

        summary_defaults = {
            "connectors_count": len(connectors),
            "missing_or_invalid_count": None,
            "total_bytes_one_day": None,
            "total_gb_one_day_decimal": None,
            "total_gib_one_day_binary": None,
        }
        summary_payload = {**summary_defaults, **ingestion_summary}

        live_ingestion_value = summary_payload.get("total_gb_one_day_decimal")
        daily_sample: Optional[Dict[str, Any]] = None

        try:
            daily_sample = ingestion_store.fetch_daily_ingestion(env_id, today_local, "GB")
        except Exception:
            logger.exception(
                "Erro ao consultar ingestão diária Crowdstrike ambiente=%s data=%s",
                env_name,
                today_local.isoformat(),
            )

        should_capture_today = (
            daily_sample is None
            and live_ingestion_value is not None
            and now_local.hour == 0
        )
        if should_capture_today:
            try:
                ingestion_store.record_daily_ingestion(
                    env_id,
                    env.get("siem") or "Crowdstrike NG-SIEM",
                    live_ingestion_value,
                    "GB",
                    sample_date=today_local,
                )
                daily_sample = ingestion_store.fetch_daily_ingestion(env_id, today_local, "GB")
                logger.info(
                    "Ingestão Crowdstrike 24h capturada para o dia %s ambiente=%s",
                    today_local.isoformat(),
                    env_name,
                )
            except Exception:
                logger.exception("Erro ao registrar ingestão diária Crowdstrike ambiente=%s", env_name)

        if daily_sample is None:
            try:
                daily_sample = ingestion_store.fetch_latest_ingestion(env_id, "GB")
            except Exception:
                logger.exception(
                    "Erro ao consultar última ingestão diária Crowdstrike ambiente=%s",
                    env_name,
                )

        sample_value = daily_sample.get("value") if daily_sample else None
        sample_date = daily_sample.get("sample_date") if daily_sample else None

        if sample_value is not None:
            summary_payload["total_gb_one_day_decimal"] = sample_value
            summary_payload["total_bytes_one_day"] = int(sample_value * (1000 ** 3))
            summary_payload["total_gib_one_day_binary"] = sample_value * ((1000 / 1024) ** 3)

        return (
            idx_env,
            {
                "name": env_name,
                "code": env_code,
                "siem": env.get("siem") or "Crowdstrike NG-SIEM",
                "license_gb_day": env.get("license_gb_day"),
                "connectors": connectors,
                **summary_payload,
                "ingestion_window_hours": 24,
                "ingestion_sample_date": sample_date,
                "ingestion_collected_at": daily_sample.get("created_at") if daily_sample else None,
                "errors": errors,
                "base_url": env.get("base_url"),
            },
        )

    max_workers = _determine_workers(total_envs, default=4)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {
            executor.submit(_collect_env, idx, env): idx for idx, env in enumerate(envs)
        }
        for future in as_completed(future_to_index):
            env_idx = future_to_index[future]
            try:
                idx_env, payload = future.result()
                rows[idx_env] = payload
            except Exception:
                logger.exception("Erro inesperado na coleta Crowdstrike idx=%s", env_idx)
                env = envs[env_idx]
                rows[env_idx] = {
                    "name": env.get("name") or env.get("codigo") or env.get("host"),
                    "code": env.get("codigo") or env.get("code"),
                    "siem": env.get("siem") or "Crowdstrike NG-SIEM",
                    "license_gb_day": env.get("license_gb_day"),
                    "connectors": [],
                    "connectors_count": 0,
                    "missing_or_invalid_count": None,
                    "total_bytes_one_day": None,
                    "total_gb_one_day_decimal": None,
                    "total_gib_one_day_binary": None,
                    "ingestion_window_hours": 24,
                    "errors": ["Falha inesperada na coleta do Crowdstrike."],
                    "base_url": env.get("base_url"),
                }

    data: List[Dict[str, Any]] = [row for row in rows if row is not None]

    return {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": data,
    }

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

from .services.zabbix_client import ZabbixClient
from .services.ssh_client import SSHClient


def _pct(value: Any) -> str:
    try:
        return f"{float(value):.1f}%" if value is not None else "—"
    except Exception:
        return "—"


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

        return (
            idx_env,
            {
                "name": name,
                "code": env.get("codigo") or env.get("code"),
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
        field_index = 0

        def _build_params() -> Dict[str, str]:
            fields_value = field_candidates[field_index]
            if fields_value:
                return {"fields": fields_value}
            return {}

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

        timed_out = False

        try:
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
                "protocol_types": [],
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
            "protocol_types": sorted(protocol_types, key=lambda item: item.lower()),
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

        email_check = None
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
            email_check = {
                "status": "error",
                "message": "Não foi possível verificar o envio de e-mails.",
                "details": [],
                "count": None,
                "error": error_message,
            }
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

            try:
                email_check = ssh.check_mail_delivery(env, client=client)
            except Exception as exc:
                error_message = str(exc)
                errors.append(error_message)
                logger.exception("Erro ao verificar envio de e-mails no ambiente %s", env_name)
                email_check = {
                    "status": "error",
                    "message": "Falha ao verificar envios de e-mail.",
                    "details": [],
                    "count": None,
                    "error": error_message,
                }
            finally:
                if client is not None:
                    try:
                        client.close()
                        logger.info("Conexão SSH encerrada ambiente=%s", env_name)
                    except Exception:
                        pass

        if email_check is None:
            email_check = {
                "status": "warning",
                "message": "Verificação de e-mails não executada.",
                "details": [],
                "count": None,
            }

        _append_error_from_check(email_check, errors)

        return (
            idx_env,
            {
                "name": env_name,
                "code": env.get("codigo") or env.get("code"),
                "services": services_result,
                "connectivity": connectivity_result,
                "log_sources_check": log_sources_check,
                "offense_check": offense_check,
                "email_check": email_check,
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
                        "services": [],
                        "connectivity": [],
                        "offense_check": {
                            "status": "error",
                            "message": "Falha inesperada na coleta",
                            "details": [],
                            "count": None,
                            "error": "Falha inesperada na coleta",
                        },
                        "email_check": {
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

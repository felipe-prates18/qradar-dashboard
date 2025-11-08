import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import RequestException

from .services.zabbix_client import ZabbixClient
from .services.ssh_client import SSHClient


def _pct(value: Any) -> str:
    try:
        return f"{float(value):.1f}%" if value is not None else "—"
    except Exception:
        return "—"


def collect_monitoring_data(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> Dict[str, Any]:
    """Collect monitoring metrics for consoles and appliances."""

    logger = logger or logging.getLogger(__name__)
    zb_conf = config.get("zabbix", {})
    zbx = ZabbixClient(zb_conf)
    ssh = SSHClient()
    items_conf = config.get("items", {})
    data: List[Dict[str, Any]] = []

    for env in config.get("qradar_envs", []):
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
        for appliance in env.get("appliances", []):
            appliance_name = (
                appliance.get("name")
                or appliance.get("hostname")
                or appliance.get("zabbix_host")
                or "—"
            )
            appliance_host_hint = appliance.get("hostname") or appliance.get("name") or appliance_name
            appliance_override = appliance.get("zabbix_host") or appliance.get("zabbix_host_override")
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
            appliances_out.append(
                {
                    "name": appliance_name,
                    "cpu": _pct(appliance_metrics.get("cpu")),
                    "memory": _pct(appliance_metrics.get("memory")),
                    "storage": _pct(appliance_metrics.get("storage")),
                }
            )

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

        data.append(
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
            }
        )

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

    def _append_error_from_check(check, bucket):
        if not check:
            return
        status = str(check.get("status") or "").lower()
        if status in ("ok", "success"):
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

    rows: List[Dict[str, Any]] = []
    for env in config.get("qradar_envs", []):
        env_name = env.get("name") or env.get("host") or "Ambiente"
        services_result: List[Dict[str, Any]] = []
        connectivity_result: List[Dict[str, Any]] = []
        errors: List[str] = []

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

        rows.append(
            {
                "name": env_name,
                "code": env.get("codigo") or env.get("code"),
                "services": services_result,
                "connectivity": connectivity_result,
                "offense_check": offense_check,
                "email_check": email_check,
                "errors": errors,
            }
        )

    payload = {
        "updated_at": datetime.now().strftime("%d/%m/%Y, %H:%M:%S"),
        "rows": rows,
        "settings": {
            "latency_warning_ms": health_conf.get("latency_warning_ms", 150),
            "latency_critical_ms": health_conf.get("latency_critical_ms", 300),
            "packet_loss_warning": health_conf.get("packet_loss_warning", 5),
        },
    }

    return payload

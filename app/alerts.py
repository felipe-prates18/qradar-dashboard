import asyncio
import json
import logging
from datetime import date, datetime, timedelta, timezone, time
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from pathlib import Path

import requests
import time as time_module
import urllib3
from requests.exceptions import RequestException
from urllib3.exceptions import NameResolutionError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .services.jira_client import JiraClient


def _parse_percent(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        if isinstance(value, str) and value.endswith("%"):
            value = value.rstrip("%")
        return float(str(value).strip())
    except Exception:
        return None


def _severity_by_percent(percent: Optional[float]) -> str:
    if percent is None:
        return "neutral"
    if percent >= 90:
        return "critical"
    if percent >= 75:
        return "warning"
    return "normal"


def _parse_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            value = value.strip()
            if not value or not value.replace("-", "").isdigit():
                return int(float(value))
        return int(value)
    except Exception:
        return None


def _parse_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", ".")
            if not value:
                return None
        return float(value)
    except Exception:
        return None


def _parse_expiration(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    try:
        text = str(raw).strip()
    except Exception:
        return None
    if not text or text.lower() in {"erro", "perpetual", "perpétuo", "—", "null", "none"}:
        return None
    if text == "01/01/9999":
        return None
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(text, fmt)
        except Exception:
            continue
    return None


class _AlertLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        text = str(msg)
        if text.startswith("Alerta - "):
            return text, kwargs
        return f"Alerta - {text}", kwargs


class AlertManager:
    def __init__(
        self,
        config: Dict[str, Any],
        *,
        fetch_monitoring: Callable[[], Dict[str, Any]],
        fetch_health: Callable[[], Dict[str, Any]],
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.config = config
        self._fetch_monitoring = fetch_monitoring
        self._fetch_health = fetch_health
        base_logger = logger or logging.getLogger(__name__)
        self.logger = _AlertLoggerAdapter(base_logger, {})
        alerts_conf = config.get("alerts", {}) or {}
        self.webhook_url = (
            alerts_conf.get("teams_webhook_url")
            or alerts_conf.get("teams_webhook")
            or alerts_conf.get("webhook")
        )
        self.license_webhook_url = alerts_conf.get("license_teams_webhook_url")
        self._state_file = Path(alerts_conf.get("state_file") or "alerts_state.json")
        self._suppress_file = Path(alerts_conf.get("suppress_file") or "suppress_alerts.json")
        self._suppress: Dict[str, Any] = {}
        self.interval = int(alerts_conf.get("interval_seconds", 600))
        if self.interval < 60:
            self.interval = 60

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self.dashboard_url_template = alerts_conf.get("dashboard_url_template")
        self.dashboard_url_base = (
            alerts_conf.get("dashboard_url")
            or alerts_conf.get("dashboard_base_url")
            or "http://172.31.1.253:9030/login"
        )

        self._resource_state: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._storage_alerts: Dict[Tuple[str, str, str], bool] = {}
        self._eps_state: Dict[str, Dict[str, Any]] = {}
        self._license_state: Dict[str, Dict[str, Any]] = {}
        self._crowdstrike_license_state: Dict[str, Dict[str, Any]] = {}
        self._license_send_time = time(hour=15, minute=0)
        self._daily_reset_time = time(hour=6, minute=0)
        self._postfix_state: Dict[str, bool] = {}
        self._offense_state: Dict[str, bool] = {}
        self._connectivity_state: Dict[Tuple[str, str], bool] = {}
        self._jira_state: Dict[str, str] = {}
        self._jira_last_dispatch: Optional[Tuple[date, int]] = None
        self._daily_reset_date: Optional[date] = None
        self._url_state: Dict[str, bool] = {}
        self._pending_confirmations: Dict[str, Dict[str, Any]] = {}
        self._confirmation_required_checks: int = int(alerts_conf.get("confirmation_checks", 5))
        self._confirmation_interval: int = max(10, int(alerts_conf.get("confirmation_interval_seconds", 30)))
        self._url_timeout = self._parse_timeout_value(alerts_conf.get("url_timeout", 30))
        self._url_retry_attempts = max(1, int(alerts_conf.get("url_retry_attempts", 2)))
        self._url_retry_backoff = max(0, int(alerts_conf.get("url_retry_backoff", 2)))
        self._url_checks = []
        for entry in alerts_conf.get("url_checks") or []:
            if not isinstance(entry, dict):
                continue
            try:
                name = str(entry.get("name") or "URL monitorada").strip()
            except Exception:
                name = "URL monitorada"
            url = entry.get("url") or entry.get("link")
            try:
                url = str(url).strip()
            except Exception:
                url = None
            if not url:
                continue
            timeout_value = self._parse_timeout_value(entry.get("timeout")) or self._url_timeout
            self._url_checks.append(
                {
                    "name": name or "URL monitorada",
                    "url": url,
                    "timeout": timeout_value,
                }
            )

        self._env_labels: Dict[str, str] = {}
        for env in config.get("qradar_envs", []):
            code = env.get("codigo") or env.get("code")
            name = env.get("name") or env.get("host") or "Ambiente"
            if code:
                self._env_labels[code] = f"{name} ({code})"
            else:
                self._env_labels[name] = name

        self._jira_config = config.get("jira") or config.get("jira_alerts") or {}
        self._jira_webhook_url = self._jira_config.get("teams_webhook_url") or self._jira_config.get(
            "webhook_url"
        )
        self._jira_clients = [
            str(client).strip()
            for client in (self._jira_config.get("clients") or [])
            if str(client).strip()
        ]
        self._jira_warning_hours = max(1, int(self._jira_config.get("warning_hours", 24)))
        self._jira_critical_hours = max(
            self._jira_warning_hours, int(self._jira_config.get("critical_hours", 36))
        )
        self._state_dirty = False

        self.logger.debug(
            "Configuração de alertas carregada | webhook=%s jira_webhook=%s interval=%ss url_checks=%d jira_clients=%d",
            "configurado" if self.webhook_url else "ausente",
            "configurado" if self._jira_webhook_url else "ausente",
            self.interval,
            len(self._url_checks),
            len(self._jira_clients),
        )
        self.logger.debug(
            "Parâmetros Jira | warning_hours=%s critical_hours=%s clients=%s",
            self._jira_warning_hours,
            self._jira_critical_hours,
            self._jira_clients,
        )

        self._load_state()
        self._load_suppress()

    async def start(self) -> None:
        if self._task is not None:
            return
        if not self.webhook_url and not self._jira_webhook_url:
            self.logger.warning(
                "Nenhum webhook configurado para alertas gerais ou do Jira. Sistema de alertas inativo."
            )
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run_loop())
        self.logger.info("Sistema de alertas iniciado. Intervalo=%ss", self.interval)

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        try:
            await self._task
        except Exception:
            self.logger.exception("Erro ao finalizar tarefa de alertas")
        finally:
            self._task = None
            self.logger.info("Sistema de alertas finalizado")

    async def _run_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while not self._stop_event.is_set():
            started_at = loop.time()
            self.logger.debug("Iniciando ciclo de verificação de alertas")
            try:
                await asyncio.to_thread(self._perform_checks)
            except Exception:
                self.logger.exception("Erro ao executar verificações de alertas")
            elapsed = loop.time() - started_at
            self.logger.debug("Ciclo de verificação concluído em %.2fs", elapsed)
            if self._pending_confirmations:
                wait_seconds = max(0, self._confirmation_interval - elapsed)
                self.logger.debug(
                    "Confirmações pendentes (%d). Próxima verificação em %ds",
                    len(self._pending_confirmations),
                    wait_seconds,
                )
            else:
                wait_seconds = max(0, self.interval - elapsed)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=wait_seconds)
            except asyncio.TimeoutError:
                continue

    def run_once(self, *, force_send: bool = False) -> None:
        """Executa a rotina de alertas uma vez, de forma síncrona."""

        started_at = time_module.monotonic()
        self.logger.info("Execução manual da rotina de alertas iniciada")
        try:
            self._perform_checks(force_send=force_send)
        except Exception:
            self.logger.exception("Erro ao executar rotina de alertas manualmente")
            raise
        elapsed = time_module.monotonic() - started_at
        self.logger.info(
            "Execução manual da rotina de alertas concluída em %.2fs", elapsed
        )

    def _perform_checks(self, *, force_send: bool = False) -> None:
        now = datetime.now()
        self.logger.debug(
            "Iniciando verificações de alertas | force_send=%s timestamp=%s",
            force_send,
            now.isoformat(),
        )
        self._reset_state_if_needed(now)
        self._load_suppress()
        try:
            monitoring = self._fetch_monitoring()
        except Exception:
            self.logger.exception("Falha ao coletar métricas para alertas")
            monitoring = None

        try:
            health = self._fetch_health()
        except Exception:
            self.logger.exception("Falha ao coletar dados de saúde para alertas")
            health = None

        if monitoring is not None:
            if monitoring:
                self.logger.debug(
                    "Dados de monitoramento obtidos com sucesso | chaves=%s",
                    list(monitoring.keys()),
                )
                self._process_monitoring_alerts(monitoring, now, force_send=force_send)
            else:
                self.logger.info("Dados de monitoramento vazios recebidos para alertas")
        else:
            self.logger.warning("Falha ao obter dados de monitoramento para alertas")

        if health is not None:
            if health:
                self.logger.debug(
                    "Dados de saúde obtidos com sucesso | chaves=%s", list(health.keys())
                )
                self._process_health_alerts(health, now, force_send=force_send)
            else:
                self.logger.info("Dados de saúde vazios recebidos para alertas")
        else:
            self.logger.warning("Falha ao obter dados de saúde para alertas")

        try:
            self._process_jira_alerts(now, force_send=force_send)
        except Exception:
            self.logger.exception("Falha ao processar alertas do Jira")

        try:
            self._process_url_alerts(now, force_send=force_send)
        except Exception:
            self.logger.exception("Falha ao processar alertas de URLs monitoradas")

        if monitoring is None and health is None:
            self.logger.warning("Nenhum dado disponível para avaliação de alertas")
        self.logger.debug("Finalizando verificações de alertas | force_send=%s", force_send)

        self._save_state_if_dirty()

    def _env_label(self, row: Dict[str, Any]) -> str:
        code = row.get("code")
        name = row.get("name") or row.get("host") or "Ambiente"
        if code and code in self._env_labels:
            return self._env_labels[code]
        if code:
            return f"{name} ({code})"
        return name

    def _build_dashboard_url(
        self,
        *,
        env_code: Optional[str] = None,
        category: Optional[str] = None,
        component: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> str:
        if self.dashboard_url_template:
            class _SafeDict(dict):
                def __missing__(self, key: str) -> str:
                    return ""

            context = _SafeDict(
                {
                    "code": env_code or "",
                    "category": category or "",
                    "component": component or "",
                    "severity": severity or "",
                }
            )
            try:
                url = self.dashboard_url_template.format_map(context)
                if url:
                    return url
            except Exception:
                self.logger.exception(
                    "Falha ao formatar dashboard_url_template. Usando URL padrão."
                )

        base = self.dashboard_url_base
        if env_code:
            separator = "&" if "?" in base else "?"
            return f"{base}{separator}env={env_code}"
        return base

    def _send_alert(
        self,
        title: str,
        message: str,
        *,
        severity: str = "normal",
        summary: Optional[str] = None,
        facts: Optional[Tuple[Dict[str, str], ...]] = None,
        category: Optional[str] = None,
        detected_at: Optional[datetime] = None,
        extra: Optional[Dict[str, Any]] = None,
        env_code: Optional[str] = None,
        component: Optional[str] = None,
        webhook_urls: Optional[Iterable[str]] = None,
    ) -> None:
        self.logger.info(
            "Preparando envio de alerta | titulo='%s' severidade='%s'", title, severity
        )

        summary = summary or title
        severity_key = (severity or "normal").strip().lower()
        severity_map = {
            "critical": "CRITICAL",
            "warning": "WARNING",
            "info": "INFO",
            "informational": "INFO",
            "normal": "INFO",
        }
        normalized_severity = severity_map.get(severity_key, severity_key.upper())

        payload: Dict[str, Any] = {
            "title": title,
            "summary": summary,
            "severity": normalized_severity,
            "message": message,
        }

        if facts:
            payload["facts"] = [dict(item) for item in facts if item.get("value")]
        if category:
            payload["category"] = category

        timestamp = detected_at or datetime.utcnow().replace(tzinfo=timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        else:
            timestamp = timestamp.astimezone(timezone.utc)
        timestamp = timestamp.replace(microsecond=0)
        payload["detectedAt"] = timestamp.isoformat().replace("+00:00", "Z")

        payload["dashboardUrl"] = self._build_dashboard_url(
            env_code=env_code,
            category=category,
            component=component,
            severity=normalized_severity,
        )

        if extra:
            payload.update(extra)
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload, ensure_ascii=False)

        dedicated_category = (category or "").lower()
        if dedicated_category in {"license", "jira"}:
            targets = []
            if dedicated_category == "license" and self.license_webhook_url:
                targets.append(("licenca", self.license_webhook_url))
            elif dedicated_category == "jira" and self._jira_webhook_url:
                targets.append(("jira", self._jira_webhook_url))
        elif webhook_urls:
            targets = [(f"custom-{idx}", url) for idx, url in enumerate(webhook_urls, start=1) if url]
        else:
            targets = [("principal", self.webhook_url)] if self.webhook_url else []

        if not targets:
            self.logger.warning("Nenhum webhook configurado para envio do alerta '%s'", title)
            return

        try:
            self.logger.debug(
                "Webhooks selecionados para envio | titulo='%s' destinos=%s",
                title,
                [label for label, _ in targets],
            )
            for label, url in targets:
                try:
                    self.logger.debug(
                        "Enviando webhook (%s) para o Microsoft Teams | headers=%s payload=%s",
                        label,
                        headers,
                        body,
                    )

                    response = None
                    attempts = 3
                    for attempt in range(1, attempts + 1):
                        try:
                            response = requests.post(
                                url,
                                headers=headers,
                                data=body.encode("utf-8"),
                                timeout=10,
                            )
                            self.logger.debug(
                                "Resposta do webhook do Teams (%s) | status=%s corpo=%s",
                                label,
                                getattr(response, "status_code", "desconhecido"),
                                (response.text[:1000] if getattr(response, "text", None) else ""),
                            )
                            response.raise_for_status()
                            break
                        except requests.RequestException as exc:
                            resp = getattr(exc, "response", None)
                            if resp is not None:
                                body_resp = resp.text[:1000] if getattr(resp, "text", None) else ""
                                self.logger.warning(
                                    "Tentativa %d/%d falhou (%s) | status=%s corpo=%s",
                                    attempt,
                                    attempts,
                                    label,
                                    resp.status_code,
                                    body_resp,
                                )
                            else:
                                if self._is_name_resolution_error(exc):
                                    self.logger.error(
                                        "Tentativa %d/%d falhou (%s) por erro de DNS. "
                                        "Verifique o hostname do webhook e a resolução de DNS antes de reativar o envio. | erro=%s",
                                        attempt,
                                        attempts,
                                        label,
                                        exc,
                                    )
                                    return

                                self.logger.warning(
                                    "Tentativa %d/%d falhou (%s) sem resposta HTTP | erro=%s",
                                    attempt,
                                    attempts,
                                    label,
                                    exc,
                                )
                            if attempt < attempts:
                                time_module.sleep(2 * attempt)
                                continue
                            raise

                    self.logger.info("Alerta enviado com sucesso (%s): %s", label, title)
                except requests.RequestException as exc:
                    resp = getattr(exc, "response", None)
                    if resp is not None:
                        body_resp = resp.text[:1000] if getattr(resp, "text", None) else ""
                        self.logger.exception(
                            "Falha ao enviar alerta para o Microsoft Teams (%s) | status=%s corpo=%s",
                            label,
                            resp.status_code,
                            body_resp,
                        )
                    else:
                        self.logger.exception(
                            "Falha ao enviar alerta para o Microsoft Teams (%s) sem resposta HTTP | erro=%s",
                            label,
                            exc,
                        )
        except Exception:
            self.logger.exception("Falha inesperada ao enviar alerta para o Microsoft Teams")

    @staticmethod
    def _is_name_resolution_error(exc: BaseException) -> bool:
        current: Optional[BaseException] = exc
        while current is not None:
            if isinstance(current, NameResolutionError):
                return True

            message = str(current)
            lowered = message.lower()
            if "failed to resolve" in lowered or "name resolution" in lowered:
                return True

            current = current.__cause__ or current.__context__

        return False

    @staticmethod
    def _parse_date_value(raw: Any) -> Optional[date]:
        if raw is None:
            return None
        try:
            return date.fromisoformat(str(raw))
        except Exception:
            return None

    @staticmethod
    def _parse_datetime_value(raw: Any) -> Optional[datetime]:
        if raw is None:
            return None
        try:
            return datetime.fromisoformat(str(raw))
        except Exception:
            return None

    @staticmethod
    def _parse_timeout_value(raw: Any) -> Any:
        """Return a timeout value compatible with requests, or None if invalid.

        Accepts:
        - numeric (int/float) -> single timeout for connect/read
        - sequence of two numerics -> (connect, read)
        - dict with keys "connect" and/or "read"
        """

        def _parse_number(value: Any) -> Optional[float]:
            try:
                number = float(value)
                if number > 0:
                    return number
            except Exception:
                return None
            return None

        if raw is None:
            return None

        if isinstance(raw, (int, float)):
            parsed = _parse_number(raw)
            return parsed if parsed is not None else None

        if isinstance(raw, (list, tuple)) and len(raw) == 2:
            connect = _parse_number(raw[0])
            read = _parse_number(raw[1])
            if connect is not None and read is not None:
                return (connect, read)
            return None

        if isinstance(raw, dict):
            connect = _parse_number(raw.get("connect"))
            read = _parse_number(raw.get("read"))
            if connect and read:
                return (connect, read)
            if connect:
                return connect
            if read:
                return read
            return None

        try:
            as_float = float(str(raw).strip())
            if as_float > 0:
                return as_float
        except Exception:
            return None
        return None

    @staticmethod
    def _format_timeout_value(raw: Any) -> str:
        if isinstance(raw, (list, tuple)) and len(raw) == 2:
            return f"connect={raw[0]}s read={raw[1]}s"
        if isinstance(raw, (int, float)):
            return f"{raw}s"
        return str(raw)

    def _load_suppress(self) -> None:
        if not self._suppress_file.exists():
            self.logger.debug(
                "Arquivo de supressão não encontrado. Supressões desativadas. | caminho=%s",
                self._suppress_file,
            )
            return
        try:
            content = json.loads(self._suppress_file.read_text(encoding="utf-8"))
            self._suppress = content.get("suppress") or {}
            self.logger.info(
                "Supressões de alertas carregadas | ambientes=%d | caminho=%s",
                len(self._suppress),
                self._suppress_file,
            )
        except Exception:
            self.logger.exception(
                "Não foi possível carregar o arquivo de supressão (%s)", self._suppress_file
            )

    def _is_suppressed(
        self, code: str, alert_type: str, target: Optional[str] = None, env_label: Optional[str] = None
    ) -> bool:
        env_suppress = self._suppress.get(code)
        if not env_suppress and env_label:
            env_suppress = self._suppress.get(env_label)
        if not env_suppress and self._suppress:
            for key, val in self._suppress.items():
                if key and (
                    (code and key.upper() in code.upper())
                    or (env_label and key.upper() in env_label.upper())
                ):
                    env_suppress = val
                    break
        if not env_suppress:
            return False
        value = env_suppress.get(alert_type)
        if value is None:
            return False
        if alert_type == "connectivity":
            if not isinstance(value, list):
                value = [value]
            return target in value
        return bool(value)

    def _load_state(self) -> None:
        if not self._state_file:
            return

        if not self._state_file.exists():
            self.logger.debug(
                "Arquivo de estado dos alertas não encontrado. Inicializando sem estado persistido. | caminho=%s",
                self._state_file,
            )
            return

        try:
            content = json.loads(self._state_file.read_text(encoding="utf-8"))
        except Exception:
            self.logger.exception(
                "Não foi possível carregar o arquivo de estado dos alertas (%s)",
                self._state_file,
            )
            return

        resource_entries = content.get("resource_state") or []
        for entry in resource_entries:
            key = (entry.get("code"), entry.get("component"), entry.get("metric"))
            if not all(key):
                continue
            self._resource_state[key] = {
                "first_seen": self._parse_datetime_value(entry.get("first_seen")),
                "alert_sent": bool(entry.get("alert_sent")),
            }

        storage_entries = content.get("storage_alerts") or []
        for entry in storage_entries:
            key = (entry.get("code"), entry.get("component"), entry.get("metric"))
            if not all(key):
                continue
            self._storage_alerts[key] = True

        eps_state = content.get("eps_state") or {}
        for code, values in eps_state.items():
            self._eps_state[code] = {
                "first_exceeded": self._parse_datetime_value(values.get("first_exceeded")),
                "last_sent_date": self._parse_date_value(values.get("last_sent_date")),
            }

        license_state = content.get("license_state") or {}
        for code, values in license_state.items():
            self._license_state[code] = {
                "info_sent_date": self._parse_date_value(values.get("info_sent_date")),
                "warning_sent_date": self._parse_date_value(values.get("warning_sent_date")),
                "critical_sent_date": self._parse_date_value(values.get("critical_sent_date")),
            }

        crowdstrike_license_state = content.get("crowdstrike_license_state") or {}
        for code, values in crowdstrike_license_state.items():
            self._crowdstrike_license_state[code] = {
                "last_sent_date": self._parse_date_value(values.get("last_sent_date")),
            }

        postfix_state = content.get("postfix_state") or {}
        self._postfix_state.update({key: bool(value) for key, value in postfix_state.items()})

        offense_state = content.get("offense_state") or {}
        self._offense_state.update({key: bool(value) for key, value in offense_state.items()})

        connectivity_entries = content.get("connectivity_state") or []
        for entry in connectivity_entries:
            key = (entry.get("code"), entry.get("target"))
            if not all(key):
                continue
            self._connectivity_state[key] = True

        url_state = content.get("url_state") or []
        for item in url_state:
            try:
                url = str(item).strip()
            except Exception:
                url = None
            if url:
                self._url_state[url] = True

        jira_state = content.get("jira_state") or {}
        self._jira_state.update({key: str(value) for key, value in jira_state.items() if value})

        dispatch = content.get("jira_last_dispatch")
        if isinstance(dispatch, (list, tuple)) and len(dispatch) == 2:
            stored_date = self._parse_date_value(dispatch[0])
            stored_hour = dispatch[1]
            if stored_date and isinstance(stored_hour, int):
                self._jira_last_dispatch = (stored_date, stored_hour)

        reset_date = self._parse_date_value(content.get("daily_reset_date"))
        if reset_date:
            self._daily_reset_date = reset_date

        self.logger.info(
            "Estado dos alertas carregado de %s", self._state_file,
        )
        self.logger.debug(
            "Resumo do estado carregado | recursos=%d storage=%d eps=%d license=%d crowdstrike_license=%d postfix=%d offense=%d connectivity=%d url=%d jira=%d",
            len(self._resource_state),
            len(self._storage_alerts),
            len(self._eps_state),
            len(self._license_state),
            len(self._crowdstrike_license_state),
            len(self._postfix_state),
            len(self._offense_state),
            len(self._connectivity_state),
            len(self._url_state),
            len(self._jira_state),
        )

    def _serialize_state(self) -> Dict[str, Any]:
        def _serialize_datetime(value: Optional[datetime]) -> Optional[str]:
            return value.isoformat() if isinstance(value, datetime) else None

        def _serialize_date(value: Optional[date]) -> Optional[str]:
            return value.isoformat() if isinstance(value, date) else None

        resource_state = [
            {
                "code": code,
                "component": component,
                "metric": metric,
                "first_seen": _serialize_datetime(values.get("first_seen")),
                "alert_sent": bool(values.get("alert_sent")),
            }
            for (code, component, metric), values in self._resource_state.items()
        ]

        storage_state = [
            {
                "code": code,
                "component": component,
                "metric": metric,
            }
            for (code, component, metric) in self._storage_alerts.keys()
        ]

        eps_state = {
            code: {
                "first_exceeded": _serialize_datetime(values.get("first_exceeded")),
                "last_sent_date": _serialize_date(values.get("last_sent_date")),
            }
            for code, values in self._eps_state.items()
        }

        license_state = {
            code: {
                "info_sent_date": _serialize_date(values.get("info_sent_date")),
                "warning_sent_date": _serialize_date(values.get("warning_sent_date")),
                "critical_sent_date": _serialize_date(values.get("critical_sent_date")),
            }
            for code, values in self._license_state.items()
        }

        crowdstrike_license_state = {
            code: {
                "last_sent_date": _serialize_date(values.get("last_sent_date")),
            }
            for code, values in self._crowdstrike_license_state.items()
        }

        connectivity_state = [
            {"code": code, "target": target}
            for (code, target) in self._connectivity_state.keys()
        ]

        url_state = [url for url in self._url_state.keys()]

        jira_dispatch = None
        if self._jira_last_dispatch:
            dispatch_date, dispatch_hour = self._jira_last_dispatch
            jira_dispatch = [
                _serialize_date(dispatch_date),
                dispatch_hour,
            ]

        return {
            "resource_state": resource_state,
            "storage_alerts": storage_state,
            "eps_state": eps_state,
            "license_state": license_state,
            "crowdstrike_license_state": crowdstrike_license_state,
            "postfix_state": self._postfix_state,
            "offense_state": self._offense_state,
            "connectivity_state": connectivity_state,
            "url_state": url_state,
            "jira_state": self._jira_state,
            "jira_last_dispatch": jira_dispatch,
            "daily_reset_date": self._daily_reset_date.isoformat()
            if self._daily_reset_date
            else None,
        }

    def _save_state_if_dirty(self) -> None:
        if not self._state_dirty:
            return

        payload = self._serialize_state()
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            self._state_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            self._state_dirty = False
            self.logger.debug("Estado dos alertas salvo em %s", self._state_file)
        except Exception:
            self.logger.exception(
                "Falha ao persistir estado dos alertas em %s", self._state_file
            )

    def _mark_state_dirty(self) -> None:
        self._state_dirty = True

    def _should_confirm_alert(self, key: str, condition_active: bool, now: datetime) -> bool:
        """Gerencia a janela de confirmação de alertas.

        Retorna True quando a condição foi confirmada pelo número necessário de verificações
        consecutivas e o alerta deve ser enviado. Retorna False enquanto aguarda confirmação
        ou quando a condição foi resolvida antes do envio.

        O objetivo é reduzir o ruído de alertas: um problema transitório que se resolve
        dentro da janela de confirmação não gera alerta.
        """
        if not condition_active:
            if key in self._pending_confirmations:
                pending = self._pending_confirmations.pop(key)
                self.logger.info(
                    "Condição de alerta resolvida dentro da janela de confirmação | "
                    "chave=%s verificações=%d/%d duração=%s",
                    key,
                    pending["check_count"],
                    self._confirmation_required_checks,
                    now - pending["first_detected"],
                )
            return False

        if key not in self._pending_confirmations:
            self._pending_confirmations[key] = {
                "first_detected": now,
                "check_count": 0,
            }
            self.logger.info(
                "Condição de alerta detectada, iniciando janela de confirmação | "
                "chave=%s verificações_necessárias=%d intervalo=%ds",
                key,
                self._confirmation_required_checks,
                self._confirmation_interval,
            )
            return False

        pending = self._pending_confirmations[key]

        timeout = timedelta(seconds=self._confirmation_interval * (self._confirmation_required_checks + 2))
        if now - pending["first_detected"] > timeout:
            self.logger.warning(
                "Janela de confirmação expirou sem atingir %d verificações | chave=%s. Reiniciando contagem.",
                self._confirmation_required_checks,
                key,
            )
            self._pending_confirmations[key] = {
                "first_detected": now,
                "check_count": 0,
            }
            return False

        pending["check_count"] += 1
        self.logger.info(
            "Verificação de confirmação de alerta | chave=%s verificações=%d/%d",
            key,
            pending["check_count"],
            self._confirmation_required_checks,
        )

        if pending["check_count"] >= self._confirmation_required_checks:
            self._pending_confirmations.pop(key)
            self.logger.info(
                "Condição de alerta confirmada após %d verificações consecutivas | "
                "chave=%s duração=%s",
                self._confirmation_required_checks,
                key,
                now - pending["first_detected"],
            )
            return True

        return False

    def _reset_state_if_needed(self, now: datetime) -> None:
        if now.time() < self._daily_reset_time:
            return
        today = now.date()
        if self._daily_reset_date == today:
            return
        self.logger.info(
            "Resetando estado dos alertas para novo ciclo diário | data=%s",
            today.isoformat(),
        )
        self._resource_state.clear()
        self._storage_alerts.clear()
        self._eps_state.clear()
        self._license_state.clear()
        self._crowdstrike_license_state.clear()
        self._postfix_state.clear()
        self._offense_state.clear()
        self._connectivity_state.clear()
        self._url_state.clear()
        self._jira_state.clear()
        self._jira_last_dispatch = None
        self._daily_reset_date = today
        self._mark_state_dirty()

    def _process_monitoring_alerts(
        self, monitoring: Dict[str, Any], now: datetime, *, force_send: bool = False
    ) -> None:
        rows = monitoring.get("rows") or []
        self.logger.debug("Processando %d registros de monitoramento", len(rows))
        for row in rows:
            env_label = self._env_label(row)
            code = row.get("code") or env_label
            self.logger.debug(
                "Processando monitoramento | ambiente=%s codigo=%s appliances=%d",
                env_label,
                code,
                len(row.get("appliances") or []),
            )

            self._check_usage_alerts(env_label, code, "Console", row, now, force_send=force_send)

            appliances = row.get("appliances") or []
            for appliance in appliances:
                component = appliance.get("name") or appliance.get("zabbix_host") or "Appliance"
                self._check_usage_alerts(
                    env_label, code, component, appliance, now, force_send=force_send
                )

            self._check_eps_alert(row, env_label, code, now, force_send=force_send)
            self._check_license_alert(
                row, env_label, code, now, force_send=force_send
            )
            self._check_crowdstrike_ingestion_license_alert(
                row, env_label, code, now, force_send=force_send
            )

    def _check_usage_alerts(
        self,
        env_label: str,
        code: str,
        component: str,
        metrics_container: Dict[str, Any],
        now: datetime,
        *,
        force_send: bool = False,
    ) -> None:
        for metric_key in ("cpu", "memory", "storage"):
            percent = _parse_percent(metrics_container.get(metric_key))
            severity = _severity_by_percent(percent)
            key = (code, component, metric_key)

            if severity == "critical":
                if key not in self._resource_state:
                    self._resource_state[key] = {"first_seen": now, "alert_sent": False}
                    self._mark_state_dirty()
                state = self._resource_state[key]
                if state.get("first_seen") is None:
                    state["first_seen"] = now
                    self._mark_state_dirty()
                if (force_send or not state.get("alert_sent")) and now - state["first_seen"] >= timedelta(hours=1):
                    message = (
                        f"{env_label} - {component}: consumo crítico de {metric_key.upper()} "
                        f"por mais de 1 hora ({percent:.1f}%)."
                    )
                    facts = (
                        {"title": "Ambiente", "value": env_label},
                        {"title": "Componente", "value": component},
                        {"title": "Recurso", "value": metric_key.upper()},
                        {"title": "Uso", "value": f"{percent:.1f}%" if percent is not None else "n/d"},
                        {"title": "Duração", "value": ">= 1 hora"},
                    )
                    self._send_alert(
                        "Consumo crítico prolongado",
                        message,
                        severity="critical",
                        summary=f"{env_label} - {component}",
                        facts=facts,
                        category="resource",
                        detected_at=now,
                        env_code=code,
                        component=component,
                    )
                    state["alert_sent"] = True
                    self._mark_state_dirty()
                else:
                    remaining = timedelta(hours=1) - (now - state["first_seen"])
                    if remaining.total_seconds() < 0:
                        remaining = timedelta(0)
                    self.logger.debug(
                        "Consumo crítico detectado para %s/%s/%s, aguardando %s para alertar",
                        env_label,
                        component,
                        metric_key,
                        remaining,
                    )
            else:
                if key in self._resource_state:
                    self._resource_state.pop(key, None)
                    self._mark_state_dirty()

            if metric_key == "storage":
                if percent is not None and percent >= 90:
                    if force_send or not self._storage_alerts.get(key):
                        message = (
                            f"{env_label} - {component}: armazenamento atingiu {percent:.1f}% de uso."
                        )
                        facts = (
                            {"title": "Ambiente", "value": env_label},
                            {"title": "Componente", "value": component},
                            {"title": "Uso", "value": f"{percent:.1f}%"},
                        )
                        self._send_alert(
                            "Armazenamento crítico",
                            message,
                            severity="critical",
                            summary=f"{env_label} - {component}",
                            facts=facts,
                            category="storage",
                            detected_at=now,
                            env_code=code,
                            component=component,
                        )
                        self._storage_alerts[key] = True
                        self._mark_state_dirty()
                    else:
                        self.logger.debug(
                            "Alerta de armazenamento já enviado para %s/%s (%s%%)",
                            env_label,
                            component,
                            percent,
                        )
                else:
                    self._storage_alerts.pop(key, None)
                    self._mark_state_dirty()

            if severity != "critical":
                # Reset the first seen timestamp if the metric returned to normal levels.
                if key in self._resource_state:
                    self._resource_state[key]["first_seen"] = None
                    self._resource_state[key]["alert_sent"] = False
                    self._mark_state_dirty()

    def _check_eps_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime, *, force_send: bool = False
    ) -> None:
        license_eps = _parse_int(row.get("license_eps"))
        eps_current = _parse_int(row.get("eps_current"))
        if not license_eps or license_eps <= 0 or eps_current is None:
            if code in self._eps_state:
                self._eps_state.pop(code, None)
                self._mark_state_dirty()
            return

        if code not in self._eps_state:
            self._eps_state[code] = {"first_exceeded": None, "last_sent_date": None}
            self._mark_state_dirty()
        state = self._eps_state[code]

        if eps_current > license_eps:
            if state.get("first_exceeded") is None:
                state["first_exceeded"] = now
                self._mark_state_dirty()
            if now - state["first_exceeded"] >= timedelta(hours=24):
                last_sent = state.get("last_sent_date")
                if force_send or last_sent != now.date():
                    message = (
                        f"{env_label}: EPS atual ({eps_current}) excede o limite de licença ({license_eps}) "
                        "há mais de 24 horas."
                    )
                    duration = now - state["first_exceeded"]
                    facts = (
                        {"title": "Ambiente", "value": env_label},
                        {"title": "EPS atual", "value": str(eps_current)},
                        {"title": "Limite da licença", "value": str(license_eps)},
                        {"title": "Excedendo há", "value": f"{duration.days * 24 + duration.seconds // 3600}h"},
                    )
                    self._send_alert(
                        "EPS acima do licenciado",
                        message,
                        severity="critical",
                        summary=env_label,
                        facts=facts,
                        category="eps",
                        detected_at=now,
                        env_code=code,
                    )
                    state["last_sent_date"] = now.date()
                    self._mark_state_dirty()
                else:
                    self.logger.debug(
                        "Alerta diário de EPS já enviado para %s na data %s",
                        env_label,
                        last_sent,
                    )
            else:
                elapsed = now - state["first_exceeded"]
                self.logger.debug(
                    "EPS excedido para %s há %s; aguardando 24h para alertar",
                    env_label,
                    elapsed,
                )
        else:
            if code in self._eps_state:
                self._eps_state.pop(code, None)
                self._mark_state_dirty()

    def _check_license_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime, *, force_send: bool
    ) -> None:
        expirations = row.get("license_exp_list") or []
        if not expirations and row.get("license_exp"):
            expirations = [row.get("license_exp")]

        dates = [dt for dt in (_parse_expiration(item) for item in expirations) if dt is not None]
        if not dates:
            self._license_state.pop(code, None)
            return

        soonest = min(dates)
        days_until = (soonest.date() - now.date()).days

        if code not in self._license_state:
            self._license_state[code] = {
                "info_sent_date": None,
                "warning_sent_date": None,
                "critical_sent_date": None,
            }
            self._mark_state_dirty()

        state = self._license_state[code]

        self.logger.debug(
            "Licença de %s expira em %d dias (data %s)", env_label, days_until, soonest.date()
        )

        send_time = time(0, 0) if force_send else self._license_send_time
        send_dt = datetime.combine(now.date(), send_time)

        if days_until <= 15:
            last_sent = state.get("critical_sent_date")
            if (force_send or now >= send_dt) and last_sent != now.date():
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Data de expiração", "value": soonest.strftime("%d/%m/%Y")},
                    {"title": "Dias restantes", "value": str(days_until)},
                )
                self._send_alert(
                    "Licença próxima da expiração",
                    message,
                    severity="critical",
                    summary=env_label,
                    facts=facts,
                    category="license",
                    detected_at=now,
                    env_code=code,
                )
                state["critical_sent_date"] = now.date()
                state["info_sent_date"] = state.get("info_sent_date") or now.date()
                state["warning_sent_date"] = state.get("warning_sent_date") or now.date()
                self._mark_state_dirty()
        elif days_until <= 30:
            if state.get("critical_sent_date") is not None:
                state["critical_sent_date"] = None
                self._mark_state_dirty()
            last_sent = state.get("warning_sent_date")
            if (force_send or now >= send_dt) and (
                last_sent is None or (now.date() - last_sent).days >= 2
            ):
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Data de expiração", "value": soonest.strftime("%d/%m/%Y")},
                    {"title": "Dias restantes", "value": str(days_until)},
                )
                self._send_alert(
                    "Licença próxima da expiração",
                    message,
                    severity="warning",
                    summary=env_label,
                    facts=facts,
                    category="license",
                    detected_at=now,
                    env_code=code,
                )
                state["warning_sent_date"] = now.date()
                self._mark_state_dirty()
        elif days_until <= 45:
            if state.get("critical_sent_date") is not None:
                state["critical_sent_date"] = None
                self._mark_state_dirty()
            last_sent = state.get("info_sent_date")
            if (force_send or now >= send_dt) and (
                last_sent is None or (now.date() - last_sent).days >= 7
            ):
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Data de expiração", "value": soonest.strftime("%d/%m/%Y")},
                    {"title": "Dias restantes", "value": str(days_until)},
                )
                self._send_alert(
                    "Licença próxima da expiração",
                    message,
                    severity="normal",
                    summary=env_label,
                    facts=facts,
                    category="license",
                    detected_at=now,
                    env_code=code,
                )
                state["info_sent_date"] = now.date()
                self._mark_state_dirty()
        else:
            if code in self._license_state:
                self._license_state.pop(code, None)
                self._mark_state_dirty()

    def _check_crowdstrike_ingestion_license_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime, *, force_send: bool
    ) -> None:
        siem_value = str(row.get("siem") or "").strip().lower()
        if "crowdstrike" not in siem_value:
            self._crowdstrike_license_state.pop(code, None)
            return

        license_gb = _parse_float(row.get("license_gb_day"))
        ingestion_gb = _parse_float(row.get("total_gb_one_day_decimal"))

        if not license_gb or license_gb <= 0 or ingestion_gb is None:
            self._crowdstrike_license_state.pop(code, None)
            return

        if code not in self._crowdstrike_license_state:
            self._crowdstrike_license_state[code] = {"last_sent_date": None}
            self._mark_state_dirty()

        state = self._crowdstrike_license_state[code]

        if ingestion_gb > license_gb:
            last_sent = state.get("last_sent_date")
            if force_send or last_sent != now.date():
                message = (
                    f"{env_label}: ingestão de 24h ({ingestion_gb:.2f} GB) excede a licença "
                    f"contratada ({license_gb:.2f} GB/dia)."
                )
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Ingestão 24h", "value": f"{ingestion_gb:.2f} GB"},
                    {"title": "Licença", "value": f"{license_gb:.2f} GB/dia"},
                    {"title": "Excedente", "value": f"{(ingestion_gb - license_gb):.2f} GB"},
                )
                self._send_alert(
                    "Ingestão acima da licença (Crowdstrike)",
                    message,
                    severity="critical",
                    summary=env_label,
                    facts=facts,
                    category="crowdstrike_license",
                    detected_at=now,
                    env_code=code,
                )
                state["last_sent_date"] = now.date()
                self._mark_state_dirty()
        else:
            if code in self._crowdstrike_license_state:
                self._crowdstrike_license_state.pop(code, None)
                self._mark_state_dirty()

    def _process_health_alerts(
        self, health: Dict[str, Any], now: datetime, *, force_send: bool = False
    ) -> None:
        rows = health.get("rows") or []
        self.logger.debug("Processando %d registros de saúde", len(rows))

        for row in rows:
            env_label = self._env_label(row)
            code = row.get("code") or env_label
            self.logger.debug(
                "Processando saúde | ambiente=%s codigo=%s serviços=%d conectividade=%d",
                env_label,
                code,
                len(row.get("services") or []),
                len(row.get("connectivity") or []),
            )

            self._check_postfix_alert(row, env_label, code, now, force_send=force_send)
            self._check_offense_alert(row, env_label, code, now, force_send=force_send)
            self._check_connectivity_alert(row, env_label, code, now, force_send=force_send)

    def _check_postfix_alert(
        self,
        row: Dict[str, Any],
        env_label: str,
        code: str,
        now: datetime,
        *,
        force_send: bool = False,
    ) -> None:
        if self._is_suppressed(code, "postfix", env_label=env_label):
            self.logger.debug("Alerta de postfix suprimido para %s", env_label)
            return
        services = row.get("services") or []
        postfix_entry = next((svc for svc in services if (svc.get("name") or "").endswith("postfix.service")), None)
        if postfix_entry:
            status = str(postfix_entry.get("status") or "").lower()
            if status != "active":
                confirmation_key = f"postfix:{code}"
                if force_send:
                    confirmed = not self._postfix_state.get(code)
                else:
                    confirmed = self._should_confirm_alert(confirmation_key, True, now)
                if confirmed:
                    message = f"{env_label}: serviço postfix está inativo (status: {status or 'desconhecido'})."
                    facts = (
                        {"title": "Ambiente", "value": env_label},
                        {"title": "Status", "value": status or "desconhecido"},
                    )
                    self._send_alert(
                        "Postfix indisponível",
                        message,
                        severity="critical",
                        summary=env_label,
                        facts=facts,
                        category="email",
                        detected_at=now,
                        env_code=code,
                        component="postfix",
                    )
                    self._postfix_state[code] = True
                    self._mark_state_dirty()
                elif self._postfix_state.get(code):
                    self.logger.debug("Alerta de postfix já enviado para %s", env_label)
            else:
                self._should_confirm_alert(f"postfix:{code}", False, now)
                if code in self._postfix_state:
                    self._postfix_state.pop(code, None)
                    self._mark_state_dirty()

    def _check_offense_alert(
        self,
        row: Dict[str, Any],
        env_label: str,
        code: str,
        now: datetime,
        *,
        force_send: bool = False,
    ) -> None:
        if self._is_suppressed(code, "offense", env_label=env_label):
            self.logger.debug("Alerta de offense suprimido para %s", env_label)
            return
        offense_check = row.get("offense_check") or {}
        status = str(offense_check.get("status") or "").lower()
        count = offense_check.get("count")
        if status != "ok" or (isinstance(count, int) and count == 0):
            confirmation_key = f"offense:{code}"
            if force_send:
                confirmed = not self._offense_state.get(code)
            else:
                confirmed = self._should_confirm_alert(confirmation_key, True, now)
            if confirmed:
                message = f"{env_label}: nenhuma ofensa registrada nas últimas 24 horas."
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Status", "value": status or "desconhecido"},
                    {"title": "Ofensas nas últimas 24h", "value": str(count) if count is not None else "0"},
                )
                self._send_alert(
                    "Ausência de ofensas",
                    message,
                    severity="critical",
                    summary=env_label,
                    facts=facts,
                    category="offense",
                    detected_at=now,
                    env_code=code,
                    component="offense",
                )
                self._offense_state[code] = True
                self._mark_state_dirty()
            elif self._offense_state.get(code):
                self.logger.debug("Alerta de ofensas já enviado para %s", env_label)
        else:
            self._should_confirm_alert(f"offense:{code}", False, now)
            if code in self._offense_state:
                self._offense_state.pop(code, None)
                self._mark_state_dirty()

    def _check_connectivity_alert(
        self,
        row: Dict[str, Any],
        env_label: str,
        code: str,
        now: datetime,
        *,
        force_send: bool = False,
    ) -> None:
        connectivity = row.get("connectivity") or []
        for entry in connectivity:
            target = entry.get("target") or entry.get("name") or "Appliance"
            reachable = entry.get("reachable")
            status = str(entry.get("status") or "").lower()
            key = (code, target)

            if reachable is False or status in {"error", "critical", "failed"}:
                if self._is_suppressed(code, "connectivity", target, env_label=env_label):
                    self.logger.debug(
                        "Alerta de conectividade suprimido para %s -> %s", env_label, target
                    )
                    continue
                confirmation_key = f"connectivity:{code}:{target}"
                if force_send:
                    confirmed = not self._connectivity_state.get(key)
                else:
                    confirmed = self._should_confirm_alert(confirmation_key, True, now)
                if confirmed:
                    message = f"{env_label}: perda de comunicação com {target}."
                    facts = (
                        {"title": "Ambiente", "value": env_label},
                        {"title": "Destino", "value": target},
                        {"title": "Status", "value": status or "desconhecido"},
                    )
                    self._send_alert(
                        "Falha de conectividade",
                        message,
                        severity="critical",
                        summary=f"{env_label} - {target}",
                        facts=facts,
                        category="connectivity",
                        detected_at=now,
                        env_code=code,
                        component=target,
                    )
                    self._connectivity_state[key] = True
                    self._mark_state_dirty()
                elif self._connectivity_state.get(key):
                    self.logger.debug(
                        "Alerta de conectividade já enviado para %s -> %s", env_label, target
                    )
            else:
                self._should_confirm_alert(f"connectivity:{code}:{target}", False, now)
                if key in self._connectivity_state:
                    self._connectivity_state.pop(key, None)
                    self._mark_state_dirty()

    def _process_url_alerts(self, now: datetime, *, force_send: bool = False) -> None:
        if not self._url_checks:
            self.logger.debug("Nenhuma URL configurada para monitoramento.")
            return

        self.logger.debug("Iniciando verificação de %d URLs monitoradas", len(self._url_checks))
        for entry in self._url_checks:
            name = entry.get("name") or "URL monitorada"
            url = entry.get("url")
            timeout = self._parse_timeout_value(entry.get("timeout")) or self._url_timeout
            timeout_label = self._format_timeout_value(timeout)
            attempts = self._url_retry_attempts

            if not url:
                continue

            status_label = None
            error_message = None
            failed = False

            self.logger.info(
                "Validando URL monitorada | destino=%s url=%s timeout=%s (verify=False) tentativas=%s",
                name,
                url,
                timeout_label,
                attempts,
            )

            for attempt in range(1, attempts + 1):
                try:
                    response = requests.get(url, timeout=timeout, verify=False)
                    status_label = f"HTTP {response.status_code}"
                    if response.status_code >= 400:
                        failed = True
                        error_message = f"Resposta HTTP {response.status_code}"
                    else:
                        failed = False
                    break
                except RequestException as exc:
                    failed = True
                    error_message = f"{exc.__class__.__name__}: {exc}"

                    if attempt < attempts:
                        self.logger.info(
                            "Tentativa %s/%s falhou para URL monitorada | destino=%s url=%s erro=%s. Repetindo em %ss",
                            attempt,
                            attempts,
                            name,
                            url,
                            error_message,
                            self._url_retry_backoff,
                        )
                        if self._url_retry_backoff:
                            time_module.sleep(self._url_retry_backoff)
                        continue

            key = str(url)

            confirmation_key = f"url:{key}"

            if failed:
                self.logger.warning(
                    "URL monitorada indisponível | destino=%s url=%s status=%s",
                    name,
                    url,
                    error_message or status_label or "indisponível",
                )
                if force_send:
                    confirmed = not self._url_state.get(key)
                else:
                    confirmed = self._should_confirm_alert(confirmation_key, True, now)
                if confirmed:
                    message = f"{name}: falha ao acessar URL monitorada."
                    facts = (
                        {"title": "Destino", "value": name},
                        {"title": "URL", "value": url},
                        {
                            "title": "Status",
                            "value": error_message or status_label or "indisponível",
                        },
                    )
                    self._send_alert(
                        "Falha ao acessar URL",
                        message,
                        severity="critical",
                        summary=name,
                        facts=facts,
                        category="url",
                        detected_at=now,
                        component=url,
                    )
                    self._url_state[key] = True
                    self._mark_state_dirty()
            else:
                self.logger.info(
                    "URL monitorada acessível | destino=%s url=%s status=%s",
                    name,
                    url,
                    status_label or "OK",
                )
                self._should_confirm_alert(confirmation_key, False, now)
                if key in self._url_state:
                    self._url_state.pop(key, None)
                    self._mark_state_dirty()

    def _process_jira_alerts(self, now: datetime, *, force_send: bool = False) -> None:
        if not self._jira_config:
            self.logger.debug("Configuração de Jira ausente. Ignorando verificação.")
            return

        if not self._jira_webhook_url:
            self.logger.debug(
                "Webhook dedicado do Teams para alertas do Jira não configurado. Ignorando verificação."
            )
            return

        if not self._jira_clients:
            self.logger.debug("Nenhum cliente configurado para monitoramento do Jira.")
            return

        allowed_hours = {7, 19}
        if not force_send and now.hour not in allowed_hours:
            self.logger.debug(
                "Hora atual (%sh) fora da janela de verificação do Jira %s.",
                now.hour,
                sorted(allowed_hours),
            )
            return

        dispatch_key = (now.date(), now.hour)
        if not force_send and self._jira_last_dispatch == dispatch_key:
            self.logger.debug(
                "Verificação de Jira já executada para %s %sh. Pulando envio duplicado.",
                now.date(),
                now.hour,
            )
            return

        self.logger.info(
            "Iniciando verificação de alertas do Jira | force_send=%s clientes=%d janela=%sh/%sh",
            force_send,
            len(self._jira_clients),
            self._jira_warning_hours,
            self._jira_critical_hours,
        )
        jira_client = JiraClient(self._jira_config, logger=self.logger)
        last_seen_map = jira_client.last_issue_by_client(
            self._jira_clients, window_hours=self._jira_critical_hours
        )
        self.logger.debug(
            "Dados de últimos tickets do Jira coletados | clientes_com_resultado=%d",
            len(last_seen_map),
        )

        now_utc = datetime.now(timezone.utc)

        for client in self._jira_clients:
            last_seen = last_seen_map.get(client)
            severity: Optional[str] = None
            hours_without: Optional[float] = None

            if last_seen is None:
                severity = "critical"
            else:
                delta = now_utc - last_seen
                hours_without = delta.total_seconds() / 3600
                if hours_without >= self._jira_critical_hours:
                    severity = "critical"
                elif hours_without >= self._jira_warning_hours:
                    severity = "warning"

            previous = self._jira_state.get(client)
            if severity:
                self.logger.debug(
                    "Cliente %s sem tickets | severidade=%s horas_sem=%s ultimo=%s",
                    client,
                    severity,
                    f"{hours_without:.1f}" if hours_without is not None else "n/d",
                    last_seen.isoformat() if last_seen else "n/a",
                )
                if force_send or previous != severity:
                    last_ticket_text = (
                        last_seen.strftime("%d/%m/%Y %H:%M:%S UTC")
                        if last_seen
                        else f"Nenhum ticket em {self._jira_critical_hours}h"
                    )
                    hours_text = (
                        f"{hours_without:.1f}h" if hours_without is not None else f">= {self._jira_critical_hours}h"
                    )
                    facts = (
                        {"title": "Cliente", "value": client},
                        {"title": "Último ticket", "value": last_ticket_text},
                        {"title": "Tempo sem tickets", "value": hours_text},
                    )
                    message = (
                        f"Cliente {client} está sem abertura de tickets há {hours_text}. "
                        "Verifique a ingestão de incidentes no Jira."
                    )
                    self._send_alert(
                        "Inatividade de tickets no Jira",
                        message,
                        severity=severity,
                        summary=client,
                        facts=facts,
                        category="jira",
                        detected_at=now_utc,
                        env_code=client,
                        component="jira-tickets",
                    )
                    self._jira_state[client] = severity
                    self._mark_state_dirty()
                else:
                    self.logger.debug(
                        "Alerta Jira já enviado para cliente=%s com severidade=%s", client, severity
                    )
            else:
                if previous:
                    self.logger.info(
                        "Cliente %s voltou a criar tickets dentro do prazo. Limpando estado de alerta do Jira.",
                        client,
                    )
                if client in self._jira_state:
                    self._jira_state.pop(client, None)
                    self._mark_state_dirty()

        self._jira_last_dispatch = dispatch_key
        self._mark_state_dirty()

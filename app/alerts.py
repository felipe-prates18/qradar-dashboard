import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Optional, Tuple

import requests


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
        self.logger = logger or logging.getLogger(__name__)
        alerts_conf = config.get("alerts", {}) or {}
        self.webhook_url = (
            alerts_conf.get("teams_webhook_url")
            or alerts_conf.get("teams_webhook")
            or alerts_conf.get("webhook")
        )
        self.interval = int(alerts_conf.get("interval_seconds", 600))
        if self.interval < 60:
            self.interval = 60

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self._resource_state: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self._storage_alerts: Dict[Tuple[str, str, str], bool] = {}
        self._eps_state: Dict[str, Dict[str, Any]] = {}
        self._license_state: Dict[str, Dict[str, Any]] = {}
        self._email_state: Dict[str, bool] = {}
        self._postfix_state: Dict[str, bool] = {}
        self._offense_state: Dict[str, bool] = {}
        self._connectivity_state: Dict[Tuple[str, str], bool] = {}

        self._env_labels: Dict[str, str] = {}
        for env in config.get("qradar_envs", []):
            code = env.get("codigo") or env.get("code")
            name = env.get("name") or env.get("host") or "Ambiente"
            if code:
                self._env_labels[code] = f"{name} ({code})"
            else:
                self._env_labels[name] = name

    async def start(self) -> None:
        if self._task is not None:
            return
        if not self.webhook_url:
            self.logger.warning("Webhook do Microsoft Teams não configurado. Sistema de alertas inativo.")
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
            wait_seconds = max(0, self.interval - elapsed)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=wait_seconds)
            except asyncio.TimeoutError:
                continue

    def _perform_checks(self) -> None:
        now = datetime.utcnow()
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
                self._process_monitoring_alerts(monitoring, now)
            else:
                self.logger.info("Dados de monitoramento vazios recebidos para alertas")
        else:
            self.logger.warning("Falha ao obter dados de monitoramento para alertas")

        if health is not None:
            if health:
                self._process_health_alerts(health, now)
            else:
                self.logger.info("Dados de saúde vazios recebidos para alertas")
        else:
            self.logger.warning("Falha ao obter dados de saúde para alertas")
        if monitoring is None and health is None:
            self.logger.warning("Nenhum dado disponível para avaliação de alertas")

    def _env_label(self, row: Dict[str, Any]) -> str:
        code = row.get("code")
        name = row.get("name") or row.get("host") or "Ambiente"
        if code and code in self._env_labels:
            return self._env_labels[code]
        if code:
            return f"{name} ({code})"
        return name

    def _send_alert(self, title: str, message: str, severity: str = "normal") -> None:
        self.logger.info(
            "Preparando envio de alerta | titulo='%s' severidade='%s'", title, severity
        )

        card_payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": {
                "normal": "2F8DEE",
                "warning": "FFA500",
                "critical": "D13438",
            }.get(severity, "2F8DEE"),
            "title": title,
            "text": f"**Severidade:** {severity.upper()}<br>{message}",
        }
        payload = {
            "MessageCard": card_payload,
            "Severity": severity,
            "Title": title,
        }
        headers = {"Content-Type": "application/json"}
        body = json.dumps(payload, ensure_ascii=False)
        try:
            self.logger.debug(
                "Enviando webhook para o Microsoft Teams | headers=%s payload=%s",
                headers,
                body,
            )
            response = requests.post(
                self.webhook_url,
                headers=headers,
                data=body.encode("utf-8"),
                timeout=10,
            )
            self.logger.debug(
                "Resposta do webhook do Teams | status=%s corpo=%s",
                getattr(response, "status_code", "desconhecido"),
                (response.text[:1000] if getattr(response, "text", None) else ""),
            )
            response.raise_for_status()
            self.logger.info("Alerta enviado com sucesso: %s", title)
        except requests.RequestException as exc:
            resp = getattr(exc, "response", None)
            if resp is not None:
                body = resp.text[:1000] if getattr(resp, "text", None) else ""
                self.logger.exception(
                    "Falha ao enviar alerta para o Microsoft Teams | status=%s corpo=%s",
                    resp.status_code,
                    body,
                )
            else:
                self.logger.exception(
                    "Falha ao enviar alerta para o Microsoft Teams sem resposta HTTP"
                )
        except Exception:
            self.logger.exception("Falha inesperada ao enviar alerta para o Microsoft Teams")

    def _process_monitoring_alerts(self, monitoring: Dict[str, Any], now: datetime) -> None:
        rows = monitoring.get("rows") or []
        self.logger.debug("Processando %d registros de monitoramento", len(rows))
        for row in rows:
            env_label = self._env_label(row)
            code = row.get("code") or env_label

            self._check_usage_alerts(env_label, code, "Console", row, now)

            appliances = row.get("appliances") or []
            for appliance in appliances:
                component = appliance.get("name") or appliance.get("zabbix_host") or "Appliance"
                self._check_usage_alerts(env_label, code, component, appliance, now)

            self._check_eps_alert(row, env_label, code, now)
            self._check_license_alert(row, env_label, code, now)

    def _check_usage_alerts(
        self,
        env_label: str,
        code: str,
        component: str,
        metrics_container: Dict[str, Any],
        now: datetime,
    ) -> None:
        for metric_key in ("cpu", "memory", "storage"):
            percent = _parse_percent(metrics_container.get(metric_key))
            severity = _severity_by_percent(percent)
            key = (code, component, metric_key)

            if severity == "critical":
                state = self._resource_state.setdefault(key, {"first_seen": now, "alert_sent": False})
                if state.get("first_seen") is None:
                    state["first_seen"] = now
                if not state.get("alert_sent") and now - state["first_seen"] >= timedelta(hours=1):
                    message = (
                        f"{env_label} - {component}: consumo crítico de {metric_key.upper()} "
                        f"por mais de 1 hora ({percent:.1f}%)."
                    )
                    self._send_alert("Consumo crítico prolongado", message, severity="critical")
                    state["alert_sent"] = True
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
                self._resource_state.pop(key, None)

            if metric_key == "storage":
                if percent is not None and percent >= 90:
                    if not self._storage_alerts.get(key):
                        message = (
                            f"{env_label} - {component}: armazenamento atingiu {percent:.1f}% de uso."
                        )
                        self._send_alert("Armazenamento crítico", message, severity="critical")
                        self._storage_alerts[key] = True
                    else:
                        self.logger.debug(
                            "Alerta de armazenamento já enviado para %s/%s (%s%%)",
                            env_label,
                            component,
                            percent,
                        )
                else:
                    self._storage_alerts.pop(key, None)

            if severity != "critical":
                # Reset the first seen timestamp if the metric returned to normal levels.
                if key in self._resource_state:
                    self._resource_state[key]["first_seen"] = None
                    self._resource_state[key]["alert_sent"] = False

    def _check_eps_alert(self, row: Dict[str, Any], env_label: str, code: str, now: datetime) -> None:
        license_eps = _parse_int(row.get("license_eps"))
        eps_current = _parse_int(row.get("eps_current"))
        if not license_eps or license_eps <= 0 or eps_current is None:
            self._eps_state.pop(code, None)
            return

        state = self._eps_state.setdefault(
            code,
            {"first_exceeded": None, "last_sent_date": None},
        )

        if eps_current > license_eps:
            if state.get("first_exceeded") is None:
                state["first_exceeded"] = now
            if now - state["first_exceeded"] >= timedelta(hours=24):
                last_sent = state.get("last_sent_date")
                if last_sent != now.date():
                    message = (
                        f"{env_label}: EPS atual ({eps_current}) excede o limite de licença ({license_eps}) "
                        "há mais de 24 horas."
                    )
                    self._send_alert("EPS acima do licenciado", message, severity="critical")
                    state["last_sent_date"] = now.date()
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
            self._eps_state.pop(code, None)

    def _check_license_alert(self, row: Dict[str, Any], env_label: str, code: str, now: datetime) -> None:
        expirations = row.get("license_exp_list") or []
        if not expirations and row.get("license_exp"):
            expirations = [row.get("license_exp")]

        dates = [dt for dt in (_parse_expiration(item) for item in expirations) if dt is not None]
        if not dates:
            self._license_state.pop(code, None)
            return

        soonest = min(dates)
        days_until = (soonest.date() - now.date()).days

        state = self._license_state.setdefault(
            code,
            {"info_sent": False, "warning_sent": False, "critical_date": None},
        )

        self.logger.debug(
            "Licença de %s expira em %d dias (data %s)", env_label, days_until, soonest.date()
        )

        if days_until <= 15:
            last_sent = state.get("critical_date")
            if last_sent != now.date():
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                self._send_alert("Licença próxima da expiração", message, severity="critical")
                state["critical_date"] = now.date()
                state["info_sent"] = True
                state["warning_sent"] = True
        elif days_until <= 30:
            if not state.get("warning_sent"):
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                self._send_alert("Licença próxima da expiração", message, severity="warning")
                state["warning_sent"] = True
        elif days_until <= 45:
            if not state.get("info_sent"):
                message = (
                    f"{env_label}: licença expira em {days_until} dia(s) (data {soonest.date():%d/%m/%Y})."
                )
                self._send_alert("Licença próxima da expiração", message, severity="normal")
                state["info_sent"] = True
        else:
            self._license_state.pop(code, None)

    def _process_health_alerts(self, health: Dict[str, Any], now: datetime) -> None:
        rows = health.get("rows") or []
        self.logger.debug("Processando %d registros de saúde", len(rows))

        for row in rows:
            env_label = self._env_label(row)
            code = row.get("code") or env_label

            self._check_email_alert(row, env_label, code)
            self._check_postfix_alert(row, env_label, code)
            self._check_offense_alert(row, env_label, code)
            self._check_connectivity_alert(row, env_label, code)

    def _check_email_alert(self, row: Dict[str, Any], env_label: str, code: str) -> None:
        email_check = row.get("email_check") or {}
        status = str(email_check.get("status") or "").lower()
        if status in {"error", "critical", "failed", "missing"}:
            if not self._email_state.get(code):
                message = f"{env_label}: sem envios de e-mail nas últimas 24 horas ou verificação com erro."
                self._send_alert("Falha no envio de e-mails", message, severity="critical")
                self._email_state[code] = True
            else:
                self.logger.debug("Alerta de e-mail já enviado para %s", env_label)
        else:
            self._email_state.pop(code, None)

    def _check_postfix_alert(self, row: Dict[str, Any], env_label: str, code: str) -> None:
        services = row.get("services") or []
        postfix_entry = next((svc for svc in services if (svc.get("name") or "").endswith("postfix.service")), None)
        if postfix_entry:
            status = str(postfix_entry.get("status") or "").lower()
            if status != "active":
                if not self._postfix_state.get(code):
                    message = f"{env_label}: serviço postfix está inativo (status: {status or 'desconhecido'})."
                    self._send_alert("Postfix indisponível", message, severity="critical")
                    self._postfix_state[code] = True
                else:
                    self.logger.debug("Alerta de postfix já enviado para %s", env_label)
            else:
                self._postfix_state.pop(code, None)

    def _check_offense_alert(self, row: Dict[str, Any], env_label: str, code: str) -> None:
        offense_check = row.get("offense_check") or {}
        status = str(offense_check.get("status") or "").lower()
        count = offense_check.get("count")
        if status != "ok" or (isinstance(count, int) and count == 0):
            if not self._offense_state.get(code):
                message = f"{env_label}: nenhuma ofensa registrada nas últimas 24 horas."
                self._send_alert("Ausência de ofensas", message, severity="critical")
                self._offense_state[code] = True
            else:
                self.logger.debug("Alerta de ofensas já enviado para %s", env_label)
        else:
            self._offense_state.pop(code, None)

    def _check_connectivity_alert(self, row: Dict[str, Any], env_label: str, code: str) -> None:
        connectivity = row.get("connectivity") or []
        for entry in connectivity:
            target = entry.get("target") or entry.get("name") or "Appliance"
            reachable = entry.get("reachable")
            status = str(entry.get("status") or "").lower()
            key = (code, target)

            if reachable is False or status in {"error", "critical", "failed"}:
                if not self._connectivity_state.get(key):
                    message = f"{env_label}: perda de comunicação com {target}."
                    self._send_alert("Falha de conectividade", message, severity="critical")
                    self._connectivity_state[key] = True
                else:
                    self.logger.debug(
                        "Alerta de conectividade já enviado para %s -> %s", env_label, target
                    )
            else:
                self._connectivity_state.pop(key, None)

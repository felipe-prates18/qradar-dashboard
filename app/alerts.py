import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
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
        self.license_webhook_url = alerts_conf.get("license_teams_webhook_url")
        self.interval = int(alerts_conf.get("interval_seconds", 600))
        if self.interval < 60:
            self.interval = 60

        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

        self.dashboard_url_template = alerts_conf.get("dashboard_url_template")
        self.dashboard_url_base = (
            alerts_conf.get("dashboard_url")
            or alerts_conf.get("dashboard_base_url")
            or "http://172.31.1.253:8000/login"
        )

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

        targets = [("principal", self.webhook_url)] if self.webhook_url else []
        if category == "license" and self.license_webhook_url:
            targets.append(("licenca", self.license_webhook_url))

        if not targets:
            self.logger.warning("Nenhum webhook configurado para envio do alerta '%s'", title)
            return

        try:
            for label, url in targets:
                try:
                    self.logger.debug(
                        "Enviando webhook (%s) para o Microsoft Teams | headers=%s payload=%s",
                        label,
                        headers,
                        body,
                    )
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
                            "Falha ao enviar alerta para o Microsoft Teams (%s) sem resposta HTTP",
                            label,
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
                state["critical_date"] = now.date()
                state["info_sent"] = True
                state["warning_sent"] = True
        elif days_until <= 30:
            if not state.get("warning_sent"):
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
                state["warning_sent"] = True
        elif days_until <= 45:
            if not state.get("info_sent"):
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
                state["info_sent"] = True
        else:
            self._license_state.pop(code, None)

    def _process_health_alerts(self, health: Dict[str, Any], now: datetime) -> None:
        rows = health.get("rows") or []
        self.logger.debug("Processando %d registros de saúde", len(rows))

        for row in rows:
            env_label = self._env_label(row)
            code = row.get("code") or env_label

            self._check_email_alert(row, env_label, code, now)
            self._check_postfix_alert(row, env_label, code, now)
            self._check_offense_alert(row, env_label, code, now)
            self._check_connectivity_alert(row, env_label, code, now)

    def _check_email_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime
    ) -> None:
        email_check = row.get("email_check") or {}
        status = str(email_check.get("status") or "").lower()
        if status in {"error", "critical", "failed", "missing"}:
            if not self._email_state.get(code):
                message = f"{env_label}: sem envios de e-mail nas últimas 24 horas ou verificação com erro."
                facts = (
                    {"title": "Ambiente", "value": env_label},
                    {"title": "Status", "value": status or "desconhecido"},
                )
                self._send_alert(
                    "Falha no envio de e-mails",
                    message,
                    severity="critical",
                    summary=env_label,
                    facts=facts,
                    category="email",
                    detected_at=now,
                    env_code=code,
                    component="email",
                )
                self._email_state[code] = True
            else:
                self.logger.debug("Alerta de e-mail já enviado para %s", env_label)
        else:
            self._email_state.pop(code, None)

    def _check_postfix_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime
    ) -> None:
        services = row.get("services") or []
        postfix_entry = next((svc for svc in services if (svc.get("name") or "").endswith("postfix.service")), None)
        if postfix_entry:
            status = str(postfix_entry.get("status") or "").lower()
            if status != "active":
                if not self._postfix_state.get(code):
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
                else:
                    self.logger.debug("Alerta de postfix já enviado para %s", env_label)
            else:
                self._postfix_state.pop(code, None)

    def _check_offense_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime
    ) -> None:
        offense_check = row.get("offense_check") or {}
        status = str(offense_check.get("status") or "").lower()
        count = offense_check.get("count")
        if status != "ok" or (isinstance(count, int) and count == 0):
            if not self._offense_state.get(code):
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
            else:
                self.logger.debug("Alerta de ofensas já enviado para %s", env_label)
        else:
            self._offense_state.pop(code, None)

    def _check_connectivity_alert(
        self, row: Dict[str, Any], env_label: str, code: str, now: datetime
    ) -> None:
        connectivity = row.get("connectivity") or []
        for entry in connectivity:
            target = entry.get("target") or entry.get("name") or "Appliance"
            reachable = entry.get("reachable")
            status = str(entry.get("status") or "").lower()
            key = (code, target)

            if reachable is False or status in {"error", "critical", "failed"}:
                if not self._connectivity_state.get(key):
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
                else:
                    self.logger.debug(
                        "Alerta de conectividade já enviado para %s -> %s", env_label, target
                    )
            else:
                self._connectivity_state.pop(key, None)

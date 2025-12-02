import re
from datetime import datetime
import paramiko
import logging
import shlex

logger = logging.getLogger(__name__)

class SSHClient:
    def __init__(self):
        pass

    def _connect(self, host, user, key_path):
        try:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                username=user,
                pkey=key,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
            )
            logger.info("Autenticação SSH bem-sucedida host=%s user=%s", host, user)
            return client
        except Exception as exc:
            logger.error("Falha na autenticação SSH host=%s user=%s: %s", host, user, exc)
            raise

    def _summarize_for_log(self, text, max_chars=400):
        if not text:
            return ""
        cleaned = text.replace("\n", "\\n")
        if len(cleaned) <= max_chars:
            return cleaned
        trimmed = cleaned[:max_chars]
        remainder = len(cleaned) - max_chars
        return f"{trimmed}… (+{remainder} chars)"

    def _exec(self, client, cmd, *, max_output_chars=400):
        logger.debug("SSH exec: %s", cmd)
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        summary_out = self._summarize_for_log(out, max_output_chars)
        summary_err = self._summarize_for_log(err, max_output_chars)
        logger.info(
            "SSH exit=%s stdout='%s' stderr='%s'",
            code,
            summary_out,
            summary_err,
        )
        return code, out, err

    def connect_env(self, env):
        host = env.get("host")
        user = env.get("ssh_user")
        key_path = env.get("ssh_key")

        if not host or not user or not key_path:
            raise ValueError("Configuração SSH incompleta para o ambiente")

        return self._connect(host, user, key_path)

    def _format_date(self, raw):
        try:
            if len(raw) >= 8:
                y = raw[0:4]
                m = raw[4:6]
                d = raw[6:8]
                return f"{d}/{m}/{y}"
            return raw
        except Exception:
            return raw

    def _expiration_sort_key(self, value):
        if isinstance(value, str):
            m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", value)
            if m:
                day, month, year = m.groups()
                try:
                    return (int(year), int(month), int(day))
                except Exception:
                    pass
        return (9999, value or "")

    def read_license(self, env):
        host = env.get("host")
        user = env.get("ssh_user")
        key_path = env.get("ssh_key")

        eps_total = 0
        exp_primary = "Erro"
        license_parts = []
        pending_expirations = []
        has_eps_limit = False

        cmd_license = r"/opt/qradar/bin/license.sh all 2>/dev/null"

        try:
            c = self._connect(host, user, key_path)
            code, out, _ = self._exec(c, f"bash -lc {shlex.quote(cmd_license)}")
            c.close()

            token_pairs = []
            for raw in re.findall(r"[^\s]+=[^\s]+", out or ""):
                if "=" not in raw:
                    continue
                k, v = raw.split("=", 1)
                token_pairs.append((k.strip(), v.strip()))

            def _attach_expiration(formatted):
                for part in reversed(license_parts):
                    if not part.get("expires"):
                        part["expires"] = formatted
                        return True
                return False

            limit_keys = {
                "EPS_LIMIT": True,
                "nonConsoleEventLimit": True,
                # consoleEventLimit is informational for breakdown, but we don't add it to the EPS sum
                "consoleEventLimit": False,
            }

            for key, value in token_pairs:
                if key in limit_keys:
                    limit_int = None
                    try:
                        limit_int = int(value)
                    except Exception:
                        limit_int = None

                    if limit_int is not None and limit_keys[key]:
                        eps_total += limit_int
                        has_eps_limit = True

                    part = {
                        "kind": key,
                        "limit": str(limit_int if limit_int is not None else value),
                        "expires": None,
                    }
                    if pending_expirations:
                        part["expires"] = pending_expirations.pop(0)
                    license_parts.append(part)
                    continue

                if key == "licenseExpiration":
                    formatted = self._format_date(value)
                    if not _attach_expiration(formatted):
                        pending_expirations.append(formatted)
                    continue

            # Attach any expirations that arrived without a matching license block
            for exp in pending_expirations:
                license_parts.append({
                    "kind": "licenseExpiration",
                    "limit": "—",
                    "expires": exp,
                })

            exp_list = [p.get("expires") for p in license_parts if p.get("expires")]
            if exp_list:
                # Remove duplicates before sorting the expirations chronologically
                seen = set()
                unique = []
                for item in exp_list:
                    if item not in seen:
                        unique.append(item)
                        seen.add(item)
                exp_list = sorted(unique, key=self._expiration_sort_key)
                exp_primary = exp_list[0]

            eps_display = "Erro"
            if has_eps_limit:
                eps_display = str(eps_total)

            logger.info(
                "Licença coletada host=%s eps_total=%s expiracoes=%s",
                host,
                eps_display,
                ",".join(exp_list) if exp_list else "nenhuma",
            )

            return {
                "license_eps": eps_display,
                "license_expiration": exp_primary,
                "license_expiration_list": exp_list,
                "license_breakdown": license_parts,
            }

        except Exception as e:
            logger.error(f"Falha na coleta de licença em {host}: {e}")
            return {
                "license_eps": "Erro",
                "license_expiration": "Erro",
                "license_expiration_list": [],
                "license_breakdown": [],
            }

    def _jmx_parse_cmd(self, bean, port):
        return (
            f"""/opt/qradar/support/jmx.sh -p {port} -b '{bean}' 2>/dev/null | """
            """awk -F'[=:]' '"""
            """/[Ee][Vv][Ee][Nn][Tt][Rr][Aa][Tt][Ee]/{gsub(/^ +| +$/,"",$2); er=$2} """
            """/EventLongWindowAverage|LongWindowAverage|Event Long Window Average/{gsub(/^ +| +$/,"",$2); mx=$2} """
            """END{if(er!="")print er; if(mx!="")print mx}'"""
        )

    def _jmx_discover_bean(self, client, port, hint_name):
        name_hint = ""
        if hint_name and "name=" in hint_name:
            try:
                name_hint = hint_name.split("name=", 1)[1]
            except Exception:
                name_hint = ""
        grep_pat = name_hint if name_hint else "Source Monitor"
        cmd_list = f"""/opt/qradar/support/jmx.sh -p {port} -l 2>/dev/null | grep -i {shlex.quote(grep_pat)} | head -n1"""
        code, out, _ = self._exec(client, f"bash -lc {shlex.quote(cmd_list)}")
        bean = out.strip()
        return bean

    def read_eps(self, env):
        port = str(env.get("jmx_port", 7787))
        bean = env.get("jmx_bean", "com.q1labs.sem:application=ecs-ec-ingress.ecs-ec-ingress,type=sources,name=Source Monitor")
        host = env.get("host")
        collector = env.get("collector")
        user = env.get("ssh_user")
        key_path = env.get("ssh_key")

        base_cmd = f"/opt/qradar/support/jmx.sh -p {port} -b '{bean}'"
        eps_curr, eps_max = None, None

        try:
            key = paramiko.RSAKey.from_private_key_file(key_path)
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=host, username=user, pkey=key, timeout=20, banner_timeout=20, auth_timeout=20)
            logger.info("Autenticação SSH bem-sucedida host=%s user=%s", host, user)

            if collector and collector not in ("host", host):
                logger.info(f"Coletando EPS com salto SSH host={host} -> collector={collector}")
                inner = f"bash -lc {shlex.quote(base_cmd)}"
                remote_cmd = f"ssh -o BatchMode=yes -o StrictHostKeyChecking=no {collector} {shlex.quote(inner)}"
                stdin, stdout, stderr = client.exec_command(remote_cmd, timeout=40)
            else:
                logger.info(f"Coletando EPS diretamente no host={host}")
                direct = f"bash -lc {shlex.quote(base_cmd)}"
                stdin, stdout, stderr = client.exec_command(direct, timeout=40)

            out = stdout.read().decode(errors="ignore")
            stderr.read()
            client.close()

            for line in out.splitlines():
                s = line.strip()
                m1 = re.search(r"EventRate:\s*([0-9.]+)", s, re.I)
                if m1:
                    try:
                        eps_curr = int(round(float(m1.group(1))))
                    except Exception:
                        pass
                    continue
                m2 = re.search(r"EventLongWindowAverage:\s*([0-9.]+)", s, re.I)
                if m2:
                    try:
                        eps_max = int(round(float(m2.group(1))))
                    except Exception:
                        pass
                    continue

            logger.info(f"EPS coletado host={host} collector={collector} current={eps_curr} max={eps_max}")
            return {"eps_current": eps_curr, "eps_max": eps_max}
        except Exception as e:
            logger.error(f"Falha na coleta EPS host={host} collector={collector}: {e}")
            return {"eps_current": None, "eps_max": None}

    def check_services(self, env, services, client=None):
        services = [s for s in services or [] if s]
        if not services:
            return []

        close_client = False
        if client is None:
            try:
                client = self.connect_env(env)
                close_client = True
            except Exception as exc:
                logger.error(f"Falha ao conectar para health check de serviços: {exc}")
                return [
                    {
                        "name": service,
                        "status": "error",
                        "enabled": "unknown",
                        "sub_state": "unknown",
                        "description": "",
                        "error": str(exc),
                    }
                    for service in services
                ]

        try:
            services_list = " ".join(shlex.quote(service) for service in services)
            script = (
                f"for svc in {services_list}; do\n"
                "  active=$(systemctl is-active \"$svc\" 2>/dev/null || echo unknown)\n"
                "  enabled=$(systemctl is-enabled \"$svc\" 2>/dev/null || echo unknown)\n"
                "  sub=$(systemctl show \"$svc\" --no-page --property=SubState 2>/dev/null | head -n1 | cut -d= -f2-)\n"
                "  desc=$(systemctl show \"$svc\" --no-page --property=Description 2>/dev/null | head -n1 | cut -d= -f2-)\n"
                "  sub=${sub//|/ }\n"
                "  desc=${desc//|/ }\n"
                "  printf '__SERVICE__|%s|%s|%s|%s|%s\\n' \"$svc\" \"$active\" \"$enabled\" \"$sub\" \"$desc\"\n"
                "done"
            )

            code, out, err = self._exec(client, f"bash -lc {shlex.quote(script)}")
            if code != 0:
                logger.warning(
                    "Execução do script de verificação de serviços retornou código %s: %s",
                    code,
                    err,
                )

            results = []
            for raw_line in out.splitlines():
                if not raw_line.startswith("__SERVICE__|"):
                    continue
                parts = raw_line.split("|", 5)
                if len(parts) < 6:
                    continue
                _, name, status, enabled, sub_state, description = parts
                results.append(
                    {
                        "name": name,
                        "status": status or "unknown",
                        "enabled": enabled or "unknown",
                        "sub_state": sub_state or "",
                        "description": description or "",
                        "error": None,
                    }
                )

            missing = [service for service in services if service not in {r["name"] for r in results}]
            for service in missing:
                results.append(
                    {
                        "name": service,
                        "status": "unknown",
                        "enabled": "unknown",
                        "sub_state": "",
                        "description": "",
                        "error": err or "Serviço não encontrado ou inacessível",
                    }
                )

            return results
        except Exception as exc:
            logger.error(f"Falha ao verificar serviços: {exc}")
            return [
                {
                    "name": service,
                    "status": "error",
                    "enabled": "unknown",
                    "sub_state": "",
                    "description": "",
                    "error": str(exc),
                }
                for service in services
            ]
        finally:
            if close_client and client is not None:
                try:
                    client.close()
                except Exception:
                    pass

    def check_connectivity(self, env, client=None):
        targets = env.get("connectivity_targets") or []

        entries = []

        def _append_entry(base):
            if not base:
                return
            if isinstance(base, str):
                entries.append({"name": base, "target": base})
                return
            if isinstance(base, dict):
                merged = dict(base)
                if "target" not in merged:
                    merged["target"] = self._resolve_appliance_target(merged)
                entries.append(merged)
                return

        for item in targets:
            _append_entry(item)

        if not entries:
            return []

        close_client = False
        if client is None:
            try:
                client = self.connect_env(env)
                close_client = True
            except Exception as exc:
                logger.error(f"Falha ao conectar para verificação de conectividade: {exc}")
                return [
                    {
                        "name": entry.get("name") or entry.get("label") or entry.get("target") or "Appliance",
                        "target": entry.get("target") or self._resolve_appliance_target(entry),
                        "reachable": False,
                        "latency_ms": None,
                        "packet_loss": None,
                        "status": "error",
                        "error": str(exc),
                    }
                    for entry in entries
                ]

        try:
            results = []
            seen = set()
            for entry in entries:
                target = entry.get("target") or self._resolve_appliance_target(entry)
                name = None
                if isinstance(entry, dict):
                    name = entry.get("name") or entry.get("label")
                if not name and isinstance(entry, str):
                    name = entry
                name = name or target or "Appliance"

                dedupe_key = (name.lower() if isinstance(name, str) else name, target)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                if not target:
                    results.append(
                        {
                            "name": name,
                            "target": None,
                            "reachable": False,
                            "latency_ms": None,
                            "packet_loss": None,
                            "status": "unknown",
                            "error": "Nenhum endereço configurado para este appliance.",
                        }
                    )
                    continue

                ping_cmd = f"ping -c 4 -w 8 {shlex.quote(target)}"
                code, out, err = self._exec(client, f"bash -lc {shlex.quote(ping_cmd)}")

                reachable = code == 0
                latency_ms = None
                packet_loss = None

                try:
                    loss_match = re.search(r"([0-9.]+)% packet loss", out)
                    if loss_match:
                        packet_loss = float(loss_match.group(1))
                except Exception:
                    packet_loss = None

                try:
                    rtt_match = re.search(r"=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+)", out)
                    if rtt_match:
                        latency_ms = float(rtt_match.group(2))
                except Exception:
                    latency_ms = None

                status = "online" if reachable else "offline"
                error_msg = None
                if not reachable:
                    error_msg = err or "Não foi possível alcançar o destino."
                results.append(
                    {
                        "name": name,
                        "target": target,
                        "reachable": reachable,
                        "latency_ms": latency_ms,
                        "packet_loss": packet_loss,
                        "status": status,
                        "error": error_msg.strip() if error_msg else None,
                    }
                )

            return results
        except Exception as exc:
            logger.error(f"Falha ao verificar conectividade: {exc}")
            return [
                {
                    "name": entry.get("name") or entry.get("label") or entry.get("target") or "Appliance",
                    "target": entry.get("target") or self._resolve_appliance_target(entry),
                    "reachable": False,
                    "latency_ms": None,
                    "packet_loss": None,
                    "status": "error",
                    "error": str(exc),
                }
                for entry in entries
            ]
        finally:
            if close_client and client is not None:
                try:
                    client.close()
                except Exception:
                    pass

    def _resolve_appliance_target(self, appliance):
        if not appliance:
            return None
        if isinstance(appliance, str):
            return appliance
        for key in (
            "host",
            "hostname",
            "ip",
            "address",
            "management_ip",
            "ip_address",
            "mgmt_ip",
            "connectivity_ip",
            "ping_ip",
            "target",
            "destination",
        ):
            value = appliance.get(key)
            if value:
                return value
        for key in ("zabbix_host", "zabbix_host_override"):
            value = appliance.get(key)
            if value:
                return value
        return None


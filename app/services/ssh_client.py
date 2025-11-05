import re
import paramiko
import logging
import shlex

logger = logging.getLogger(__name__)

class SSHClient:
    def __init__(self):
        pass

    def _connect(self, host, user, key_path):
        key = paramiko.RSAKey.from_private_key_file(key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, username=user, pkey=key, timeout=20, banner_timeout=20, auth_timeout=20)
        return client

    def _exec(self, client, cmd):
        logger.info(f"SSH exec: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        logger.info(f"SSH exit={code} stdout='{out[:4000]}' stderr='{err[:4000]}'")
        return code, out, err

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
                # Remove duplicates while preserving order for display purposes
                seen = set()
                ordered = []
                for item in exp_list:
                    if item not in seen:
                        ordered.append(item)
                        seen.add(item)
                exp_list = ordered
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


import logging
from typing import Optional, Dict, Any, List

import requests
from requests.exceptions import RequestException

DEFAULT_OUT = {"cpu": None, "memory": None, "storage": None, "eps_current": None, "eps_max": None}

class ZabbixClient:
    def __init__(self, conf: Dict[str, Any]):
        self.url = conf.get("url")
        self.user = conf.get("user")
        self.password = conf.get("password")
        self.api_token = conf.get("api_token")
        self.verify = conf.get("verify_tls", True)
        self.enabled = conf.get("enabled", True)
        self._token = None
        self._timeout = 10
        self._logger = logging.getLogger(__name__)

    def _rpc(self, method: str, params: dict, auth: Optional[str] = None, rid: int = 1):
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": rid}
        headers = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        elif auth:
            payload["auth"] = auth
        r = requests.post(self.url, json=payload, headers=headers, verify=self.verify, timeout=self._timeout)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"Zabbix API error {data['error'].get('code')}: {data['error'].get('message')} - {data['error'].get('data')}")
        return data["result"]

    def login(self) -> Optional[str]:
        if not self.enabled:
            return None
        if self.api_token:
            return "bearer"
        try:
            if self._token:
                return self._token
            res = self._rpc("user.login", {"username": self.user, "password": self.password})
            self._token = res
            self._logger.debug("Token de API obtido com sucesso")
            return self._token
        except Exception as exc:
            self._logger.exception("Falha ao autenticar na API do Zabbix: %s", exc)
            return None

    def _host_get(self, filter_dict: Dict[str, List[str]]) -> Optional[dict]:
        token = self.login()
        res = self._rpc("host.get", {"output": ["hostid", "host", "name"], "filter": filter_dict}, auth=None if self.api_token else token)
        return res[0] if res else None

    def _host_search_by_name(self, name_term: str) -> Optional[dict]:
        token = self.login()
        res = self._rpc("host.get",
                        {"output": ["hostid", "host", "name"], "search": {"name": name_term}, "searchWildcardsEnabled": True},
                        auth=None if self.api_token else token)
        return res[0] if res else None

    def host_get_id(self, hostname_hint: str, zabbix_host_override: Optional[str] = None) -> Optional[str]:
        if zabbix_host_override:
            self._logger.debug(
                "Buscando host override=%s hostname_hint=%s", zabbix_host_override, hostname_hint
            )
            h = self._host_get({"name": [zabbix_host_override]}) or self._host_get({"host": [zabbix_host_override]})
            if h:
                self._logger.debug("Host override encontrado hostid=%s", h["hostid"])
                return h["hostid"]
            self._logger.debug("Host override não encontrado, tentando hint")
        h = self._host_get({"name": [hostname_hint]})
        if h:
            self._logger.debug("Host localizado por nome hostid=%s", h["hostid"])
            return h["hostid"]
        h = self._host_get({"host": [hostname_hint]})
        if h:
            self._logger.debug("Host localizado por host field hostid=%s", h["hostid"])
            return h["hostid"]
        h = self._host_search_by_name(hostname_hint)
        if h:
            self._logger.debug("Host localizado via busca hostid=%s", h["hostid"])
            return h["hostid"]
        self._logger.warning("Host não encontrado no Zabbix hostname_hint=%s", hostname_hint)
        return None

    def _item_get_by_name(self, hostid: str, name: str) -> Optional[dict]:
        token = self.login()
        res = self._rpc("item.get",
                        {"output": ["itemid", "name", "key_", "value_type", "units", "lastvalue", "status", "state", "error"],
                         "hostids": [hostid],
                         "filter": {"name": [name]}},
                        auth=None if self.api_token else token)
        return res[0] if res else None

    def _item_get_first_by_key_search(self, hostid: str, key: str) -> Optional[dict]:
        token = self.login()
        res = self._rpc("item.get",
                        {"output": ["itemid", "name", "key_", "value_type", "units", "lastvalue", "status", "state", "error"],
                         "hostids": [hostid],
                         "search": {"key_": key},
                         "searchWildcardsEnabled": True,
                         "sortfield": "name"},
                        auth=None if self.api_token else token)
        return res[0] if res else None

    def _history_last_value(self, itemid: str, value_type: int) -> Optional[float]:
        token = self.login()
        hist_type = 0 if value_type == 0 else 3 if value_type == 3 else 0
        res = self._rpc("history.get",
                        {"output": "extend", "history": hist_type, "itemids": [itemid],
                         "sortfield": "clock", "sortorder": "DESC", "limit": 1},
                        auth=None if self.api_token else token)
        if not res:
            return None
        try:
            return float(res[0].get("value"))
        except Exception:
            return None

    def _resolve_item_value(self, hostid: str, name: Optional[str], key_fallback: Optional[str]) -> Optional[float]:
        it = None
        if name:
            it = self._item_get_by_name(hostid, name)
        if not it and key_fallback:
            it = self._item_get_first_by_key_search(hostid, key_fallback)
        if not it:
            return None
        if it.get("lastvalue") not in (None, ""):
            try:
                return float(it["lastvalue"])
            except Exception:
                pass
        try:
            vt = int(it.get("value_type", 0))
        except Exception:
            vt = 0
        return self._history_last_value(it["itemid"], vt)

    def get_metrics(self, hostname: str, items: Dict[str, Any], zabbix_host_override: Optional[str] = None) -> Dict[str, Any]:
        if not self.enabled:
            return DEFAULT_OUT.copy()
        try:
            out = DEFAULT_OUT.copy()
            hostid = self.host_get_id(hostname_hint=zabbix_host_override or hostname,
                                      zabbix_host_override=zabbix_host_override)
            if not hostid:
                self._logger.warning(
                    "Não foi possível localizar host no Zabbix hostname=%s override=%s",
                    hostname,
                    zabbix_host_override,
                )
                return out

            cpu = self._resolve_item_value(hostid, items.get("cpu_item_name"), items.get("cpu_key_fallback"))
            if cpu is not None:
                out["cpu"] = cpu

            mem = self._resolve_item_value(hostid, items.get("mem_item_name"), items.get("mem_key_fallback"))
            if mem is not None:
                out["memory"] = mem

            store = self._resolve_item_value(hostid, items.get("store_item_name"), items.get("store_key_fallback"))
            if store is not None:
                out["storage"] = store

            self._logger.debug(
                "Métricas obtidas hostid=%s cpu=%s memory=%s storage=%s",
                hostid,
                out["cpu"],
                out["memory"],
                out["storage"],
            )
            return out
        except RequestException as exc:
            self._logger.exception("Erro de requisição ao coletar métricas hostname=%s: %s", hostname, exc)
            return DEFAULT_OUT.copy()
        except Exception as exc:
            self._logger.exception("Erro inesperado ao coletar métricas hostname=%s: %s", hostname, exc)
            return DEFAULT_OUT.copy()


import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class CrowdstrikeApiError(RuntimeError):


class CrowdstrikeAuthError(CrowdstrikeApiError):


_SIZE_RE = re.compile(r"^\s*([0-9]+(?:\.[0-9]+)?)\s*([a-zA-Z]+)?\s*$")

DECIMAL_BASE = 1000
BINARY_BASE = 1024


def _parse_size_to_bytes(value: Any) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    if not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    m = _SIZE_RE.match(s)
    if not m:
        return None

    num_str, unit = m.group(1), (m.group(2) or "B")
    try:
        num = float(num_str)
    except ValueError:
        return None

    u = unit.strip()

    u = u.replace("Bytes", "B").replace("Byte", "B")

    bin_map = {
        "B": 1,
        "KiB": BINARY_BASE,
        "MiB": BINARY_BASE**2,
        "GiB": BINARY_BASE**3,
        "TiB": BINARY_BASE**4,
    }

    dec_map = {
        "B": 1,
        "kB": DECIMAL_BASE,
        "MB": DECIMAL_BASE**2,
        "GB": DECIMAL_BASE**3,
        "TB": DECIMAL_BASE**4,
    }

    if u in bin_map:
        factor = bin_map[u]
    elif u in dec_map:
        factor = dec_map[u]
    elif u.lower() in {k.lower() for k in dec_map.keys()}:
        key = next(k for k in dec_map.keys() if k.lower() == u.lower())
        factor = dec_map[key]
    elif u.lower() in {k.lower() for k in bin_map.keys()}:
        key = next(k for k in bin_map.keys() if k.lower() == u.lower())
        factor = bin_map[key]
    else:
        return None

    return int(num * factor)


def _build_session() -> requests.Session:
    retry = Retry(
        total=6,
        backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


class CrowdstrikeClient:
    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        logger: Optional[logging.Logger] = None,
        timeout: int = 30,
        page_limit: int = 100,
        filter_expr: str = "",
        sort_expr: Optional[str] = None,
    ):
        if not base_url:
            raise ValueError("Base URL do Crowdstrike não configurada.")
        if not client_id:
            raise ValueError("Client ID do Crowdstrike não configurado.")
        if not client_secret:
            raise ValueError("Client Secret do Crowdstrike não configurado.")

        self.base_url = str(base_url).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self.page_limit = page_limit
        self.filter_expr = filter_expr
        self.sort_expr = sort_expr
        self.logger = logger or logging.getLogger(__name__)
        self.session = _build_session()

    def _token_url(self) -> str:
        return f"{self.base_url}/oauth2/token"

    def _connections_url(self) -> str:
        return f"{self.base_url}/ngsiem/combined/connections/v1"

    def fetch_token(self) -> str:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        resp = self.session.post(self._token_url(), data=data, headers=headers, timeout=self.timeout)
        if resp.status_code not in (200, 201):
            raise CrowdstrikeAuthError(
                f"Falha ao obter token OAuth2. HTTP {resp.status_code}. Response: {resp.text}"
            )
        try:
            payload = resp.json()
        except json.JSONDecodeError:
            raise CrowdstrikeAuthError("Resposta inválida da API OAuth2 do Crowdstrike.")

        token = payload.get("access_token")
        if not token:
            raise CrowdstrikeAuthError("access_token não encontrado na resposta do OAuth2.")
        return token

    def _list_connections_page(self, bearer: str, offset: int) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "limit": self.page_limit,
            "offset": offset,
        }
        if self.filter_expr:
            params["filter"] = self.filter_expr
        if self.sort_expr:
            params["sort"] = self.sort_expr

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer}",
        }

        resp = self.session.get(
            self._connections_url(), headers=headers, params=params, timeout=self.timeout
        )
        if resp.status_code == 429:
            time.sleep(5)
            resp = self.session.get(
                self._connections_url(), headers=headers, params=params, timeout=self.timeout
            )

        if resp.status_code != 200:
            raise CrowdstrikeApiError(
                f"Falha ao listar conexões. HTTP {resp.status_code}. Response: {resp.text}"
            )
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise CrowdstrikeApiError(f"Resposta inválida ao listar conexões: {exc}") from exc

    @staticmethod
    def _extract_resources_and_total(payload: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        resources = payload.get("resources", []) or []
        pagination = payload.get("meta", {}).get("pagination", {}) or {}
        total = pagination.get("total")
        try:
            total_value = int(total) if total is not None else None
        except (TypeError, ValueError):
            total_value = None
        return resources, total_value

    def list_all_connections(self, bearer: str) -> Dict[str, Any]:
        offset = 0
        all_resources: List[Dict[str, Any]] = []
        reported_total: Optional[int] = None

        while True:
            page = self._list_connections_page(bearer, offset)
            resources, total = self._extract_resources_and_total(page)
            if reported_total is None:
                reported_total = total
            all_resources.extend(resources)
            if len(resources) < self.page_limit:
                break
            if reported_total and len(all_resources) >= reported_total:
                break
            offset += self.page_limit
            if offset > 200000:
                raise CrowdstrikeApiError("Offset excessivo ao paginar conexões (possível loop infinito).")

        return {
            "meta": {
                "retrieved_total": len(all_resources),
                "reported_total": reported_total,
                "base_url": self.base_url,
                "filter": self.filter_expr,
                "sort": self.sort_expr,
            },
            "resources": all_resources,
        }

    @staticmethod
    def summarize_ingestion(result: Dict[str, Any]) -> Dict[str, Any]:
        resources = result.get("resources", []) or []
        total_bytes = 0
        missing_or_invalid = 0

        for entry in resources:
            raw = entry.get("last_ingested_volume_one_day")
            size_bytes = _parse_size_to_bytes(raw)
            if size_bytes is None:
                missing_or_invalid += 1
                continue
            total_bytes += size_bytes

        total_gb_decimal = total_bytes / (DECIMAL_BASE**3)
        total_gib_binary = total_bytes / (BINARY_BASE**3)

        return {
            "connectors_count": len(resources),
            "missing_or_invalid_count": missing_or_invalid,
            "total_bytes_one_day": total_bytes,
            "total_gb_one_day_decimal": total_gb_decimal,
            "total_gib_one_day_binary": total_gib_binary,
        }

    @staticmethod
    def map_connectors(resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        mapped: List[Dict[str, Any]] = []
        for entry in resources or []:
            size_bytes = _parse_size_to_bytes(entry.get("last_ingested_volume_one_day"))
            mapped.append(
                {
                    "id": entry.get("id") or entry.get("connection_id") or entry.get("cid"),
                    "name": entry.get("name") or entry.get("connection_name") or entry.get("connector_name"),
                    "status": entry.get("status") or entry.get("connection_status"),
                    "type": entry.get("connection_type") or entry.get("type") or entry.get("connector_type"),
                    "vendor": entry.get("vendor") or entry.get("vendor_name") or entry.get("source_vendor"),
                    "product": entry.get("product") or entry.get("product_name") or entry.get("source_product"),
                    "last_ingested_volume_one_day": entry.get("last_ingested_volume_one_day"),
                    "last_ingested_volume_bytes": size_bytes,
                    "last_ingested_at": entry.get("last_ingested_time")
                    or entry.get("last_ingested_timestamp")
                    or entry.get("last_ingested"),
                }
            )
        return mapped

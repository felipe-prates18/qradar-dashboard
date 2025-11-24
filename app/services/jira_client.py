import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests
from requests.auth import HTTPBasicAuth


class JiraClient:
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.base_url = config.get("base_url") or config.get("url")
        self.email = config.get("email")
        self.api_token = config.get("api_token")
        self.project_key = config.get("project_key") or "CSIRT"
        self.customfield_clients_id = config.get("customfield_clients_id") or "customfield_10191"
        self.max_results = int(config.get("max_results", 200))
        if not self.base_url or not self.email or not self.api_token:
            raise ValueError("Configuração do Jira incompleta: base_url, email e api_token são obrigatórios")

    def _search_issues(self, jql: str, next_page_token: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}/rest/api/3/search/jql"
        auth = HTTPBasicAuth(self.email, self.api_token)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        params: Dict[str, Any] = {
            "jql": jql,
            "maxResults": self.max_results,
            "fields": f"key,summary,created,{self.customfield_clients_id}",
        }
        if next_page_token:
            params["nextPageToken"] = next_page_token

        response = requests.get(url, headers=headers, params=params, auth=auth, timeout=20)
        if response.status_code != 200:
            raise RuntimeError(
                f"Erro ao buscar issues do Jira | status={response.status_code} corpo={response.text[:1000]}"
            )
        return response.json()

    def fetch_recent_issues(self, hours: int = 24) -> List[Dict[str, Any]]:
        window_hours = max(1, int(hours))
        jql = f"project = {self.project_key} AND created >= -{window_hours}h ORDER BY created DESC"
        issues: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        while True:
            data = self._search_issues(jql, next_page_token=next_token)
            issues.extend(data.get("issues", []) or [])
            next_token = data.get("nextPageToken")
            if not next_token:
                break
        return issues

    @staticmethod
    def _extract_client_names(field_value: Any) -> List[str]:
        if not field_value:
            return []
        if isinstance(field_value, list):
            result: List[str] = []
            for item in field_value:
                if isinstance(item, dict):
                    name = item.get("value") or item.get("name")
                    if name:
                        result.append(str(name))
                else:
                    result.append(str(item))
            return result
        if isinstance(field_value, dict):
            name = field_value.get("value") or field_value.get("name")
            return [str(name)] if name else []
        return [str(field_value)]

    @staticmethod
    def _parse_created(value: Any) -> Optional[datetime]:
        if not value:
            return None
        text = str(value).strip()
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                dt = datetime.strptime(text, fmt)
                return dt.astimezone(timezone.utc)
            except Exception:
                continue
        try:
            return datetime.fromisoformat(text).astimezone(timezone.utc)
        except Exception:
            return None

    def last_issue_by_client(
        self, clients: Iterable[str], *, window_hours: int = 24
    ) -> Dict[str, Optional[datetime]]:
        normalized_clients = {str(c).strip(): None for c in clients if str(c).strip()}
        if not normalized_clients:
            return {}

        issues = self.fetch_recent_issues(hours=window_hours)
        self.logger.info("%d issues do Jira coletadas para análise de clientes", len(issues))

        last_seen: Dict[str, Optional[datetime]] = {client: None for client in normalized_clients}
        for issue in issues:
            fields = issue.get("fields", {}) or {}
            created_raw = fields.get("created")
            created_at = self._parse_created(created_raw)
            client_field = fields.get(self.customfield_clients_id)
            client_names = self._extract_client_names(client_field)

            for client in client_names:
                normalized = str(client).strip()
                if normalized not in last_seen:
                    continue
                if created_at is None:
                    continue
                previous = last_seen.get(normalized)
                if previous is None or created_at > previous:
                    last_seen[normalized] = created_at
        return last_seen

    def summarize_clients(
        self, clients: Iterable[str], *, window_hours: int = 24
    ) -> List[Dict[str, Any]]:
        normalized_clients = [str(c).strip() for c in clients if str(c).strip()]
        if not normalized_clients:
            return []

        window_hours = max(1, int(window_hours))
        issues = self.fetch_recent_issues(hours=window_hours)
        self.logger.info(
            "%d issues do Jira coletadas para resumo de clientes", len(issues)
        )

        now = datetime.now(timezone.utc)
        client_summary: Dict[str, Dict[str, Any]] = {
            client: {
                "client": client,
                "issues_in_window": 0,
                "last_issue": None,
                "hours_without_ticket": None,
            }
            for client in normalized_clients
        }

        for issue in issues:
            fields = issue.get("fields", {}) or {}
            created_raw = fields.get("created")
            created_at = self._parse_created(created_raw)
            client_field = fields.get(self.customfield_clients_id)
            client_names = self._extract_client_names(client_field)

            for client in client_names:
                normalized = str(client).strip()
                if normalized not in client_summary:
                    continue
                summary_entry = client_summary[normalized]
                summary_entry["issues_in_window"] += 1

                if created_at is None:
                    continue

                previous_last = summary_entry.get("last_issue")
                if previous_last is None or created_at > previous_last.get(
                    "created_at"
                ):
                    summary_entry["last_issue"] = {
                        "key": issue.get("key"),
                        "summary": fields.get("summary") or "",
                        "created_at": created_at,
                    }

        for client, summary_entry in client_summary.items():
            last_issue = summary_entry.get("last_issue")
            hours_without = None
            if last_issue and last_issue.get("created_at"):
                delta = now - last_issue["created_at"]
                hours_without = max(0, delta.total_seconds() / 3600)
            summary_entry["hours_without_ticket"] = hours_without

        return list(client_summary.values())

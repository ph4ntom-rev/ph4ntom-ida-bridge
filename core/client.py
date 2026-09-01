"""HTTP client shared by the CLI, MCP server, agents, and integrations."""

from __future__ import annotations

import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import JSONDecodeError, RequestException
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

DEFAULT_BRIDGE_URL = "http://127.0.0.1:13370"
DEFAULT_TIMEOUT = 30


class BridgeClient:
    """Resilient client for the local ph4ntom IDA Bridge API.

    A lock serializes access to the underlying ``requests.Session``. If IDA is
    restarted and rotates its token, the client reloads the token after the
    first 401 response and retries that request once.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        token: Optional[str] = None,
        token_file: Optional[str] = None,
    ) -> None:
        raw_url = url or os.environ.get("IDA_BRIDGE_URL", DEFAULT_BRIDGE_URL)
        self.base_url = self._normalize_url(raw_url)
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        self.timeout = timeout
        self._explicit_token = token or os.environ.get("IDA_BRIDGE_TOKEN")
        self._explicit_token_file = token_file or os.environ.get("IDA_BRIDGE_TOKEN_FILE")
        self._request_lock = threading.RLock()
        self.session = self._build_session()

    @staticmethod
    def _normalize_url(url: str) -> str:
        normalized = url.strip().rstrip("/")
        parsed = urlsplit(normalized)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Bridge URL must be an absolute http:// or https:// URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Bridge URL must not contain credentials, a query, or a fragment")
        return normalized

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self._load_token(session)

        retry_strategy = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.3,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(("GET", "HEAD", "OPTIONS")),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _token_candidates(self) -> Iterable[Path]:
        seen = set()
        candidates = []
        if self._explicit_token_file:
            candidates.append(Path(self._explicit_token_file).expanduser())
        candidates.extend((
            Path.home() / ".ph4ntom_ida_bridge_token",
            Path(tempfile.gettempdir()) / ".ph4ntom_ida_bridge_token",
        ))
        for candidate in candidates:
            key = os.path.normcase(os.path.abspath(str(candidate)))
            if key not in seen:
                seen.add(key)
                yield candidate

    def _load_token(self, session: requests.Session) -> bool:
        token = self._explicit_token
        if not token:
            for token_path in self._token_candidates():
                try:
                    if token_path.is_file():
                        token = token_path.read_text(encoding="utf-8").strip()
                        if token:
                            break
                except OSError as exc:
                    logger.warning("Failed to read token from %s: %s", token_path, exc)

        if token:
            session.headers["Authorization"] = "Bearer " + token
            return True
        session.headers.pop("Authorization", None)
        return False

    def _refresh_token(self) -> bool:
        previous = self.session.headers.get("Authorization")
        self.session.headers.pop("Authorization", None)
        loaded = self._load_token(self.session)
        current = self.session.headers.get("Authorization")
        return loaded and current != previous

    def _request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        """Send one API request and return a JSON-compatible result."""
        clean_path = path.lstrip("/")
        url = self.base_url + "/" + clean_path
        kwargs.setdefault("timeout", self.timeout)

        try:
            with self._request_lock:
                response = self.session.request(method, url, **kwargs)
                if response.status_code == 401 and self._refresh_token():
                    response = self.session.request(method, url, **kwargs)

            response.raise_for_status()
            if not response.text.strip():
                return {"success": True, "data": None}
            payload = response.json()
            if isinstance(payload, dict):
                return payload
            return {"success": True, "data": payload}
        except requests.ConnectionError:
            return {"error": f"IDA Bridge offline at {self.base_url}", "success": False}
        except JSONDecodeError:
            return {
                "error": f"Invalid JSON response from server (HTTP {response.status_code})",
                "success": False,
            }
        except requests.exceptions.HTTPError as exc:
            try:
                payload = response.json()
            except (ValueError, JSONDecodeError):
                payload = None
            if isinstance(payload, dict):
                payload.setdefault("error", str(exc))
                payload["success"] = False
                return payload
            return {
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
                "success": False,
            }
        except requests.exceptions.Timeout:
            return {"error": "Request timed out", "success": False}
        except RequestException as exc:
            return {"error": f"HTTP request failed: {exc}", "success": False}

    def get(self, path: str, **params: Any) -> Dict[str, Any]:
        return self._request("GET", path, params=params)

    def post(self, path: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._request("POST", path, json=data or {})

    def call_api(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized_method = method.upper()
        if normalized_method == "GET":
            return self._request("GET", path, params=payload or {})
        if normalized_method == "POST":
            return self._request("POST", path, json=payload or {})
        return {"error": "Only GET and POST are supported", "success": False}

    @staticmethod
    def path_component(value: Any) -> str:
        return quote(str(value), safe="")

    def ping(self) -> Dict[str, Any]:
        return self.get("/api/ping")

    def info(self) -> Dict[str, Any]:
        return self.get("/api/info")

    def is_online(self) -> bool:
        response = self.ping()
        return response.get("status") == "ok" and not response.get("error")

    def decompile(self, ea: str) -> Dict[str, Any]:
        return self.get(f"/api/function/{self.path_component(ea)}/pseudocode")

    def pseudocode(self, ea: str) -> Dict[str, Any]:
        return self.decompile(ea)

    def functions(self, limit: Optional[int] = None, offset: int = 0) -> Dict[str, Any]:
        if limit is not None:
            return self.get("/api/functions-page", offset=offset, limit=limit)
        return self.get("/api/functions")

    def strings(self, filter_pattern: Optional[str] = None) -> Dict[str, Any]:
        params = {"filter": filter_pattern} if filter_pattern else {}
        return self.get("/api/strings", **params)

    def xrefs_to(self, ea: str) -> Dict[str, Any]:
        return self.get(f"/api/function/{self.path_component(ea)}/xrefs-to")

    def exec_python(self, script: str) -> Dict[str, Any]:
        return self.post("/api/exec", {"script": script})

    def batch(self, mutations: list) -> Dict[str, Any]:
        return self.post("/api/batch", {"mutations": mutations})

    def wait_analysis(self) -> Dict[str, Any]:
        return self.get("/api/wait-analysis")

    def rename_func(self, ea: str, name: str) -> Dict[str, Any]:
        return self.post(
            f"/api/function/{self.path_component(ea)}/rename",
            {"name": name},
        )

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "BridgeClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

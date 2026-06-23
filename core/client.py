"""
Antigravity IDA Bridge — Core HTTP Client
==========================================
Reusable HTTP client for communicating with the IDA Bridge REST API.
Used by all backends, integrations, and CLI tools.

Changes (v5.2):
- Centralized _request method (DRY)
- Connection pooling with HTTPAdapter
- Auto-retry with exponential backoff (429, 5xx)
- Safe JSON parsing (handles HTML error pages)
- Secure token loading from user home directory
- URL slash normalization
"""

import os
import logging
import tempfile
from typing import Dict, Any, Optional
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException, JSONDecodeError
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class BridgeClient:
    """Thread-safe HTTP client for the Antigravity IDA Bridge."""

    def __init__(self, url: Optional[str] = None, timeout: int = 30):
        raw_url = url or os.environ.get(
            "IDA_BRIDGE_URL", "http://127.0.0.1:13370")
        self.base_url = raw_url.rstrip("/")
        self.timeout = timeout
        self.session = self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"Content-Type": "application/json"})
        self._load_token(session)

        # Connection pooling and auto-retry for resilience
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            pool_connections=20,
            pool_maxsize=20,
            max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _load_token(self, session: requests.Session) -> None:
        """Load ephemeral Bearer token. Checks home dir first, then temp dir."""
        candidates = [
            Path.home() / ".antigravity_token",
            Path(tempfile.gettempdir()) / ".antigravity_token",
        ]
        for token_path in candidates:
            try:
                if token_path.is_file():
                    token = token_path.read_text(encoding="utf-8").strip()
                    if token:
                        session.headers["Authorization"] = f"Bearer {token}"
                        return
            except OSError as e:
                logger.warning(f"Failed to read token from {token_path}: {e}")

    # ── Core HTTP Methods ────────────────────────────────────────────────

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Centralized request dispatcher with robust error handling."""
        clean_path = path.lstrip("/")
        url = f"{self.base_url}/{clean_path}"
        kwargs.setdefault("timeout", self.timeout)

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            if response.text.strip():
                return response.json()
            return {"success": True, "data": None}

        except requests.ConnectionError:
            return {
                "error": f"IDA Bridge offline at {
                    self.base_url}",
                "success": False}
        except JSONDecodeError:
            return {
                "error": f"Invalid JSON response from server (HTTP {
                    response.status_code})",
                "success": False}
        except requests.exceptions.HTTPError as e:
            try:
                return {
                    "error": response.json().get(
                        "error",
                        str(e)),
                    "success": False}
            except (ValueError, JSONDecodeError):
                return {
                    "error": f"HTTP {response.status_code}: {response.text[:200]}", "success": False}
        except requests.exceptions.Timeout:
            return {"error": "Request timed out", "success": False}
        except RequestException as e:
            return {
                "error": f"HTTP request failed: {
                    str(e)}", "success": False}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def get(self, path: str, **params) -> Dict[str, Any]:
        """GET request to bridge. Returns parsed JSON."""
        return self._request("GET", path, params=params)

    def post(self, path: str,
             data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST request to bridge. Returns parsed JSON."""
        return self._request("POST", path, json=data or {})

    # ── Convenience Methods ──────────────────────────────────────────────

    def ping(self) -> Dict[str, Any]:
        """Check bridge connectivity."""
        return self.get("/api/ping")

    def info(self) -> Dict[str, Any]:
        """Get binary metadata."""
        return self.get("/api/info")

    def is_online(self) -> bool:
        """Quick connectivity check."""
        return "error" not in self.ping()

    def decompile(self, ea: str) -> Dict[str, Any]:
        """Decompile function at address."""
        return self.get(f"/api/function/{ea}/pseudocode")

    def pseudocode(self, ea: str) -> Dict[str, Any]:
        """Alias for decompile()."""
        return self.decompile(ea)

    def functions(self,
                  limit: Optional[int] = None,
                  offset: int = 0) -> Dict[str,
                                           Any]:
        """List functions with optional pagination."""
        if limit:
            return self.get("/api/functions-page", offset=offset, limit=limit)
        return self.get("/api/functions")

    def exec_python(self, script: str) -> Dict[str, Any]:
        """Execute IDAPython script."""
        return self.post("/api/exec", {"script": script})

    def batch(self, mutations: list) -> Dict[str, Any]:
        """Execute batch mutations atomically."""
        return self.post("/api/batch", {"mutations": mutations})

    def wait_analysis(self) -> Dict[str, Any]:
        """Wait for IDA auto-analysis to complete."""
        return self.get("/api/wait-analysis")

    def rename_func(self, ea: str, name: str) -> Dict[str, Any]:
        """Rename function at address."""
        return self.post(f"/api/function/{ea}/rename", {"name": name})

    def call_api(self, method: str, path: str,
                 payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generic API call supporting arbitrary HTTP methods."""
        method = method.upper()
        if method == "GET":
            return self._request(method, path, params=payload)
        else:
            return self._request(method, path, json=payload or {})

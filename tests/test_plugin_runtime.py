import importlib.util
import json
import sys
import threading
import types
import uuid
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_PATH = ROOT / "ida_plugin" / "ph4ntom_ida_bridge.py"


class _Hook:
    def hook(self):
        return True

    def unhook(self):
        return True


class _Plugin:
    pass


def _load_plugin(monkeypatch, tmp_path):
    ida_kernwin = types.ModuleType("ida_kernwin")
    ida_kernwin.UI_Hooks = _Hook
    ida_kernwin.MFF_READ = 0
    ida_kernwin.MFF_WRITE = 1
    ida_kernwin.execute_sync = lambda callback, mode: callback()
    ida_kernwin.msg = lambda message: None
    ida_kernwin.process_ui_action = lambda action: True

    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.plugin_t = _Plugin
    ida_idaapi.PLUGIN_KEEP = 1
    ida_idaapi.BADADDR = (1 << 64) - 1

    ida_dbg = types.ModuleType("ida_dbg")
    ida_dbg.DbgHooks = _Hook

    monkeypatch.setitem(sys.modules, "ida_kernwin", ida_kernwin)
    monkeypatch.setitem(sys.modules, "ida_idaapi", ida_idaapi)
    monkeypatch.setitem(sys.modules, "ida_dbg", ida_dbg)
    for name in (
        "ida_funcs",
        "ida_name",
        "ida_bytes",
        "ida_segment",
        "ida_nalt",
        "ida_entry",
        "ida_auto",
        "ida_lines",
        "ida_typeinf",
        "ida_range",
        "ida_hexrays",
        "idautils",
        "idc",
    ):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

    token_file = tmp_path / "bridge-token"
    monkeypatch.setenv("IDA_BRIDGE_TOKEN_FILE", str(token_file))
    module_name = "ph4ntom_test_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(module_name, PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, token_file


def test_plugin_imports_with_stubbed_ida_and_writes_secure_token(monkeypatch, tmp_path):
    plugin, token_file = _load_plugin(monkeypatch, tmp_path)

    token = token_file.read_text(encoding="utf-8")
    assert token == plugin.AUTH_TOKEN
    assert len(token) == 64
    assert len(plugin.GET_ROUTES) == 41
    assert len(plugin.POST_ROUTES) == 44


def test_http_security_defaults(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        ping = requests.get(base_url + "/api/ping", timeout=2)
        unauthorized = requests.get(base_url + "/api/info", timeout=2)
        bad_host = requests.get(
            base_url + "/api/ping",
            headers={"Host": "example.com"},
            timeout=2,
        )
        remote_origin = requests.get(
            base_url + "/api/ping",
            headers={"Origin": "https://example.com"},
            timeout=2,
        )
        local_origin = requests.get(
            base_url + "/api/ping",
            headers={"Origin": "http://localhost:3000"},
            timeout=2,
        )

        plugin.MAX_BODY_SIZE = 1
        oversized = requests.post(
            base_url + "/api/save",
            headers={"Authorization": "Bearer " + plugin.AUTH_TOKEN},
            json={},
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert ping.status_code == 200
    assert ping.json()["dynamic_exec_enabled"] is False
    assert unauthorized.status_code == 401
    assert bad_host.status_code == 403
    assert "Access-Control-Allow-Origin" not in remote_origin.headers
    assert local_origin.headers["Access-Control-Allow-Origin"] == "http://localhost:3000"
    assert oversized.status_code == 413


def test_schema_route_works_when_ida_executes_plugin_without_file(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    schema = ROOT / "api_schema.json"
    installed_schema = tmp_path / schema.name
    installed_schema.write_bytes(schema.read_bytes())

    ida_diskio = types.ModuleType("ida_diskio")
    ida_diskio.idadir = lambda subdir: str(tmp_path) if subdir == "plugins" else ""
    ida_diskio.get_user_idadir = lambda: str(tmp_path / "user")
    monkeypatch.setitem(sys.modules, "ida_diskio", ida_diskio)
    monkeypatch.delattr(plugin, "__file__")

    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        response = requests.get(
            base_url + "/api/schema",
            headers={"Authorization": "Bearer " + plugin.AUTH_TOKEN},
            timeout=2,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert response.status_code == 200
    assert response.json()["meta"]["version"] == plugin.BRIDGE_VERSION


def test_every_documented_endpoint_is_routable(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    schema = json.loads((ROOT / "api_schema.json").read_text(encoding="utf-8"))
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {"Authorization": "Bearer " + plugin.AUTH_TOKEN}
    failures = []

    def concrete_path(template):
        return (
            template.replace("<ea>", "0x1000")
            .replace("<size>", "4")
            .replace("<name>", "TestName")
            .replace("<pattern>", "90")
            .replace("<text>", "test")
        )

    try:
        for endpoint in schema["endpoints"]["read"] + schema["endpoints"]["write"]:
            method = endpoint["method"]
            path = concrete_path(endpoint["path"])
            if method == "GET":
                response = requests.get(base_url + path, headers=headers, timeout=2)
            else:
                response = requests.post(
                    base_url + path,
                    headers=headers,
                    json=endpoint.get("body", {}),
                    timeout=2,
                )
            message = response.text
            if response.status_code == 404 or "Unknown action" in message or "Unknown POST action" in message:
                failures.append((method, path, response.status_code, message[:200]))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert failures == []

import json
import os
import threading
import types
from pathlib import Path

import requests

from core.client import BridgeClient
from tests.test_plugin_runtime import _load_plugin


def _start_test_server(plugin):
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {"Authorization": f"Bearer {plugin.AUTH_TOKEN}"}
    return server, thread, base_url, headers


def _stop_test_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_conditional_breakpoints_blocked_when_exec_disabled_and_allowed_when_enabled(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    added = []

    class _FakeBpt:
        def __init__(self):
            self.ea = 0x1000
            self.size = 1
            self.type = 4
            self.flags = 8
            self.condition = ""
            self.elang = "Python"
            self.pass_count = 0

    fake_bpt = _FakeBpt()
    plugin.ida_dbg.add_bpt = lambda *args: added.append(args) or True
    plugin.ida_dbg.bpt_t = _FakeBpt
    plugin.ida_dbg.get_bpt = lambda ea, bp: setattr(bp, "ea", ea) is None or True
    plugin.ida_dbg.update_bpt = lambda bp: setattr(fake_bpt, "condition", bp.condition) is None or True
    plugin.ida_nalt.get_imagebase = lambda: 0x1000
    plugin.ida_nalt.get_root_filename = lambda: "test.exe"

    server, thread, base_url, headers = _start_test_server(plugin)
    try:
        r_bp = requests.post(
            base_url + "/api/dbg/breakpoint",
            headers=headers,
            json={"ea": "0x1000", "condition": "__import__('os').system('calc')"},
            timeout=2,
        )
        r_wp = requests.post(
            base_url + "/api/dbg/watchpoint",
            headers=headers,
            json={"ea": "0x1000", "size": 4, "mode": "write", "condition": "1 == 1"},
            timeout=2,
        )
        r_upd = requests.post(
            base_url + "/api/dbg/update-breakpoint",
            headers=headers,
            json={"ea": "0x1000", "condition": "eax == 0"},
            timeout=2,
        )
        r_imp = requests.post(
            base_url + "/api/dbg/breakpoints/import",
            headers=headers,
            json={"breakpoints": [{"ea": "0x1000", "condition": "True"}]},
            timeout=2,
        )
        assert r_bp.status_code == 403
        assert r_wp.status_code == 403
        assert r_upd.status_code == 403
        assert r_imp.status_code == 403
        assert added == []

        # Unconditional breakpoint and clearing condition must still work when exec is disabled
        r_plain = requests.post(
            base_url + "/api/dbg/breakpoint",
            headers=headers,
            json={"ea": "0x1000", "condition": ""},
            timeout=2,
        )
        r_clear = requests.post(
            base_url + "/api/dbg/update-breakpoint",
            headers=headers,
            json={"ea": "0x1000", "condition": ""},
            timeout=2,
        )
        assert r_plain.status_code == 200 and r_plain.json()["success"] is True
        assert r_clear.status_code == 200 and r_clear.json()["success"] is True

        # Enabling dynamic execution allows conditional breakpoints
        plugin.ALLOW_SCRIPT_EXECUTION = True
        r_allowed = requests.post(
            base_url + "/api/dbg/breakpoint",
            headers=headers,
            json={"ea": "0x1004", "condition": "eax == 1"},
            timeout=2,
        )
        assert r_allowed.status_code == 200 and r_allowed.json()["success"] is True
    finally:
        _stop_test_server(server, thread)


def test_dbg_start_blocked_by_default_and_allowed_with_flag(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    started = []
    plugin.ida_dbg.start_process = lambda path, args, sdir: started.append((path, args, sdir)) or 1
    plugin.ida_nalt.get_input_file_path = lambda: "C:\\sample.exe"

    server, thread, base_url, headers = _start_test_server(plugin)
    try:
        blocked = requests.post(
            base_url + "/api/dbg/start",
            headers=headers,
            json={"path": "C:\\Windows\\System32\\cmd.exe", "args": "/c whoami"},
            timeout=2,
        )
        assert blocked.status_code == 403
        assert started == []

        plugin.ALLOW_DBG_START = True
        allowed = requests.post(
            base_url + "/api/dbg/start",
            headers=headers,
            json={"path": "C:\\sample.exe", "args": "--test"},
            timeout=2,
        )
        assert allowed.status_code == 200
        assert allowed.json()["success"] is True
        assert len(started) == 1
    finally:
        _stop_test_server(server, thread)


def test_http_get_file_write_forbidden_and_readonly_allows_json_export(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    plugin.ida_dbg.get_bpt_qty = lambda: 0
    plugin.ida_dbg.is_debugger_on = lambda: False
    plugin.idc.get_screen_ea = lambda: plugin.ida_idaapi.BADADDR

    bp_target = tmp_path / "get_bp_leak.json"
    ev_target = tmp_path / "get_ev_leak.json"

    server, thread, base_url, headers = _start_test_server(plugin)
    try:
        r_bp_write = requests.get(
            base_url + "/api/dbg/breakpoints/export",
            headers=headers,
            params={"output": str(bp_target)},
            timeout=2,
        )
        r_ev_write = requests.get(
            base_url + "/api/dbg/evidence",
            headers=headers,
            params={"output": str(ev_target)},
            timeout=2,
        )
        assert r_bp_write.status_code == 400
        assert r_ev_write.status_code == 400
        assert not bp_target.exists()
        assert not ev_target.exists()

        plugin.READ_ONLY = True
        r_bp_ok = requests.get(base_url + "/api/dbg/breakpoints/export", headers=headers, timeout=2)
        r_ev_ok = requests.get(base_url + "/api/dbg/evidence", headers=headers, timeout=2)
        assert r_bp_ok.status_code == 200 and "breakpoints" in r_bp_ok.json()
        assert r_ev_ok.status_code == 200 and "binary" in r_ev_ok.json()
    finally:
        _stop_test_server(server, thread)


def test_server_side_file_export_and_import_root_isolation(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    plugin.ida_dbg.get_bpt_qty = lambda: 0
    plugin.ida_dbg.is_debugger_on = lambda: False
    plugin.idc.get_screen_ea = lambda: plugin.ida_idaapi.BADADDR
    plugin.HAS_HEXRAYS = False

    allowed_export = tmp_path / "exports"
    allowed_import = tmp_path / "imports"
    outside_dir = tmp_path / "outside"
    allowed_export.mkdir()
    allowed_import.mkdir()
    outside_dir.mkdir()

    outside_bp = outside_dir / "secret.json"
    outside_bp.write_text(json.dumps({"breakpoints": []}), encoding="utf-8")
    trusted_bp = allowed_import / "bps.json"
    trusted_bp.write_text(json.dumps({"breakpoints": []}), encoding="utf-8")

    server, thread, base_url, headers = _start_test_server(plugin)
    try:
        # Unconfigured roots -> server-side file paths rejected with 403
        out_unconf = outside_dir / "unconf.json"
        for endpoint, body in (
            ("/api/decompile-batch", {"addresses": ["0x1000"], "output_path": str(out_unconf)}),
            ("/api/dbg/breakpoints/export", {"output_path": str(out_unconf)}),
            ("/api/dbg/evidence", {"output_path": str(out_unconf)}),
        ):
            res = requests.post(base_url + endpoint, headers=headers, json=body, timeout=2)
            assert res.status_code == 403, f"{endpoint} should reject unconfigured export path"
        assert not out_unconf.exists()

        imp_unconf = requests.post(
            base_url + "/api/dbg/breakpoints/import",
            headers=headers,
            json={"input_path": str(outside_bp)},
            timeout=2,
        )
        assert imp_unconf.status_code == 403

        # Configure roots -> inside succeeds, outside and sensitive names fail with 403
        plugin.ALLOWED_EXPORT_ROOTS = (str(allowed_export.resolve()),)
        plugin.ALLOWED_IMPORT_ROOTS = (str(allowed_import.resolve()),)

        good_out = allowed_export / "evidence.json"
        ok_ev = requests.post(
            base_url + "/api/dbg/evidence",
            headers=headers,
            json={"output_path": str(good_out)},
            timeout=2,
        )
        assert ok_ev.status_code == 200
        assert good_out.is_file()

        bad_out = outside_dir / "escape.json"
        bad_ev = requests.post(
            base_url + "/api/dbg/evidence",
            headers=headers,
            json={"output_path": str(bad_out)},
            timeout=2,
        )
        assert bad_ev.status_code == 403
        assert not bad_out.exists()

        sensitive_out = allowed_export / ".ph4ntom_ida_bridge_token"
        sens_ev = requests.post(
            base_url + "/api/dbg/breakpoints/export",
            headers=headers,
            json={"output_path": str(sensitive_out)},
            timeout=2,
        )
        assert sens_ev.status_code == 403
        assert not sensitive_out.exists()

        ok_imp = requests.post(
            base_url + "/api/dbg/breakpoints/import",
            headers=headers,
            json={"input_path": str(trusted_bp)},
            timeout=2,
        )
        assert ok_imp.status_code == 200 and ok_imp.json()["success"] is True

        bad_imp = requests.post(
            base_url + "/api/dbg/breakpoints/import",
            headers=headers,
            json={"input_path": str(outside_bp)},
            timeout=2,
        )
        assert bad_imp.status_code == 403
    finally:
        _stop_test_server(server, thread)


def test_instance_registry_hardening_dead_pid_pruning_and_token_validation(monkeypatch, tmp_path):
    reg_file = tmp_path / ".ph4ntom_ida_instances.json"
    monkeypatch.setenv("IDA_BRIDGE_INSTANCES_FILE", str(reg_file))
    plugin, token_file = _load_plugin(monkeypatch, tmp_path)
    plugin.ida_nalt.get_root_filename = lambda: "firmware.bin"
    plugin.ida_nalt.get_input_file_path = lambda: str(tmp_path / "firmware.bin")

    # Seed a stale dead PID entry before registering current live instance
    reg_file.write_text(
        json.dumps(
            {
                "13388": {
                    "port": 13388,
                    "url": "http://127.0.0.1:13388",
                    "pid": 99999999,
                    "filename": "dead.exe",
                    "filepath": "C:\\dead.exe",
                    "token_path": str(tmp_path / ".ph4ntom_ida_bridge_token_13388"),
                }
            }
        ),
        encoding="utf-8",
    )

    private_writes = []
    orig_create_private = plugin._create_private_file

    def tracked_private(path, content):
        private_writes.append(Path(path).name)
        return orig_create_private(path, content)

    monkeypatch.setattr(plugin, "_create_private_file", tracked_private)
    plugin._register_instance("127.0.0.1", 13370, str(token_file))

    assert private_writes, "Instance registry should be written via _create_private_file"
    listed_plugin = plugin.list_instances_api()["instances"]
    assert all(item.get("pid") != 99999999 for item in listed_plugin)
    assert any(item.get("port") == 13370 for item in listed_plugin)

    # Poison registry with an untrusted arbitrary file as token_path
    poison_secret = tmp_path / "arbitrary_secret.txt"
    poison_secret.write_text("TOP_SECRET_FILE_CONTENT", encoding="utf-8")
    valid_home_token = tmp_path / ".ph4ntom_ida_bridge_token_13371"
    valid_home_token.write_text("a" * 64, encoding="utf-8")

    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))
    reg_file.write_text(
        json.dumps(
            {
                "13370": {
                    "port": 13370,
                    "url": "http://127.0.0.1:13370",
                    "pid": os.getpid(),
                    "filename": "poisoned.exe",
                    "token_path": str(poison_secret),
                },
                "13371": {
                    "port": 13371,
                    "url": "http://127.0.0.1:13371",
                    "pid": os.getpid(),
                    "filename": "clean.exe",
                    "token_path": str(valid_home_token),
                },
                "13389": {
                    "port": 13389,
                    "url": "http://127.0.0.1:13389",
                    "pid": 99999998,
                    "filename": "dead2.exe",
                    "token_path": str(valid_home_token),
                },
            }
        ),
        encoding="utf-8",
    )

    client = BridgeClient(base_url="http://127.0.0.1:13370")
    try:
        listed_client = client.list_instances()["instances"]
        assert all(item.get("pid") != 99999998 for item in listed_client)

        sel_poison = client.select_instance("poisoned.exe")
        assert sel_poison["success"] is True
        auth_header = client.session.headers.get("Authorization", "")
        assert "TOP_SECRET_FILE_CONTENT" not in auth_header

        sel_clean = client.select_instance("clean.exe")
        assert sel_clean["success"] is True
        assert client.session.headers.get("Authorization") == "Bearer " + ("a" * 64)
    finally:
        client.close()

    # UI hook refreshes registry when a new database is opened in IDA
    plugin._server = types.SimpleNamespace(server_port=13370)
    plugin._token_path = str(valid_home_token)
    plugin.ida_nalt.get_root_filename = lambda: "reloaded_new.bin"
    assert hasattr(plugin.ui_hooks, "database_inited")
    plugin.ui_hooks.database_inited(0, "")
    updated = json.loads(reg_file.read_text(encoding="utf-8"))
    assert updated["13370"]["filename"] == "reloaded_new.bin"
    plugin._server = None


def test_run_synced_preserves_client_errors_and_strips_internal_tracebacks(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    @plugin.get_route(r"/api/test/value_err")
    def _r_val(self, match, params):
        self.send_json(plugin.safe_read(lambda: (_ for _ in ()).throw(ValueError("bad input value"))))

    @plugin.get_route(r"/api/test/perm_err")
    def _r_perm(self, match, params):
        self.send_json(plugin.safe_read(lambda: (_ for _ in ()).throw(PermissionError("policy denied"))))

    @plugin.get_route(r"/api/test/boom_err")
    def _r_boom(self, match, params):
        self.send_json(plugin.safe_read(lambda: 1 / 0))

    server, thread, base_url, headers = _start_test_server(plugin)
    try:
        r_val = requests.get(base_url + "/api/test/value_err", headers=headers, timeout=2)
        r_perm = requests.get(base_url + "/api/test/perm_err", headers=headers, timeout=2)
        r_boom = requests.get(base_url + "/api/test/boom_err", headers=headers, timeout=2)

        assert r_val.status_code == 400
        assert r_val.json()["error"] == "bad input value"

        assert r_perm.status_code == 403
        assert r_perm.json()["error"] == "policy denied"

        assert r_boom.status_code == 500
        err_text = r_boom.json()["error"]
        assert "Traceback (most recent call last)" not in err_text
        assert "ph4ntom_ida_bridge.py" not in err_text
        assert "ZeroDivisionError" in err_text
    finally:
        _stop_test_server(server, thread)

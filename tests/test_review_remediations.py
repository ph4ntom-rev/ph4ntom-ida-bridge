"""Regression tests for all Cycle 5 independent adversarial review findings."""
import asyncio
import json
import sys
import threading
import types
from unittest.mock import Mock, patch

import requests

import cli
import mcp_server
from core.client import BridgeClient
from tests.test_plugin_runtime import _load_plugin


def _start_server(plugin):
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    plugin._server = server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": f"Bearer {server.auth_token}"}
    return server, thread, base_url, headers


def _stop_server(server, thread):
    server.stopping.set()
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_dbg_run_to_attach_and_local_load_respect_dbg_start_gate(monkeypatch, tmp_path):
    """CRITICAL-1 & HIGH-1: run_to (when debugger off), attach, and local load must require ALLOW_DBG_START or ALLOW_EXEC."""
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    plugin.ALLOW_SCRIPT_EXECUTION = False
    plugin.ALLOW_DBG_START = False
    plugin.ida_dbg.is_debugger_on = lambda: False
    plugin.ida_dbg.run_to = lambda ea: True
    plugin.ida_dbg.attach_process = lambda pid, ev: 1
    plugin.ida_dbg.load_debugger = lambda name, remote: True

    server, thread, base_url, headers = _start_server(plugin)
    try:
        r_runto = requests.post(base_url + "/api/dbg/run-to", headers=headers, json={"ea": "0x1000"}, timeout=2)
        r_attach = requests.post(base_url + "/api/dbg/attach", headers=headers, json={"pid": 1234}, timeout=2)
        r_load_local = requests.post(base_url + "/api/dbg/load", headers=headers, json={"name": "win32", "remote": False}, timeout=2)
        assert r_runto.status_code == 403
        assert r_attach.status_code == 403
        assert r_load_local.status_code == 403

        # Stepping/continue/pause when debugger is off must return clean error, not call backend
        r_step = requests.post(base_url + "/api/dbg/step-into", headers=headers, json={}, timeout=2)
        assert r_step.status_code == 200 and "No active debugger" in r_step.json().get("error", "")

        # Enabling ALLOW_DBG_START unlocks run_to, attach, and local load
        plugin.ALLOW_DBG_START = True
        assert requests.post(base_url + "/api/dbg/run-to", headers=headers, json={"ea": "0x1000"}, timeout=2).status_code == 200
        assert requests.post(base_url + "/api/dbg/attach", headers=headers, json={"pid": 1234}, timeout=2).status_code == 200
        assert requests.post(base_url + "/api/dbg/load", headers=headers, json={"name": "win32", "remote": False}, timeout=2).status_code == 200
    finally:
        _stop_server(server, thread)


def test_dbg_wait_dec_notask_and_ida95_exception_event_extraction(monkeypatch, tmp_path):
    """CRITICAL-2: DEC_NOTASK (-2) returns immediately without looping; EXCEPTION (0x40) extracts ev.exc()."""
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    calls = []
    plugin.ida_dbg.DEC_NOTASK = -2
    plugin.ida_dbg.DEC_TIMEOUT = 0
    plugin.ida_dbg.WFNE_USEC = 0x20
    plugin.ida_dbg.is_debugger_on = lambda: False
    plugin.ida_dbg.get_process_state = lambda: 0
    plugin.ida_dbg.wait_for_next_event = lambda wfne, t: calls.append((wfne, t)) or -2

    res_notask = plugin.dbg_wait_event(timeout=5)
    assert len(calls) == 1, "DEC_NOTASK (-2) must terminate wait immediately without retrying"
    assert res_notask["timed_out"] is False
    assert res_notask["event_code"] == -2

    # IDA 9.5 debug_event_t.exc() extraction when eid() == EXCEPTION (0x40)
    ida_idd = types.ModuleType("ida_idd")
    ida_idd.EXCEPTION = 0x40
    ida_idd.get_debug_event_name = lambda ev: "EXCEPTION"
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)

    exc_info = types.SimpleNamespace(code=0xC0000005, ea=0x401122, info="Access violation")
    fake_ev = types.SimpleNamespace(
        eid=lambda: 0x40,
        pid=999,
        tid=101,
        ea=0x401122,
        handled=False,
        exc=lambda: exc_info,
    )
    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_process_state = lambda: -1
    plugin.ida_dbg.wait_for_next_event = lambda wfne, t: 0x40
    plugin.ida_dbg.get_debug_event = lambda: fake_ev

    res_exc = plugin.dbg_wait_event(timeout=1)
    assert res_exc["success"] is True
    assert res_exc["event"]["exc_code"] == "0xc0000005"
    assert res_exc["event"]["exc_ea"] == "0x401122"
    assert res_exc["event"]["exc_info"] == "Access violation"


def test_thread_selection_failure_aborts_set_reg_appcall_and_fixes_get_regs_ip(monkeypatch, tmp_path):
    """HIGH-2: Failed select_thread must NEVER mutate prev_tid in set_reg/appcall or leak prev_tid IP in get_regs."""
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    plugin.ALLOW_SCRIPT_EXECUTION = True

    cur = {"tid": 100}
    reg_writes = []
    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_process_state = lambda: -1
    plugin.ida_dbg.get_current_thread = lambda: cur["tid"]
    plugin.ida_dbg.select_thread = lambda t: False  # Simulate invalid TID / failed switch!
    plugin.ida_dbg.set_reg_val = lambda name, val: reg_writes.append((cur["tid"], name, val)) or True
    plugin.ida_dbg.get_ip_val = lambda: 0xDEAD100  # Thread 100's IP!
    plugin.ida_dbg.get_sp_val = lambda: 0xBEEF100

    # 1. dbg_set_reg(tid=999) must abort and NOT write to thread 100
    res_set = plugin.dbg_set_reg("rax", 0x42, tid=999)
    assert res_set.get("success") is False
    assert reg_writes == [], "Must never write register on prev_tid when select_thread(tid) returns False!"

    # 2. dbg_appcall_api(tid=999) must abort when select_thread fails, and restore prev_tid when it succeeds
    ida_idd = types.ModuleType("ida_idd")
    appcall_tids = []
    ida_idd.Appcall = {"target_fn": lambda *a: appcall_tids.append(cur["tid"]) or 7}
    ida_idd.get_dbg = lambda: types.SimpleNamespace(
        regs=lambda idx: [
            types.SimpleNamespace(name="pc", dtype=0),
            types.SimpleNamespace(name="sp", dtype=0),
        ][idx]
    )
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)

    res_app_fail = plugin.dbg_appcall_api("target_fn", args=[], tid=999)
    assert res_app_fail.get("success") is False
    assert appcall_tids == []

    # 3. dbg_get_regs(tid=200) when select_thread fails falls back to get_reg_vals(200) and uses thread 200's PC/SP, NOT thread 100's!
    plugin.ida_dbg.get_reg_vals = lambda t: [
        types.SimpleNamespace(pyval=lambda dt: 0x402000),
        types.SimpleNamespace(pyval=lambda dt: 0x7FFF200),
    ]
    res_get = plugin.dbg_get_regs(tid=200)
    assert res_get["ip"] == "0x402000"
    assert res_get["sp"] == "0x7fff200"


def test_import_c_header_uses_trusted_path_validation_and_hides_host_paths(monkeypatch, tmp_path):
    """HIGH-3 & MEDIUM-1: import_c_header validates types/creds/roots via 403/400, and 500s/schema never leak host paths."""
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    hdr_dir = tmp_path / "headers"
    hdr_dir.mkdir()
    good_hdr = hdr_dir / "types.h"
    good_hdr.write_text("struct S { int x; };\n", encoding="utf-8")
    cred_spoof = hdr_dir / ".ph4ntom_ida_bridge_token"
    cred_spoof.write_text("secret", encoding="utf-8")
    plugin.ALLOWED_IMPORT_ROOTS = (str(hdr_dir.resolve()),)
    plugin.idc.parse_decls = lambda p, flags: 0

    server, thread, base_url, headers = _start_server(plugin)
    try:
        # Non-string path -> 400 (not 500)
        r_bad_type = requests.post(base_url + "/api/import-header", headers=headers, json={"path": 123}, timeout=2)
        assert r_bad_type.status_code == 400

        # Credential filename inside allowed root -> 403
        r_cred = requests.post(base_url + "/api/import-header", headers=headers, json={"path": str(cred_spoof)}, timeout=2)
        assert r_cred.status_code == 403

        # Valid header succeeds without leaking full host directory path
        r_ok = requests.post(base_url + "/api/import-header", headers=headers, json={"path": str(good_hdr)}, timeout=2)
        assert r_ok.status_code == 200 and r_ok.json()["success"] is True
        assert str(hdr_dir) not in json.dumps(r_ok.json())

        # Unauthenticated GET /api/schema error and unhandled OSError in route must NOT leak host paths
        plugin._cached_schema = None
        monkeypatch.setattr(plugin, "_schema_candidates", lambda: [str(good_hdr)])
        monkeypatch.setattr(plugin.json, "load", lambda *_a, **_k: (_ for _ in ()).throw(OSError(13, "Denied", r"C:\Secret\Host\api_schema.json")))
        r_schema = requests.get(base_url + "/api/schema", timeout=2)
        assert r_schema.status_code == 500
        assert "Secret" not in r_schema.text and "api_schema.json" not in r_schema.text
    finally:
        _stop_server(server, thread)


def test_readonly_permits_safe_post_queries_and_arm_regs_callgraph_memsearch_vtable(monkeypatch, tmp_path, capsys):
    """MEDIUM-2, MEDIUM-3, MEDIUM-4, and Minor Polish items."""
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    # 1. ARM32 registers included in default _read_regs_inner
    arm_vals = {"r0": 0x10, "r1": 0x20, "lr": 0x8004, "sp": 0x7000, "pc": 0x8000, "cpsr": 0x60000010}
    plugin.ida_dbg.get_current_thread = lambda: 1
    plugin.ida_dbg.get_reg_val = lambda n: arm_vals.get(n)
    regs = plugin._read_regs_inner(plugin.ida_dbg)
    assert regs["r0"] == "0x10" and regs["lr"] == "0x8004" and regs["cpsr"] == "0x60000010"

    # 2. get_call_graph(depth=1) includes direct callees (1 hop) and normalizes mid-function EA to start_ea
    funcs = {
        0x1000: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        0x1004: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1010),
        0x2000: types.SimpleNamespace(start_ea=0x2000, end_ea=0x2010),
        0x3000: types.SimpleNamespace(start_ea=0x3000, end_ea=0x3010),
    }
    plugin.ida_funcs.get_func = lambda ea: funcs.get(ea)
    plugin.ida_funcs.get_func_name = lambda ea: f"fn_{funcs[ea].start_ea:x}"
    plugin.idautils.FuncItems = lambda ea: iter([ea])
    xrefs = {
        0x1000: [types.SimpleNamespace(frm=0x1000, to=0x2000, type=17)],
        0x2000: [types.SimpleNamespace(frm=0x2000, to=0x3000, type=17)],
    }
    plugin.idautils.XrefsFrom = lambda ea: xrefs.get(ea, [])
    cg1 = plugin.get_call_graph(0x1004, depth=1)
    assert cg1["ea"] == "0x1000"
    assert len(cg1["calls"]) == 1 and cg1["calls"][0]["ea"] == "0x2000"
    assert cg1["calls"][0]["calls"] == []

    # 3. dbg_search_memory_api scans regions > 16 MiB (e.g. 20 MiB module) instead of skipping them
    plugin.ida_dbg.is_debugger_on = lambda: True
    monkeypatch.setattr(
        plugin,
        "dbg_get_memory_map",
        lambda: {"regions": [{"start": "0x10000000", "end": "0x11400000", "perm": "r-x"}]},  # 20 MiB
    )
    ida_idd = types.ModuleType("ida_idd")
    ida_idd.dbg_read_memory = lambda addr, sz: (b"MAGIC_HIT" + b"\x00" * (sz - 9)) if addr == 0x10000000 else b"\x00" * sz
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)
    msearch = plugin.dbg_search_memory_api("MAGIC_HIT")
    assert msearch["count"] == 1 and msearch["results"][0]["ea"] == "0x10000000"

    # 4. create_vtable_struct_api passes PT_REPLACE so existing vtable structs can be updated
    plugin.idc.PT_TYP = 1
    plugin.idc.PT_REPLACE = 0x80
    seen_flags = []
    plugin.idc.parse_decls = lambda decl, flags: seen_flags.append(flags) or 0
    monkeypatch.setattr(
        plugin,
        "get_vtable",
        lambda ea, max_entries=256: {"entries": [{"index": 0, "name": "Tick", "prototype": None}]},
    )
    vt_res = plugin.create_vtable_struct_api(0x5000, name="VTable_5000")
    assert vt_res["success"] is True
    assert bool(seen_flags[0] & 0x80)

    # 5. READ_ONLY allows pure read POST (/api/dbg/search-memory) while blocking mutating POST (/api/save)
    plugin.READ_ONLY = True
    server, thread, base_url, headers = _start_server(plugin)
    try:
        r_ro_search = requests.post(base_url + "/api/dbg/search-memory", headers=headers, json={"pattern": "MAGIC_HIT"}, timeout=2)
        r_ro_save = requests.post(base_url + "/api/save", headers=headers, json={}, timeout=2)
        assert r_ro_search.status_code == 200 and r_ro_search.json()["count"] == 1
        assert r_ro_save.status_code == 403
    finally:
        _stop_server(server, thread)

    # 6. MCP wait timeout > 30s forwards extended HTTP timeout & timed_out=True does not raise ToolError
    captured_timeouts = []
    monkeypatch.setattr(
        mcp_server.client,
        "call_api",
        lambda method, path, payload=None, timeout=None: (
            captured_timeouts.append(timeout)
            or {"success": False, "timed_out": True, "status": "running", "event_code": 0}
        ),
    )
    wait_out = json.loads(mcp_server.dbg_wait_event(timeout=60))
    assert wait_out["timed_out"] is True
    assert captured_timeouts[0] is not None and captured_timeouts[0] >= 65.0

    # 7. MCP tools that accept local file export paths do NOT advertise readOnlyHint=True
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert tools["decompile_batch"].annotations.read_only_hint is False
    assert tools["dbg_export_breakpoints"].annotations.read_only_hint is False
    assert tools["capture_evidence"].annotations.read_only_hint is False

    # 8. BridgeClient.select_instance clears sticky _explicit_token when switching instances
    tok_b = tmp_path / ".ph4ntom_ida_bridge_token_13371"
    tok_b.write_text("token_for_b", encoding="utf-8")
    reg = tmp_path / ".ph4ntom_ida_instances.json"
    reg.write_text(
        json.dumps({"13371": {"port": 13371, "url": "http://127.0.0.1:13371", "filename": "b.dll", "token_path": str(tok_b)}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("IDA_BRIDGE_INSTANCES_FILE", str(reg))
    monkeypatch.setenv("IDA_BRIDGE_TOKEN_FILE", str(tok_b))
    c = BridgeClient("http://127.0.0.1:13370", token="sticky_token_a")
    try:
        c.select_instance("b.dll")
        assert c.session.headers.get("Authorization") == "Bearer token_for_b"
    finally:
        c.close()

    # 9. cli.py instances avoids double-nesting {"instances": {"instances": [...]}}
    mock_c = Mock()
    mock_c.__enter__ = Mock(return_value=mock_c)
    mock_c.__exit__ = Mock(return_value=None)
    mock_c.base_url = "http://127.0.0.1:13370"
    mock_c.list_instances.return_value = {"instances": [{"port": 13370}], "active_url": "http://127.0.0.1:13370", "count": 1}
    with patch("cli.BridgeClient", return_value=mock_c):
        cli.main(["instances"])
    inst_out = json.loads(capsys.readouterr().out)
    assert isinstance(inst_out["instances"], list)
    assert inst_out["count"] == 1


def test_bundled_ida_pro_skill_and_cli_install_skill(tmp_path, capsys):
    """Bundled ida-pro Agent Skill follows SKILL.md spec, avoids removed IDA 9 modules, and installs via cli.py."""
    root = cli.PROJECT_ROOT
    skill_dir = root / ".agents" / "skills" / "ida-pro"
    skill_md = skill_dir / "SKILL.md"
    assert skill_md.is_file()
    text = skill_md.read_text(encoding="utf-8")
    assert text.startswith("---\nname: ida-pro\ndescription:")
    assert "Use when " in text.split("---", 2)[1]
    for ref_name in (
        "idapython-95-sdk.md",
        "firmware-types-and-vtables.md",
        "debugging-microcode-and-batch.md",
    ):
        assert (skill_dir / "references" / ref_name).is_file()

    # agent_config.json must not claim removed IDA 9.x modules ida_struct / ida_enum exist
    agent_cfg = json.loads((root / "agent_config.json").read_text(encoding="utf-8"))
    mods = set(agent_cfg["script_execution"]["available_modules"])
    assert "ida_struct" not in mods and "ida_enum" not in mods

    # cli.py install-skill installs SKILL.md + references/ and respects --force
    dest_root = tmp_path / "skills_dest"
    rc1 = cli.main(["install-skill", "--dest", str(dest_root)])
    out1 = json.loads(capsys.readouterr().out)
    assert rc1 == 0 and out1["success"] is True
    installed_md = dest_root / "ida-pro" / "SKILL.md"
    assert installed_md.is_file()
    assert (dest_root / "ida-pro" / "references" / "idapython-95-sdk.md").is_file()

    # Differing file without --force refuses overwrite; --force replaces cleanly
    installed_md.write_text("modified", encoding="utf-8")
    rc2 = cli.main(["install-skill", "--dest", str(dest_root)])
    out2 = json.loads(capsys.readouterr().out)
    assert rc2 == 1 and out2["success"] is False

    rc3 = cli.main(["install-skill", "--dest", str(dest_root), "--force"])
    out3 = json.loads(capsys.readouterr().out)
    assert rc3 == 0 and out3["success"] is True
    assert installed_md.read_text(encoding="utf-8") == text


import sys
import threading
import types

import requests

from tests.test_plugin_runtime import _load_plugin


def _start_server(plugin):
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {"Authorization": f"Bearer {plugin.AUTH_TOKEN}"}
    return server, thread, base_url, headers


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_strings_endpoint_default_limit_and_lazy_strlist_build(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    build_calls = []

    class _StrInfo:
        def __init__(self):
            self.ea = 0x2000
            self.length = 5
            self.strtype = 0

    ida_strlist = types.ModuleType("ida_strlist")
    qty_state = [0]

    def build_strlist():
        build_calls.append(True)
        qty_state[0] = 2

    def get_strlist_item(sl, idx):
        sl.ea = 0x2000 + idx * 0x10
        sl.length = 5
        sl.strtype = 0
        return True

    ida_strlist.build_strlist = build_strlist
    ida_strlist.string_info_t = _StrInfo
    ida_strlist.get_strlist_qty = lambda: qty_state[0]
    ida_strlist.get_strlist_item = get_strlist_item
    monkeypatch.setitem(sys.modules, "ida_strlist", ida_strlist)
    plugin.ida_bytes.get_strlit_contents = lambda ea, ln, st: f"str_{ea:x}".encode("utf-8")

    server, thread, base_url, headers = _start_server(plugin)
    try:
        # 1. GET /api/strings without ?limit= must return 200 and build initially empty strlist once
        r1 = requests.get(base_url + "/api/strings", headers=headers, timeout=2)
        assert r1.status_code == 200
        data1 = r1.json()
        assert data1["limit"] == plugin.MAX_STRINGS
        assert data1["returned"] == 2
        assert len(build_calls) == 1

        # 2. Subsequent page when qty > 0 must NOT rebuild strlist unless refresh=1
        r2 = requests.get(base_url + "/api/strings", headers=headers, params={"offset": 1, "limit": 1}, timeout=2)
        assert r2.status_code == 200
        assert r2.json()["returned"] == 1
        assert len(build_calls) == 1

        # 3. Explicit refresh=1 forces rebuild
        r3 = requests.get(base_url + "/api/strings", headers=headers, params={"refresh": "1"}, timeout=2)
        assert r3.status_code == 200
        assert len(build_calls) == 2
    finally:
        _stop_server(server, thread)


def test_decompiler_timeout_seconds_to_milliseconds_conversion(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    plugin.HAS_HEXRAYS = True
    current_ms = [30000]

    def set_timeout(ms):
        prev = current_ms[0]
        current_ms[0] = ms
        return prev

    plugin.ida_hexrays.get_decompiler_timeout = lambda: current_ms[0]
    plugin.ida_hexrays.set_decompiler_timeout = set_timeout

    server, thread, base_url, headers = _start_server(plugin)
    try:
        post_res = requests.post(
            base_url + "/api/decompiler/timeout",
            headers=headers,
            json={"seconds": 15},
            timeout=2,
        )
        assert post_res.status_code == 200
        pdata = post_res.json()
        assert current_ms[0] == 15000
        assert pdata["timeout_ms"] == 15000
        assert pdata["seconds"] == 15.0

        get_res = requests.get(base_url + "/api/decompiler/timeout", headers=headers, timeout=2)
        assert get_res.status_code == 200
        gdata = get_res.json()
        assert gdata["timeout_ms"] == 15000
        assert gdata["seconds"] == 15.0
    finally:
        _stop_server(server, thread)


def test_capture_evidence_and_bp_export_import_contract_completeness(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    export_dir = tmp_path / "trusted_exports"
    export_dir.mkdir()
    plugin.ALLOWED_EXPORT_ROOTS = (str(export_dir.resolve()),)
    plugin.ALLOWED_IMPORT_ROOTS = (str(export_dir.resolve()),)
    plugin.HAS_HEXRAYS = False
    plugin.ida_dbg.is_debugger_on = lambda: False
    plugin.ida_dbg.get_bpt_qty = lambda: 0
    plugin.idc.get_screen_ea = lambda: 0x1000
    plugin.idc.generate_disasm_line = lambda ea, flags: f"nop_{ea:x}"
    plugin.idc.next_head = lambda ea, max_ea: ea + 4
    plugin.ida_bytes.get_item_size = lambda ea: 4
    plugin.ida_bytes.get_bytes = lambda ea, sz: b"ABCD"[:sz]
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1020)
    plugin.ida_funcs.get_func_name = lambda ea: "target_fn"

    server, thread, base_url, headers = _start_server(plugin)
    try:
        ev_file = export_dir / "ev.json"
        r_ev = requests.post(
            base_url + "/api/dbg/evidence",
            headers=headers,
            json={
                "ea": "0x1000",
                "memory_ranges": [{"ea": "0x1000", "size": 4, "label": "hdr"}],
                "notes": "important crash state",
                "include_stack": False,
                "include_modules": False,
                "include_breakpoints": False,
                "save_path": str(ev_file),
            },
            timeout=2,
        )
        assert r_ev.status_code == 200
        ev = r_ev.json()
        assert ev["notes"] == "important crash state"
        assert len(ev["target"]["disasm"]) > 0
        assert ev["memory_ranges"][0]["ascii"] == "ABCD"
        assert ev["saved_to"] == str(ev_file.resolve())
        assert ev["debugger"]["breakpoints"] == []

        bp_file = export_dir / "bps_saved.json"
        r_exp = requests.post(
            base_url + "/api/dbg/breakpoints/export",
            headers=headers,
            json={"save_path": str(bp_file)},
            timeout=2,
        )
        assert r_exp.status_code == 200
        assert bp_file.is_file()

        r_imp = requests.post(
            base_url + "/api/dbg/breakpoints/import",
            headers=headers,
            json={"load_path": str(bp_file)},
            timeout=2,
        )
        assert r_imp.status_code == 200 and r_imp.json()["success"] is True
    finally:
        _stop_server(server, thread)


def test_invalid_regex_filters_fallback_and_class_filter_routes(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    class _StrInfo:
        ea = 0x2000
        length = 12
        strtype = 0

    ida_strlist = types.ModuleType("ida_strlist")
    ida_strlist.build_strlist = lambda: None
    ida_strlist.string_info_t = _StrInfo
    ida_strlist.get_strlist_qty = lambda: 1
    ida_strlist.get_strlist_item = lambda sl, idx: True
    monkeypatch.setitem(sys.modules, "ida_strlist", ida_strlist)
    plugin.ida_bytes.get_strlit_contents = lambda ea, ln, st: b"val[unclosed_tag"

    plugin.idautils.XrefsTo = lambda ea, *a: [types.SimpleNamespace(frm=0x1000, to=ea, type=17)]
    plugin.idautils.XrefsFrom = lambda ea: [types.SimpleNamespace(frm=ea, to=0x2000, type=17)]
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 4, size=lambda: 4)
    plugin.ida_funcs.get_func_name = lambda ea: "fn_[unclosed"
    plugin.idc.next_head = lambda ea, limit: ea + 4

    # Invalid regex "[unclosed" must fall back cleanly to case-insensitive substring match
    assert plugin.get_strings(filter_regex="[unclosed")["returned"] == 1
    assert plugin.get_xrefs_to(0x3000, filter_str="[unclosed")["count"] == 1
    assert plugin.get_xrefs_from(0x1000, filter_str="[unclosed")["count"] == 1

    # Class routes must forward query params
    captured_cls = {}
    captured_detail = {}
    monkeypatch.setattr(
        plugin,
        "get_classes_api",
        lambda filter_pattern=None, toplevel_only=False, include_hidden=False: (
            captured_cls.update(
                filter_pattern=filter_pattern,
                toplevel_only=toplevel_only,
                include_hidden=include_hidden,
            )
            or {"classes": [], "count": 0}
        ),
    )
    monkeypatch.setattr(
        plugin,
        "get_class_details_api",
        lambda name, ea=None, render=True, no_bodies=False: (
            captured_detail.update(name=name, ea=ea, render=render, no_bodies=no_bodies)
            or {"name": name}
        ),
    )

    server, thread, base_url, headers = _start_server(plugin)
    try:
        rc = requests.get(
            base_url + "/api/classes",
            headers=headers,
            params={"filter": "CNet*", "toplevel": "1", "hidden": "true"},
            timeout=2,
        )
        rd = requests.get(
            base_url + "/api/class/CNetChan",
            headers=headers,
            params={"ea": "0x1000", "render": "0", "no_bodies": "1"},
            timeout=2,
        )
        assert rc.status_code == 200
        assert captured_cls == {"filter_pattern": "CNet*", "toplevel_only": True, "include_hidden": True}
        assert rd.status_code == 200
        assert captured_detail == {"name": "CNetChan", "ea": 0x1000, "render": False, "no_bodies": True}
    finally:
        _stop_server(server, thread)


def test_firmware_module_rva_and_badaddr_entry_point(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_procname = lambda: "mipsl"
    ida_ida.inf_is_64bit = lambda: False
    ida_ida.inf_is_32bit_exactly = lambda: True
    ida_ida.inf_get_min_ea = lambda: 0xB8970000
    ida_ida.inf_get_max_ea = lambda: 0xB8980000
    ida_ida.inf_get_start_ea = lambda: plugin.ida_idaapi.BADADDR
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)

    plugin.ida_nalt.get_imagebase = lambda: 0
    plugin.ida_nalt.get_root_filename = lambda: "sec_0_EMEM_0xb8970000.bin"
    seg_obj = types.SimpleNamespace(start_ea=0xB8970000, end_ea=0xB8980000)
    plugin.ida_segment.getseg = lambda ea: seg_obj if 0xB8970000 <= ea < 0xB8980000 else None
    plugin.ida_segment.get_segm_name = lambda s: "ROM"

    assert plugin._format_module_rva_inner(0xB8977498) == "ROM+0x7498"
    info = plugin.get_info()
    assert info["entry_point"] is None


def test_parse_ea_symbol_precedence_hyphenated_modules_and_batch_symbolic_ea(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    symbols = {"add": 0x402000, "main": 0x401000}
    plugin.ida_name.get_name_ea = lambda bad, name: symbols.get(name, bad)
    plugin.ida_name.get_name = lambda ea: next((k for k, v in symbols.items() if v == ea), f"sub_{ea:x}")
    plugin.ida_name.SN_NOWARN = 1
    plugin.ida_name.VNT_IDENT = 0
    plugin.ida_name.validate_name = lambda name, kind: name if name.isidentifier() else ""
    plugin.ida_name.set_name = lambda ea, name, flags: symbols.__setitem__(name, ea) is None or True
    plugin.ida_bytes.is_mapped = lambda ea: 0x400000 <= ea < 0x500000
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=0x401000) if ea == 0x401000 else None
    plugin.idc.get_cmt = lambda ea, rep: ""
    plugin.idc.set_cmt = lambda ea, val, rep: True

    class _HyphenMod:
        name = "/usr/lib/libfoo-1.so"
        base = 0x7F000000
        size = 0x10000

    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_modules = lambda: [_HyphenMod()]

    # Unprefixed hex-letter symbol "add" resolves to symbol 0x402000, while "0xadd" resolves to 0xadd
    assert plugin.parse_ea("add") == 0x402000
    assert plugin.parse_ea("0xadd") == 0xADD
    assert plugin.parse_ea("libfoo-1.so+0x20") == 0x7F000020

    # execute_batch supports symbolic and symbol+offset addresses
    res = plugin.execute_batch(
        [{"op": "comment", "ea": "main+0x4", "comment": "patched check"}],
        dry_run=True,
    )
    assert res["status"] == "preview"
    assert res["plan"][0]["ea"] == "0x401004"


def test_xrefs_from_multiple_callsites_funcitems_vtable_thumb_and_switch(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    # 1. Discontinuous chunks via FuncItems + multiple calls to same target
    func_chunks = [0x1000, 0x1004, 0x5000]  # 0x5000 is a discontinuous tail chunk!
    plugin.idautils.FuncItems = lambda ea: iter(func_chunks)
    xref_map = {
        0x1000: [types.SimpleNamespace(frm=0x1000, to=0x3000, type=17)],
        0x1004: [types.SimpleNamespace(frm=0x1004, to=0x3000, type=17)],
        0x5000: [types.SimpleNamespace(frm=0x5000, to=0x4000, type=17)],
    }
    plugin.idautils.XrefsFrom = lambda ea: xref_map.get(ea, [])
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 8, size=lambda: 8)
    plugin.ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
    plugin.idc.generate_disasm_line = lambda ea, f: f"inst_{ea:x}"

    xf = plugin.get_xrefs_from(0x1000)
    assert xf["count"] == 3  # both call sites to 0x3000 AND tail chunk call to 0x4000!
    dis = plugin.get_disasm(0x1000)
    assert [d["ea"] for d in dis["disasm"]] == ["0x1000", "0x1004", "0x5000"]

    # 2. ARM 32-bit Thumb vtable bit masking + typed C prototype in create_vtable_struct_api
    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_procname = lambda: "ARM"
    ida_ida.inf_is_64bit = lambda: False
    monkeypatch.setitem(sys.modules, "ida_ida", ida_ida)

    dwords = {0x9000: 0x8001, 0x9004: 0}  # 0x8001 has Thumb bit set!
    plugin.ida_bytes.get_dword = lambda ea: dwords.get(ea, 0)
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=0x8000, size=lambda: 16) if ea == 0x8000 else None
    plugin.ida_funcs.get_func_name = lambda ea: "Widget_Draw" if ea == 0x8000 else None

    class _FakeTinfo:
        def __str__(self):
            return "int __fastcall(void *self, int flags)"

    plugin.ida_typeinf.tinfo_t = _FakeTinfo
    plugin.ida_nalt.get_tinfo = lambda tif, ea: ea == 0x8000
    decls_seen = []
    plugin.idc.PT_TYP = 1
    plugin.idc.parse_decls = lambda decl, flags: decls_seen.append(decl) or 0

    vt = plugin.get_vtable(0x9000)
    assert vt["count"] == 1
    assert vt["entries"][0]["target"] == "0x8000"
    st_res = plugin.create_vtable_struct_api(0x9000, name="WidgetVtbl")
    assert st_res["success"] is True
    assert "int" in st_res["c_declaration"] and "int flags" in st_res["c_declaration"]

    # 3. Switch info via ida_xref.calc_switch_cases
    ida_xref = types.ModuleType("ida_xref")
    ida_xref.calc_switch_cases = lambda ea, si: types.SimpleNamespace(
        cases=[[0, 1], [2]],
        targets=[0x8100, 0x8200],
    )
    monkeypatch.setitem(sys.modules, "ida_xref", ida_xref)
    plugin.ida_nalt.get_switch_info = lambda ea: types.SimpleNamespace(
        jumps=0x9500,
        defjump=0x8300,
        get_jtable_size=lambda: 2,
        get_jtable_element_size=lambda: 4,
        get_shift=lambda: 0,
    )
    plugin.idc.BADADDR = plugin.ida_idaapi.BADADDR
    sw = plugin.get_switch_info(0x8050)
    assert sw["count"] == 2
    assert sw["cases"][0]["values"] == [0, 1]
    assert sw["cases"][0]["target"] == "0x8100"


def test_debugger_bp_tid_clear_exception_preservation_and_telescoping(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    # 1. dbg_update_bp(tid=0) clears thread filter
    class _FakeBpt:
        ea = 0x1000
        size = 1
        type = 4
        flags = 8
        condition = ""
        elang = "Python"
        pass_count = 0

    plugin.ida_dbg.bpt_t = _FakeBpt
    plugin.ida_dbg.get_bpt = lambda ea, bp: True
    plugin.ida_dbg.update_bpt = lambda bp: True
    plugin._bp_policies[0x1000] = {
        "tid": 4321,
        "action": "stop",
        "auto_continue": False,
        "log_regs": [],
        "hit_count": 0,
        "module_rva": "0x1000",
    }
    upd = plugin.dbg_update_bp(0x1000, tid=0)
    assert upd["tid"] is None
    assert plugin._bp_policies[0x1000]["tid"] is None

    # 2. dbg_configure_exception_api preserves existing name/desc/flags when None
    defined = []
    existing_exc = types.SimpleNamespace(
        code=0xC0000005,
        name="EXCEPTION_ACCESS_VIOLATION",
        desc="Access violation",
        flags=1 | 2 | 4,
    )
    plugin.ida_dbg.retrieve_exceptions = lambda: [existing_exc]
    plugin.ida_dbg.define_exception = lambda code, name, desc, flags: defined.append((code, name, desc, flags)) or ""
    plugin.ida_dbg.store_exceptions = lambda: True
    ida_idd = types.ModuleType("ida_idd")
    ida_idd.EXC_BREAK = 1
    ida_idd.EXC_HANDLE = 2
    ida_idd.EXC_MSG = 4
    ida_idd.EXC_SILENT = 8
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)

    exc_res = plugin.dbg_configure_exception_api(0xC0000005, name=None, desc=None, Break=False, handle=None, msg=None)
    assert exc_res["success"] is True
    assert defined[-1][1] == "EXCEPTION_ACCESS_VIOLATION"
    assert defined[-1][2] == "Access violation"
    assert (defined[-1][3] & 2) != 0  # preserved EXC_HANDLE!
    assert (defined[-1][3] & 1) == 0  # cleared EXC_BREAK!

    # 3. Register and memory telescoping
    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_process_state = lambda: -1
    plugin.ida_dbg.get_current_thread = lambda: 100
    plugin.ida_dbg.get_reg_val = lambda name: 0x401000 if name == "rax" else None
    plugin.ida_dbg.get_ip_val = lambda: 0x401000
    plugin.ida_dbg.get_sp_val = lambda: 0x7FF000
    plugin.ida_funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=0x401000) if ea == 0x401000 else None
    plugin.ida_funcs.get_func_name = lambda ea: "main_handler" if ea == 0x401000 else None
    ida_idd.dbg_read_memory = lambda ea, sz: (0x401000).to_bytes(8, "little") if ea == 0x7FF000 else None

    regs_out = plugin.dbg_get_regs()
    assert "telescoped" in regs_out
    assert regs_out["telescoped"]["rax"]["symbol"] == "main_handler"

    mem_out = plugin.dbg_read_mem(0x7FF000, 8)
    assert "pointers" in mem_out
    assert mem_out["pointers"][0]["symbol"] == "main_handler"

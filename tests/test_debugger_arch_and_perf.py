import sys
import threading
import time
import types

import requests

from tests.test_plugin_runtime import _load_plugin


def _start_server(plugin):
    server = plugin.BridgeHTTPServer(("127.0.0.1", 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"
    headers = {"Authorization": "Bearer " + plugin.AUTH_TOKEN}
    return server, thread, base_url, headers


def _stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_nonblocking_sliced_debugger_wait_allows_concurrent_pause_and_uses_wfne_silent(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    # Simulate IDA's single UI main thread lock inside execute_sync
    ui_lock = threading.Lock()

    def synced_exec(callback, mode):
        with ui_lock:
            return callback()

    plugin.ida_kernwin.execute_sync = synced_exec

    state = {"proc": 1, "pending_event": 0, "wait_calls": []}
    plugin.ida_dbg.WFNE_ANY = 1
    plugin.ida_dbg.WFNE_SUSP = 2
    plugin.ida_dbg.WFNE_SILENT = 4
    plugin.ida_dbg.WFNE_CONT = 8
    plugin.ida_dbg.WFNE_NOWAIT = 16
    plugin.ida_dbg.DEC_TIMEOUT = -2

    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_process_state = lambda: state["proc"]
    plugin.ida_dbg.get_ip_val = lambda: 0x401234
    plugin.ida_dbg.get_sp_val = lambda: 0x7FFF0000
    plugin.ida_dbg.continue_process = lambda: state.__setitem__("proc", 1) is None or True

    def fake_suspend():
        state["proc"] = -1
        state["pending_event"] = 0x10
        return True

    plugin.ida_dbg.suspend_process = fake_suspend

    plugin.ida_dbg.WFNE_USEC = 0x20
    plugin.ida_dbg.DEC_NOTASK = -2
    plugin.ida_dbg.DEC_ERROR = -1
    plugin.ida_dbg.DEC_TIMEOUT = 0

    def fake_wait_for_next_event(wfne, timeout):
        state["wait_calls"].append((wfne, timeout))
        # Real IDA 9.5 SDK: WFNE_NOWAIT does NOT wait for or dequeue events — returns DEC_TIMEOUT immediately!
        if wfne & plugin.ida_dbg.WFNE_NOWAIT:
            return plugin.ida_dbg.DEC_TIMEOUT
        if state["pending_event"] > 0:
            ev = state["pending_event"]
            state["pending_event"] = 0
            return ev
        if timeout > 0:
            sleep_sec = (timeout / 1_000_000.0) if (wfne & plugin.ida_dbg.WFNE_USEC) else float(timeout)
            time.sleep(min(sleep_sec, 1.2))
        return plugin.ida_dbg.DEC_TIMEOUT

    plugin.ida_dbg.wait_for_next_event = fake_wait_for_next_event

    server, thread, base_url, headers = _start_server(plugin)
    try:
        cont_result = {}

        def _do_continue_wait():
            r = requests.post(
                base_url + "/api/dbg/continue",
                headers=headers,
                json={"wait": True, "timeout": 3},
                timeout=4,
            )
            cont_result["status_code"] = r.status_code
            cont_result["json"] = r.json()

        waiter = threading.Thread(target=_do_continue_wait, daemon=True)
        waiter.start()
        time.sleep(0.08)

        # Issue a concurrent /api/dbg/pause while /api/dbg/continue(wait=True) is waiting
        t0 = time.monotonic()
        r_pause = requests.post(base_url + "/api/dbg/pause", headers=headers, json={}, timeout=2)
        pause_elapsed = time.monotonic() - t0
        waiter.join(timeout=2)

        assert r_pause.status_code == 200
        assert pause_elapsed < 0.35, f"Concurrent pause blocked UI thread for {pause_elapsed:.2f}s"
        assert cont_result.get("status_code") == 200
        assert cont_result["json"]["status"] == "paused"
        assert cont_result["json"]["wait_code"] == 0x10

        # Check POST /api/dbg/wait default flags include WFNE_SILENT (4) and WFNE_USEC (0x20), never WFNE_NOWAIT!
        state["wait_calls"].clear()
        state["pending_event"] = 0x20
        r_wait = requests.post(base_url + "/api/dbg/wait", headers=headers, json={"timeout": 1}, timeout=2)
        assert r_wait.status_code == 200
        assert r_wait.json()["success"] is True
        assert state["wait_calls"], "wait_for_next_event was not called"
        used_wfne, used_timeout = state["wait_calls"][0]
        assert bool(used_wfne & plugin.ida_dbg.WFNE_SILENT), "POST /api/dbg/wait must include WFNE_SILENT by default"
        assert bool(used_wfne & plugin.ida_dbg.WFNE_USEC) and used_timeout == 40000
        assert not bool(used_wfne & plugin.ida_dbg.WFNE_NOWAIT)
    finally:
        _stop_server(server, thread)


def test_dbg_get_regs_and_set_reg_preserve_current_thread_and_use_tid_fallback(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    cur = {"tid": 100}
    per_tid_rax = {100: 0x1111, 200: 0x2222}

    plugin.ida_dbg.is_debugger_on = lambda: True
    plugin.ida_dbg.get_process_state = lambda: -1
    plugin.ida_dbg.get_current_thread = lambda: cur["tid"]
    plugin.ida_dbg.select_thread = lambda t: cur.__setitem__("tid", int(t)) is None or True
    plugin.ida_dbg.get_reg_val = lambda name: per_tid_rax[cur["tid"]] if name == "rax" else None
    plugin.ida_dbg.set_reg_val = lambda name, val: per_tid_rax.__setitem__(cur["tid"], int(val)) is None or True

    # 1. With select_thread: dbg_get_regs(tid=200) and dbg_set_reg(..., tid=200) restore cur_tid=100
    r_get = plugin.dbg_get_regs(tid=200)
    assert r_get["registers"]["rax"] == "0x2222"
    assert cur["tid"] == 100

    r_set = plugin.dbg_set_reg("rax", 0x3333, tid=200)
    assert r_set["success"] is True
    assert per_tid_rax[200] == 0x3333
    assert per_tid_rax[100] == 0x1111
    assert cur["tid"] == 100

    # 2. Without select_thread: must NOT silently return thread 100's get_reg_val when tid=200 is requested
    delattr(plugin.ida_dbg, "select_thread")
    ida_idd = types.ModuleType("ida_idd")
    ida_idd.get_dbg = lambda: types.SimpleNamespace(
        regs=lambda idx: types.SimpleNamespace(name="rax", dtype=0)
    )
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)
    plugin.ida_dbg.get_reg_vals = lambda t: [types.SimpleNamespace(pyval=lambda dt: per_tid_rax[int(t)])]

    r_fallback = plugin.dbg_get_regs(tid=200)
    assert r_fallback["registers"]["rax"] == "0x3333"


def test_get_call_graph_uses_single_safe_read_and_funcitems(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    sync_count = {"n": 0}
    orig_sync = plugin.ida_kernwin.execute_sync

    def counting_sync(cb, mode):
        sync_count["n"] += 1
        return orig_sync(cb, mode)

    plugin.ida_kernwin.execute_sync = counting_sync

    funcs = {
        0x1000: types.SimpleNamespace(start_ea=0x1000, end_ea=0x1008),
        0x2000: types.SimpleNamespace(start_ea=0x2000, end_ea=0x2004),  # also has tail chunk at 0x9000
        0x3000: types.SimpleNamespace(start_ea=0x3000, end_ea=0x3004),
    }
    plugin.ida_funcs.get_func = lambda ea: funcs.get(ea)
    plugin.ida_funcs.get_func_name = lambda ea: f"fn_{ea:x}"
    chunks = {
        0x1000: [0x1000],
        0x2000: [0x2000, 0x9000],  # discontinuous tail chunk at 0x9000 calls 0x3000!
        0x3000: [0x3000],
    }
    plugin.idautils.FuncItems = lambda ea: iter(chunks.get(ea, []))
    xrefs = {
        0x1000: [types.SimpleNamespace(frm=0x1000, to=0x2000, type=17)],
        0x9000: [types.SimpleNamespace(frm=0x9000, to=0x3000, type=17)],
    }
    plugin.idautils.XrefsFrom = lambda ea: xrefs.get(ea, [])

    cg = plugin.get_call_graph(0x1000, depth=4)
    assert sync_count["n"] == 1, f"Expected 1 execute_sync call, got {sync_count['n']}"
    assert cg["calls"][0]["ea"] == "0x2000"
    assert cg["calls"][0]["calls"][0]["ea"] == "0x3000"


def test_dbg_search_memory_finds_pattern_straddling_chunk_boundary_without_duplicates(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)

    base = 0x500000
    chunk = 256 * 1024
    buf = bytearray(b"\x00" * (chunk * 2))
    sig = bytes.fromhex("DEADBEEFCAFE")
    # Hit 1 inside the overlap region before chunk boundary (must appear once, not twice!)
    off1 = chunk - 16
    # Hit 2 straddling the 256 KiB chunk boundary (3 bytes in chunk 0, 3 bytes in chunk 1)
    off2 = chunk - 3
    buf[off1 : off1 + len(sig)] = sig
    buf[off2 : off2 + len(sig)] = sig

    plugin.ida_dbg.is_debugger_on = lambda: True
    ida_idd = types.ModuleType("ida_idd")
    ida_idd.dbg_read_memory = lambda ea, sz: bytes(buf[ea - base : ea - base + sz])
    monkeypatch.setitem(sys.modules, "ida_idd", ida_idd)
    plugin.ida_funcs.get_func = lambda ea: None

    res = plugin.dbg_search_memory_api("DE AD BE EF CA FE", start_ea=base, end_ea=base + len(buf), max_results=20)
    found_eas = [m["ea"] for m in res["results"]]
    assert found_eas == [hex(base + off1), hex(base + off2)]
    assert res["count"] == 2


def test_start_and_stop_server_do_not_duplicate_startup_or_shutdown_banner(monkeypatch, tmp_path, capsys):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    monkeypatch.setenv("IDA_BRIDGE_INSTANCES_FILE", str(tmp_path / "instances.json"))
    msg_lines = []
    plugin.ida_kernwin.msg = lambda s: msg_lines.append(s)

    # Pick an ephemeral free port via socket first so start_server binds cleanly
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    plugin.start_server(port=free_port)
    plugin.stop_server()

    captured = capsys.readouterr().out
    combined_lines = [ln for ln in (captured.splitlines() + "".join(msg_lines).splitlines()) if ln.strip()]
    started_banners = [ln for ln in combined_lines if "Bridge server started on" in ln]
    stopped_banners = [ln for ln in combined_lines if "stopped" in ln.lower()]

    assert len(started_banners) == 1, f"Duplicate startup banners emitted: {started_banners}"
    assert len(stopped_banners) == 1, f"Duplicate stop banners emitted: {stopped_banners}"

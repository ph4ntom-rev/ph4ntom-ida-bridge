import asyncio
import json
from unittest.mock import Mock, patch

import pytest

import agent
import cli
import mcp_server
from core.client import BridgeClient
from integrations.ide_extension import IDEBridge


def test_bridge_client_no_retry_on_500_docker_host_optin_and_filter_params(monkeypatch):
    client = BridgeClient()
    adapter = client.session.get_adapter("http://127.0.0.1:13370/api/info")
    assert 500 not in adapter.max_retries.status_forcelist
    assert {429, 502, 503, 504}.issubset(set(adapter.max_retries.status_forcelist))

    # Rejects host.docker.internal by default, allows when IDA_BRIDGE_ALLOW_DOCKER_HOST=1
    with pytest.raises(ValueError):
        BridgeClient(url="http://host.docker.internal:13370")

    monkeypatch.setenv("IDA_BRIDGE_ALLOW_DOCKER_HOST", "1")
    docker_client = BridgeClient(url="http://host.docker.internal:13370")
    assert docker_client.base_url == "http://host.docker.internal:13370"

    captured = []
    monkeypatch.setattr(
        client,
        "get",
        lambda path, **params: captured.append((path, params)) or {"ok": True},
    )
    client.strings(filter_pattern="http", limit=50, offset=10)
    client.classes(filter_pattern="CNet*", toplevel_only=True, include_hidden=True)
    client.class_details("CNetChan", ea="0x1000", render=False, no_bodies=True)

    assert captured[0] == ("/api/strings", {"filter": "http", "limit": 50, "offset": 10})
    assert captured[1] == ("/api/classes", {"filter": "CNet*", "toplevel": "1", "hidden": "1"})
    assert captured[2] == ("/api/class/CNetChan", {"ea": "0x1000", "render": "0", "no_bodies": "1"})


def test_cli_strings_pagination_and_client_side_evidence_save(tmp_path, capsys):
    mock_client = Mock()
    mock_client.__enter__ = Mock(return_value=mock_client)
    mock_client.__exit__ = Mock(return_value=None)
    mock_client.strings.return_value = {"strings": [], "returned": 0}

    with patch("cli.BridgeClient", return_value=mock_client):
        rc = cli.main(["strings", "--filter", "abc", "--limit", "25", "--offset", "5"])
    assert rc == 0
    capsys.readouterr()
    mock_client.strings.assert_called_once_with("abc", limit=25, offset=5)

    ev_path = tmp_path / "cli_evidence.json"
    post_calls = []

    def fake_post(path, payload=None):
        post_calls.append((path, payload))
        return {"bridge_version": "6.4.0", "notes": (payload or {}).get("notes"), "binary": {"filename": "fw.bin"}}

    mock_client.post.side_effect = fake_post
    with patch("cli.BridgeClient", return_value=mock_client):
        rc_ev = cli.main(["evidence", "--ea", "0x1000", "--notes", "crash", "--save", str(ev_path)])
    out_json = json.loads(capsys.readouterr().out)
    assert rc_ev == 0
    assert ev_path.is_file()
    assert out_json["saved_to"] == str(ev_path.resolve())
    # Must never send local host save_path/output_path to HTTP server!
    for _, payload in post_calls:
        assert "save_path" not in (payload or {})
        assert "output_path" not in (payload or {})
        assert "output" not in (payload or {})


def test_mcp_client_side_file_handling_and_class_params(monkeypatch, tmp_path):
    api_calls = []

    def fake_call_api(method, path, payload=None):
        api_calls.append((method, path, dict(payload or {})))
        if path == "/api/decompile-batch":
            return {
                "results": [{"ea": "0x1000", "name": "sub_1000", "pseudocode": "int sub_1000() { return 1; }"}],
                "count": 1,
                "succeeded": 1,
                "failed": 0,
            }
        if path == "/api/dbg/breakpoints/export":
            return {"version": "6.4.0", "count": 1, "breakpoints": [{"ea": "0x1000", "mode": "exec"}]}
        if path == "/api/dbg/breakpoints/import":
            return {"success": True, "restored_count": len((payload or {}).get("breakpoints", []))}
        if path == "/api/dbg/evidence":
            return {"bridge_version": "6.4.0", "notes": (payload or {}).get("notes")}
        return {"success": True}

    monkeypatch.setattr(mcp_server.client, "call_api", fake_call_api)

    c_out = tmp_path / "batch_out.c"
    res_batch = json.loads(mcp_server.decompile_batch(addresses_json='["0x1000"]', output_path=str(c_out), format="c"))
    assert c_out.is_file()
    assert "int sub_1000()" in c_out.read_text(encoding="utf-8")
    assert res_batch["saved_to"] == str(c_out.resolve())

    bp_out = tmp_path / "bps.json"
    res_exp = json.loads(mcp_server.dbg_export_breakpoints(save_path=str(bp_out)))
    assert bp_out.is_file()
    assert res_exp["saved_to"] == str(bp_out.resolve())

    res_imp = json.loads(mcp_server.dbg_import_breakpoints(load_path=str(bp_out), clear_existing=True))
    assert res_imp["restored_count"] == 1

    ev_out = tmp_path / "ev.json"
    res_ev = json.loads(mcp_server.capture_evidence(ea="0x1000", notes="n1", save_path=str(ev_out)))
    assert ev_out.is_file()
    assert res_ev["saved_to"] == str(ev_out.resolve())

    mcp_server.list_classes(filter_pattern="Foo*", toplevel_only=True, include_hidden=True)
    mcp_server.get_class("Foo", ea="0x1000", render=False, no_bodies=True)

    # Verify NO server call ever received a host filesystem path
    for _, _, payload in api_calls:
        for forbidden_key in ("output_path", "save_path", "load_path", "input_path", "output"):
            assert not payload.get(forbidden_key), f"Server payload leaked filesystem key {forbidden_key}: {payload}"

    assert ("GET", "/api/classes", {"filter": "Foo*", "toplevel": "1", "hidden": "1"}) in api_calls
    assert ("GET", "/api/class/Foo", {"ea": "0x1000", "render": "0", "no_bodies": "1"}) in api_calls


def test_mcp_registers_all_131_tools_with_valid_annotations_and_routes(monkeypatch):
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert len(tools) == 131
    expected_new_33 = {
        "get_enum",
        "create_enum",
        "add_enum_member",
        "delete_enum",
        "add_struct_member",
        "delete_struct",
        "apply_struct",
        "delete_type",
        "list_type_libraries",
        "load_type_library",
        "make_function",
        "delete_function",
        "make_code",
        "make_data",
        "undefine",
        "set_name",
        "reanalyze",
        "wait_for_analysis",
        "get_global_vars",
        "get_stack_vars",
        "get_switch_info",
        "get_instruction",
        "list_patches",
        "list_function_gaps",
        "list_bookmarks",
        "add_bookmark",
        "delete_bookmark",
        "get_cursor",
        "get_selection",
        "create_segment",
        "delete_segment",
        "set_segment_attrs",
        "analyze_function_context",
    }
    assert expected_new_33.issubset(set(tools))
    assert all(t.annotations is not None for t in tools.values())
    assert tools["get_enum"].annotations.read_only_hint is True
    assert tools["analyze_function_context"].annotations.read_only_hint is True
    assert tools["delete_function"].annotations.read_only_hint is False
    assert tools["delete_function"].annotations.destructive_hint is True

    calls = []
    monkeypatch.setattr(
        mcp_server.client,
        "call_api",
        lambda method, path, payload=None: calls.append((method, path, payload)) or {"success": True},
    )
    mcp_server.get_enum("MyEnum")
    mcp_server.set_segment_attrs("0x1000", name=".rodata", seg_class="CONST", perm="r--")
    mcp_server.analyze_function_context("0x1000")
    assert ("GET", "/api/enum/MyEnum", {}) in calls
    assert ("POST", "/api/segment/set-attrs", {"ea": "0x1000", "name": ".rodata", "class": "CONST", "perm": "r--"}) in calls
    assert ("GET", "/api/macro/analyze_context", {"ea": "0x1000"}) in calls


def test_agent_call_bridge_api_supports_query_strings_and_ide_extension_status_keys(tmp_path):
    class _DummyBackend(agent.AgentBackend):
        @classmethod
        def get_name(cls) -> str:
            return "Dummy"

        @classmethod
        def get_default_model(cls) -> str:
            return "dummy-1"

        @classmethod
        def is_available(cls) -> bool:
            return True

        def chat(self, message: str) -> str:
            return message

    mock_client = Mock()
    mock_client.call_api.return_value = {"functions": [], "returned": 0}
    backend = _DummyBackend(client=mock_client)

    raw_res = backend.call_bridge_api("GET", "/api/functions-page?offset=10&limit=25")
    assert json.loads(raw_res)["returned"] == 0
    mock_client.call_api.assert_called_once_with("GET", "/api/functions-page", {"offset": "10", "limit": "25"})

    ide = IDEBridge(str(tmp_path))
    ide.client = Mock()
    ide.client.ping.return_value = {"status": "ok", "version": "6.4.0"}
    ide.client.info.return_value = {
        "filename": "sec_0_EMEM_0xb8970000.bin",
        "processor": "mipsl",
        "bitness": 32,
        "entry_point": None,
        "func_count": 389,
    }
    ide.client.path_component.side_effect = BridgeClient.path_component
    ide.client.get.return_value = {"pseudocode": "void f(){}"}

    st = ide.get_status()
    assert st["binary"] == "sec_0_EMEM_0xb8970000.bin"
    assert st["arch"] == "mipsl 32-bit"
    assert st["functions"] == 389

    ide.get_decompilation("networksystem.dll+0x10")
    ide.client.get.assert_called_once_with("/api/function/networksystem.dll%2B0x10/pseudocode")

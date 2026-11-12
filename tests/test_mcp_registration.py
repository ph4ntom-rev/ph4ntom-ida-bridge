import asyncio
import json

from fastmcp import Client
import mcp_server

from mcp_server import mcp


def test_mcp_registers_expected_tools_and_resources():
    tools = asyncio.run(mcp.list_tools())
    resources = asyncio.run(mcp.list_resources())
    names = {tool.name for tool in tools}

    assert len(tools) == 131
    assert len(resources) == 2
    assert {
        "ping",
        "decompile",
        "decompile_batch",
        "get_disasm_range",
        "create_vtable_struct",
        "get_ctree",
        "get_microcode",
        "rename_function",
        "execute_idapython",
        "save_database",
        "list_classes",
        "get_class",
        "get_decompiler_timeout",
        "set_decompiler_timeout",
        "dbg_get_status",
        "dbg_load_debugger",
        "dbg_set_watchpoint",
        "dbg_delete_breakpoint",
        "dbg_toggle_breakpoint",
        "dbg_update_breakpoint",
        "dbg_export_breakpoints",
        "dbg_import_breakpoints",
        "capture_evidence",
        "list_ida_instances",
        "select_ida_instance",
        "dbg_get_memory_map",
        "dbg_search_memory",
        "dbg_list_modules",
        "dbg_configure_trace",
        "dbg_get_trace",
        "dbg_get_events",
        "dbg_appcall",
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
    }.issubset(names)


def test_mcp_annotations_distinguish_reads_and_writes():
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    assert all(tool.annotations is not None for tool in tools.values())
    assert tools['decompile'].annotations.read_only_hint is True
    assert tools['rename_function'].annotations.read_only_hint is False
    assert tools['rename_function'].annotations.destructive_hint is True
    assert tools['execute_idapython'].annotations.open_world_hint is True
    assert tools['dbg_get_status'].annotations.read_only_hint is True
    assert tools['dbg_set_watchpoint'].annotations.read_only_hint is False


def test_mcp_protocol_marks_bridge_failures_as_errors(monkeypatch):
    monkeypatch.setattr(mcp_server.client, 'call_api', lambda *args: {'success': False, 'error': 'injected bridge failure'})
    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool('get_binary_info', {}, raise_on_error=False)
            assert result.is_error
            assert 'injected bridge failure' in result.content[0].text
    asyncio.run(run())


def test_mcp_protocol_preserves_successful_payload(monkeypatch):
    monkeypatch.setattr(mcp_server.client, 'call_api', lambda *args: {'status': 'ok', 'version': 'fixture'})
    async def run():
        async with Client(mcp) as client:
            result = await client.call_tool('ping', {})
            assert not result.is_error
            assert json.loads(result.content[0].text)['version'] == 'fixture'
    asyncio.run(run())

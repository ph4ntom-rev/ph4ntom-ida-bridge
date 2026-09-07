import asyncio
import json

from fastmcp import Client
import mcp_server

from mcp_server import mcp


def test_mcp_registers_expected_tools_and_resources():
    tools = asyncio.run(mcp.list_tools())
    resources = asyncio.run(mcp.list_resources())
    names = {tool.name for tool in tools}

    assert len(tools) == 54
    assert len(resources) == 2
    assert {
        "ping",
        "decompile",
        "get_ctree",
        "get_microcode",
        "rename_function",
        "execute_idapython",
        "save_database",
    }.issubset(names)


def test_mcp_annotations_distinguish_reads_and_writes():
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    assert all(tool.annotations is not None for tool in tools.values())
    assert tools['decompile'].annotations.readOnlyHint is True
    assert tools['rename_function'].annotations.readOnlyHint is False
    assert tools['rename_function'].annotations.destructiveHint is True
    assert tools['execute_idapython'].annotations.openWorldHint is True


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

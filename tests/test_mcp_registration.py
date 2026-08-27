import asyncio

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

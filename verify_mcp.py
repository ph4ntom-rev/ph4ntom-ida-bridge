import sys
from pathlib import Path

# Add the directory to path
sys.path.append(str(Path(__file__).parent))

try:
    import asyncio
    from mcp_server import mcp
    print("=== Antigravity IDA Bridge MCP Tools Verification ===")
    print(f"Server Name: {mcp.name}")

    tools = asyncio.run(mcp.list_tools())
    resources = asyncio.run(mcp.list_resources())

    print(f"Total Registered Tools: {len(tools)}")
    print(f"Total Registered Resources: {len(resources)}")

    print("\nRegistered Tools List:")
    for i, tool in enumerate(tools, 1):
        print(f"{i:02d}. {tool.name:<25} | {tool.description}")

    print("\nRegistered Resources:")
    for i, res in enumerate(resources, 1):
        print(f"{i:02d}. {str(res.uri):<25} | {res.description}")

    print("\n==========================================")
    print("MCP SERVER SYNTAX & REGISTRATION OK!")
    print("==========================================")
except Exception as e:
    print(f"FAILED to load MCP server: {e}")
    sys.exit(1)

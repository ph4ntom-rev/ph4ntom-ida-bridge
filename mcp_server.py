"""
Antigravity IDA Bridge — MCP Server (Upgraded & Integrated)
============================================================
Model Context Protocol server that exposes 50+ IDA Pro capabilities
to any MCP-compatible AI client (Claude Desktop, Cursor, Cline, etc.)

Uses the shared BridgeClient for thread-safety, connection pooling,
bearer token authentication, and robust exponential backoff.
"""

import json
from fastmcp import FastMCP
from core.client import BridgeClient

client = BridgeClient()


def _get(path: str, **params) -> dict:
    """GET request via BridgeClient."""
    return client.call_api("GET", path, params)


def _post(path: str, data: dict = None) -> dict:
    """POST request via BridgeClient."""
    return client.call_api("POST", path, data)

# ─── MCP Server ──────────────────────────────────────────────────────────────


mcp = FastMCP("Antigravity IDA Bridge")

# ─── Resources ───────────────────────────────────────────────────────────────


@mcp.resource("ida://info")
def binary_info() -> str:
    """Current binary metadata: filename, architecture, bitness, entry point."""
    return json.dumps(_get("/api/info"), indent=2)


@mcp.resource("ida://schema")
def api_schema() -> str:
    """Full API schema with all available endpoints and their parameters."""
    return json.dumps(_get("/api/schema"), indent=2)

# ─── Core Analysis Tools ─────────────────────────────────────────────────────


@mcp.tool
def ping() -> str:
    """Check if IDA Bridge is running and get version info."""
    return json.dumps(_get("/api/ping"))


@mcp.tool
def get_binary_info() -> str:
    """Get binary metadata: filename, processor, bitness, entry point, address range, hex-rays availability."""
    return json.dumps(_get("/api/info"), indent=2)


@mcp.tool
def list_functions(offset: int = 0, limit: int = 200) -> str:
    """List functions in the binary with pagination.

    Args:
        offset: Start index (default 0)
        limit: Max functions to return (default 200, max 5000)
    """
    return json.dumps(_get("/api/functions-page", offset=offset, limit=limit), indent=2)


@mcp.tool
def decompile(ea: str) -> str:
    """Decompile function at address to C pseudocode. Returns pseudocode + local variables.

    Args:
        ea: Function address as hex string (e.g. '0x140001000')
    """
    return json.dumps(_get(f"/api/function/{ea}/pseudocode"), indent=2)


@mcp.tool
def get_disassembly(ea: str) -> str:
    """Get assembly listing for function at address.

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/disasm"), indent=2)


@mcp.tool
def get_ctree(ea: str) -> str:
    """Get Hex-Rays AST (ctree) as JSON for pattern matching and deep analysis. 
    Each node has kind(insn/expr), op, ea, dtype. Expressions include values, strings, objects, variables, call targets.

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/ctree"), indent=2)


@mcp.tool
def get_microcode(ea: str, maturity: int = 7) -> str:
    """Get microcode IR listing. Maturity levels: 0=PREOPT (raw), 7=LVARS (fully optimized).
    Lower maturity is useful for deobfuscation analysis.

    Args:
        ea: Function address as hex string
        maturity: Optimization level 0-7 (default 7)
    """
    return json.dumps(_get(f"/api/function/{ea}/microcode", maturity=maturity), indent=2)


@mcp.tool
def get_local_variables(ea: str) -> str:
    """Get full local variable map with types, register/stack info for a function.

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/lvar-map"), indent=2)


@mcp.tool
def get_function_details(ea: str) -> str:
    """Get detailed function info: prototype, flags, frame size, comments.

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/details"), indent=2)

# ─── Cross-References & Navigation ──────────────────────────────────────────


@mcp.tool
def get_xrefs_to(ea: str) -> str:
    """Get all cross-references TO this address (who calls/references this).

    Args:
        ea: Target address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/xrefs-to"), indent=2)


@mcp.tool
def get_xrefs_from(ea: str) -> str:
    """Get all cross-references FROM this function (what it calls/references).

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/xrefs-from"), indent=2)


@mcp.tool
def get_callers(ea: str) -> str:
    """Get functions that call this function (caller graph).

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/callers"), indent=2)


@mcp.tool
def get_callees(ea: str) -> str:
    """Get functions called by this function (callee graph).

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/callees"), indent=2)


@mcp.tool
def get_call_graph(ea: str, depth: int = 3) -> str:
    """Get recursive call graph tree starting from function.

    Args:
        ea: Root function address
        depth: Recursion depth (default 3)
    """
    return json.dumps(_get(f"/api/function/{ea}/call-graph", depth=depth), indent=2)


@mcp.tool
def get_basic_blocks(ea: str) -> str:
    """Get control flow graph (basic blocks with successors/predecessors).

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/basic-blocks"), indent=2)


@mcp.tool
def get_strings_used(ea: str) -> str:
    """Get string constants referenced by a function.

    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{ea}/strings-used"), indent=2)

# ─── Search Tools ────────────────────────────────────────────────────────────


@mcp.tool
def search_function(name: str) -> str:
    """Find functions by name (partial match).

    Args:
        name: Search query (partial function name)
    """
    return json.dumps(_get(f"/api/search-func/{name}"), indent=2)


@mcp.tool
def search_bytes(pattern: str) -> str:
    """Search for byte pattern in binary. Use ?? for wildcards.
    Example: 'E8 ?? ?? ?? ?? 48 8B'

    Args:
        pattern: Hex byte pattern with optional ?? wildcards
    """
    return json.dumps(_get(f"/api/search-bytes/{pattern}"), indent=2)


@mcp.tool
def search_text(text: str) -> str:
    """Search for text in disassembly listings.

    Args:
        text: Text to search for
    """
    return json.dumps(_get(f"/api/search-text/{text}"), indent=2)


@mcp.tool
def list_strings() -> str:
    """List all strings found in the binary."""
    return json.dumps(_get("/api/strings"), indent=2)


@mcp.tool
def list_names() -> str:
    """List all named items (functions, variables, labels)."""
    return json.dumps(_get("/api/names"), indent=2)

# ─── Binary Structure ────────────────────────────────────────────────────────


@mcp.tool
def list_imports() -> str:
    """List imported functions grouped by module (DLL/library)."""
    return json.dumps(_get("/api/imports"), indent=2)


@mcp.tool
def list_exports() -> str:
    """List exported functions with addresses."""
    return json.dumps(_get("/api/exports"), indent=2)


@mcp.tool
def list_segments() -> str:
    """List memory segments with permissions (read/write/execute)."""
    return json.dumps(_get("/api/segments"), indent=2)


@mcp.tool
def read_bytes(ea: str, size: int) -> str:
    """Read raw bytes from binary at specified address.

    Args:
        ea: Start address as hex string
        size: Number of bytes to read
    """
    return json.dumps(_get(f"/api/bytes/{ea}/{size}"), indent=2)


@mcp.tool
def read_vtable(ea: str) -> str:
    """Read virtual function table entries at address.

    Args:
        ea: Vtable start address
    """
    return json.dumps(_get(f"/api/vtable/{ea}"), indent=2)

# ─── Type System ─────────────────────────────────────────────────────────────


@mcp.tool
def list_structs() -> str:
    """List all defined structures with sizes."""
    return json.dumps(_get("/api/structs"), indent=2)


@mcp.tool
def get_struct(name: str) -> str:
    """Get structure members with offsets, sizes, and types.

    Args:
        name: Structure name
    """
    return json.dumps(_get(f"/api/struct/{name}"), indent=2)


@mcp.tool
def list_enums() -> str:
    """List all defined enumerations."""
    return json.dumps(_get("/api/enums"), indent=2)


@mcp.tool
def list_types() -> str:
    """List all local types (structs, unions, enums, typedefs)."""
    return json.dumps(_get("/api/types"), indent=2)


@mcp.tool
def get_type(name: str) -> str:
    """Get detailed type information including struct/union members.

    Args:
        name: Type name
    """
    return json.dumps(_get(f"/api/type/{name}"), indent=2)


@mcp.tool
def create_type(definition: str) -> str:
    """Create a new type from C declaration.

    Args:
        definition: C type definition, e.g. 'struct Player { int health; float pos[3]; };'
    """
    return json.dumps(_post("/api/type/create", {"definition": definition}))

# ─── Mutation Tools ──────────────────────────────────────────────────────────


@mcp.tool
def rename_function(ea: str, name: str) -> str:
    """Rename function at address.

    Args:
        ea: Function address as hex string
        name: New function name
    """
    return json.dumps(_post(f"/api/function/{ea}/rename", {"name": name}))


@mcp.tool
def comment_function(ea: str, comment: str) -> str:
    """Set function comment.

    Args:
        ea: Function address as hex string
        comment: Comment text
    """
    return json.dumps(_post(f"/api/function/{ea}/comment", {"comment": comment}))


@mcp.tool
def set_inline_comment(ea: str, comment: str) -> str:
    """Set inline comment at specific address.

    Args:
        ea: Address as hex string
        comment: Comment text
    """
    return json.dumps(_post(f"/api/address/{ea}/comment", {"comment": comment}))


@mcp.tool
def rename_variable(ea: str, old_name: str, new_name: str) -> str:
    """Rename local variable in a decompiled function.

    Args:
        ea: Function address
        old_name: Current variable name
        new_name: New variable name
    """
    return json.dumps(_post(f"/api/function/{ea}/lvar-rename", {"old": old_name, "new": new_name}))


@mcp.tool
def set_variable_type(ea: str, var_name: str, type_str: str) -> str:
    """Change local variable type in decompiled function.

    Args:
        ea: Function address
        var_name: Variable name
        type_str: C type string (e.g. 'DWORD *', 'struct Player *')
    """
    return json.dumps(_post(f"/api/function/{ea}/lvar-set-type", {"var": var_name, "type": type_str}))


@mcp.tool
def set_function_type(ea: str, prototype: str) -> str:
    """Set function prototype/signature.

    Args:
        ea: Function address
        prototype: C prototype (e.g. 'int __fastcall(void *this, int count)')
    """
    return json.dumps(_post(f"/api/function/{ea}/set-type", {"type": prototype}))


@mcp.tool
def create_struct(definition: str) -> str:
    """Create structure from C definition.

    Args:
        definition: C struct definition, e.g. 'struct Entity { int id; char name[32]; };'
    """
    return json.dumps(_post("/api/struct/create", {"definition": definition}))


@mcp.tool
def patch_bytes(ea: str, hex_bytes: str) -> str:
    """Patch bytes in the binary. Use hex string with spaces.

    Args:
        ea: Address to patch
        hex_bytes: Hex bytes, e.g. '90 90 90' for NOPs
    """
    return json.dumps(_post("/api/patch-bytes", {"ea": ea, "bytes": hex_bytes}))


@mcp.tool
def batch_mutations(mutations: str) -> str:
    """Execute multiple mutations atomically with rollback support.
    Pass a JSON array string of operations.

    Args:
        mutations: JSON array string, e.g. '[{"op":"rename-func","ea":"0x...","name":"new_name"}]'
    """
    ops = json.loads(mutations)
    return json.dumps(_post("/api/batch", {"mutations": ops}), indent=2)

# ─── Debugger Tools ──────────────────────────────────────────────────────────


@mcp.tool
def dbg_start(path: str = "", args: str = "") -> str:
    """Start debugging the current binary or specified executable.

    Args:
        path: Optional path to executable (defaults to current binary)
        args: Command line arguments
    """
    return json.dumps(_post("/api/dbg/start", {"path": path or None, "args": args}))


@mcp.tool
def dbg_set_breakpoint(ea: str, hardware: bool = False) -> str:
    """Set a breakpoint at address.

    Args:
        ea: Address for breakpoint
        hardware: Use hardware breakpoint (default False)
    """
    return json.dumps(_post("/api/dbg/breakpoint", {"ea": ea, "hardware": hardware}))


@mcp.tool
def dbg_continue() -> str:
    """Continue process execution (resume from breakpoint/pause)."""
    return json.dumps(_post("/api/dbg/continue"))


@mcp.tool
def dbg_step_into() -> str:
    """Step into the next instruction (follows calls)."""
    return json.dumps(_post("/api/dbg/step-into"))


@mcp.tool
def dbg_step_over() -> str:
    """Step over the next instruction (skips calls)."""
    return json.dumps(_post("/api/dbg/step-over"))


@mcp.tool
def dbg_get_registers() -> str:
    """Read all CPU registers (debugger must be active)."""
    return json.dumps(_get("/api/dbg/regs"), indent=2)


@mcp.tool
def dbg_read_memory(ea: str, size: int) -> str:
    """Read process memory at runtime (debugger must be active).

    Args:
        ea: Memory address
        size: Number of bytes to read
    """
    return json.dumps(_get(f"/api/dbg/memory/{ea}/{size}"), indent=2)


@mcp.tool
def dbg_get_stack() -> str:
    """Get call stack trace (debugger must be active)."""
    return json.dumps(_get("/api/dbg/stack"), indent=2)

# ─── Utility Tools ───────────────────────────────────────────────────────────


@mcp.tool
def execute_idapython(script: str) -> str:
    """Execute arbitrary IDAPython script in IDA Pro. Full SDK access.
    Use the global 'result' dict to return structured data.

    Args:
        script: Python code to execute in IDA's environment
    """
    return json.dumps(_post("/api/exec", {"script": script}), indent=2)


@mcp.tool
def undo() -> str:
    """Undo the last action in IDA."""
    return json.dumps(_post("/api/undo"))


@mcp.tool
def redo() -> str:
    """Redo the last undone action."""
    return json.dumps(_post("/api/redo"))


@mcp.tool
def navigate_to(ea: str) -> str:
    """Move IDA's cursor to the specified address.

    Args:
        ea: Address to navigate to
    """
    return json.dumps(_post("/api/navigate", {"ea": ea}))


@mcp.tool
def save_database() -> str:
    """Save the current IDA database (.idb/.i64)."""
    return json.dumps(_post("/api/save"))

# ─── Entry Point ─────────────────────────────────────────────────────────────


if __name__ == "__main__":
    mcp.run()

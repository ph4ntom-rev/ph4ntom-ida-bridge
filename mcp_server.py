"""
ph4ntom IDA Bridge — MCP Server
====================================
Model Context Protocol server that exposes 131 IDA Pro 9.5+ tools
to any MCP-compatible AI client (Claude Desktop, Cursor, Cline, Antigravity, etc.)

Uses the shared BridgeClient for thread-safety, connection pooling,
bearer token authentication, and robust exponential backoff.
"""

import json
import os
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from core.client import BridgeClient

client = BridgeClient()

def _get(path: str, **params) -> dict:
    """GET request via BridgeClient."""
    return _checked(client.call_api("GET", path, params))

def _post(path: str, data: Optional[dict] = None, timeout: Optional[float] = None) -> dict:
    """POST request via BridgeClient."""
    if timeout is not None:
        return _checked(client.call_api("POST", path, data, timeout=timeout))
    return _checked(client.call_api("POST", path, data))


def _checked(result: dict) -> dict:
    if result.get('error') or (result.get('success') is False and not result.get('timed_out')):
        raise ToolError(json.dumps(result, ensure_ascii=False))
    return result


def _safe_client_file_path(raw: str) -> Path:
    p = Path(raw.strip()).expanduser()
    low_name = p.name.lower()
    if low_name.startswith(".ph4ntom_ida_bridge_token") or low_name == ".ph4ntom_ida_instances.json":
        raise ValueError("Refusing to read or overwrite bridge credential/registry files")
    is_junc = getattr(os.path, "isjunction", lambda _x: False)
    cur = p.absolute()
    while True:
        if cur.is_symlink() or is_junc(str(cur)):
            raise ValueError("Symlink or junction paths are not permitted")
        if cur.parent == cur:
            break
        cur = cur.parent
    return p.resolve()


def _component(value: object) -> str:
    return client.path_component(value)

# ─── MCP Server ──────────────────────────────────────────────────────────────

mcp = FastMCP("ph4ntom IDA Bridge")

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

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def ping() -> str:
    """Check if IDA Bridge is running and get version info."""
    return json.dumps(_get("/api/ping"))

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_binary_info() -> str:
    """Get binary metadata: filename, processor, bitness, entry point, address range, hex-rays availability."""
    return json.dumps(_get("/api/info"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_functions(
    offset: int = 0,
    limit: int = 200,
    filter: Optional[str] = None,
    start_ea: Optional[str] = None,
    end_ea: Optional[str] = None,
) -> str:
    """List functions in the binary with pagination, name/regex filter, and address range filter.
    
    Args:
        offset: Start index (default 0)
        limit: Max functions to return (default 200, max 10000)
        filter: Optional substring or regex pattern to filter function names
        start_ea: Optional start address (hex or 'module.dll+0xRVA')
        end_ea: Optional end address (hex or 'module.dll+0xRVA')
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if start_ea:
        params["start"] = start_ea
    if end_ea:
        params["end"] = end_ea
    return json.dumps(_get("/api/functions-page", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def decompile(ea: str) -> str:
    """Decompile function at address to C pseudocode. Returns pseudocode + local variables.
    
    Args:
        ea: Function address as hex string ('0x140001000') or 'module.dll+0xC3EA7'
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/pseudocode"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def decompile_batch(addresses_json: str = "", output_path: str = "", format: str = "json", eas: str = "") -> str:
    """Batch decompile multiple functions and optionally save results locally to disk (.json or .c).
    
    Args:
        addresses_json: JSON array or comma-separated list of addresses or 'module+0xRVA' strings (e.g. '["0x140001000", "networksystem.dll+0xC3EA7"]')
        output_path: Optional local file path to save decompiled output
        format: Output file format when output_path is set ('json' or 'c')
        eas: Alias for addresses_json (comma-separated or JSON array)
    """
    raw = (addresses_json or eas).strip()
    if not raw:
        raise ValueError("Provide addresses_json or eas")
    if raw.startswith("["):
        addrs = json.loads(raw)
    else:
        addrs = [x.strip() for x in raw.split(",") if x.strip()]
    if not isinstance(addrs, list):
        raise ValueError("addresses_json must decode to a list of addresses")
    res = _post("/api/decompile-batch", {"addresses": addrs, "format": format})
    if output_path and output_path.strip():
        out_file = _safe_client_file_path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        if str(format).lower() == "c" or out_file.suffix.lower() in (".c", ".cc", ".cpp", ".h"):
            chunks = []
            for item in res.get("results", []):
                chunks.append(f"// === Function: {item.get('name', 'unknown')} @ {item.get('ea', '?')} ===")
                if item.get("error"):
                    chunks.append(f"// ERROR: {item['error']}\n")
                else:
                    chunks.append((item.get("pseudocode") or "") + "\n")
            out_file.write_text("\n".join(chunks), encoding="utf-8")
        else:
            out_file.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        res["saved_to"] = str(out_file)
    return json.dumps(res, indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_disassembly(ea: str, end_ea: Optional[str] = None, count: Optional[int] = None) -> str:
    """Get assembly listing for a function or address range.
    
    Args:
        ea: Start/function address as hex string or 'module.dll+0xRVA'
        end_ea: Optional end address to limit disassembly range
        count: Optional maximum number of instructions to disassemble
    """
    params = {}
    if end_ea is not None:
        params["end"] = end_ea
    if count is not None:
        params["count"] = count
    return json.dumps(_get(f"/api/function/{_component(ea)}/disasm", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_disasm_range(start_ea: str, end_ea: Optional[str] = None, count: int = 100) -> str:
    """Disassemble an arbitrary address range without requiring the address to belong to a function.
    
    Args:
        start_ea: Start address (hex or 'module.dll+0xRVA')
        end_ea: Optional end address (hex or 'module.dll+0xRVA')
        count: Maximum number of instructions when end_ea is omitted (default 100)
    """
    params = {"start": start_ea, "count": count}
    if end_ea is not None:
        params["end"] = end_ea
    return json.dumps(_get("/api/disasm-range", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_ctree(ea: str) -> str:
    """Get Hex-Rays AST (ctree) as JSON for pattern matching and deep analysis. 
    Each node has kind(insn/expr), op, ea, dtype. Expressions include values, strings, objects, variables, call targets.
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/ctree"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_microcode(ea: str, maturity: int = 7) -> str:
    """Get microcode IR listing. Maturity levels: 0=PREOPT (raw), 7=LVARS (fully optimized).
    Lower maturity is useful for deobfuscation analysis.
    
    Args:
        ea: Function address as hex string
        maturity: Optimization level 0-7 (default 7)
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/microcode", maturity=maturity), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_local_variables(ea: str) -> str:
    """Get full local variable map with types, register/stack info for a function.
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/lvar-map"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_function_details(ea: str) -> str:
    """Get detailed function info: prototype, flags, frame size, comments.
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/details"), indent=2)

# ─── Cross-References & Navigation ──────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_xrefs_to(
    ea: str,
    exact: bool = False,
    filter: Optional[str] = None,
    start_ea: Optional[str] = None,
    end_ea: Optional[str] = None,
    xref_type: Optional[str] = None,
) -> str:
    """Get all cross-references TO this address (who calls/references this), with optional name/range/type filters.
    
    Args:
        ea: Target address as hex string or 'module.dll+0xRVA'
        exact: Use IDA 9.5+ XREF_EXACT to match only exact byte address (default False)
        filter: Optional substring/regex filter on referencing function name
        start_ea: Optional start address filter
        end_ea: Optional end address filter
        xref_type: Optional xref type filter (e.g. 'Call', 'Read', 'Write')
    """
    params = {}
    if exact:
        params["exact"] = "1"
    if filter:
        params["filter"] = filter
    if start_ea:
        params["start"] = start_ea
    if end_ea:
        params["end"] = end_ea
    if xref_type:
        params["type"] = xref_type
    return json.dumps(_get(f"/api/function/{_component(ea)}/xrefs-to", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_xrefs_from(
    ea: str,
    filter: Optional[str] = None,
    start_ea: Optional[str] = None,
    end_ea: Optional[str] = None,
    xref_type: Optional[str] = None,
) -> str:
    """Get all cross-references FROM this function (what it calls/references), with optional filters.
    
    Args:
        ea: Function address as hex string or 'module.dll+0xRVA'
        filter: Optional substring/regex filter on target function/symbol name
        start_ea: Optional target start address filter
        end_ea: Optional target end address filter
        xref_type: Optional xref type filter
    """
    params = {}
    if filter:
        params["filter"] = filter
    if start_ea:
        params["start"] = start_ea
    if end_ea:
        params["end"] = end_ea
    if xref_type:
        params["type"] = xref_type
    return json.dumps(_get(f"/api/function/{_component(ea)}/xrefs-from", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_callers(ea: str) -> str:
    """Get functions that call this function (caller graph).
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/callers"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_callees(ea: str) -> str:
    """Get functions called by this function (callee graph).
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/callees"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_call_graph(ea: str, depth: int = 3) -> str:
    """Get recursive call graph tree starting from function.
    
    Args:
        ea: Root function address
        depth: Recursion depth (default 3)
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/call-graph", depth=depth), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_basic_blocks(ea: str) -> str:
    """Get control flow graph (basic blocks with successors/predecessors).
    
    Args:
        ea: Function address as hex string
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/basic-blocks"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_strings_used(ea: str) -> str:
    """Get string constants referenced by a function (excludes machine code instructions).
    
    Args:
        ea: Function address as hex string or 'module.dll+0xRVA'
    """
    return json.dumps(_get(f"/api/function/{_component(ea)}/strings-used"), indent=2)

# ─── Search Tools ────────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def search_function(name: str) -> str:
    """Find functions by name (partial match).
    
    Args:
        name: Search query (partial function name)
    """
    return json.dumps(_get(f"/api/search-func/{_component(name)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def search_bytes(pattern: str) -> str:
    """Search for byte pattern in binary. Use ?? for wildcards.
    Example: 'E8 ?? ?? ?? ?? 48 8B'
    
    Args:
        pattern: Hex byte pattern with optional ?? wildcards
    """
    return json.dumps(_get(f"/api/search-bytes/{_component(pattern)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def search_text(text: str) -> str:
    """Search for text in disassembly listings.
    
    Args:
        text: Text to search for
    """
    return json.dumps(_get(f"/api/search-text/{_component(text)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_strings(
    filter: Optional[str] = None,
    offset: int = 0,
    limit: int = 500,
    start_ea: Optional[str] = None,
    end_ea: Optional[str] = None,
) -> str:
    """List strings found in the binary with full pagination and name/address-range filters.
    
    Args:
        filter: Optional substring or regex filter
        offset: Pagination start index (default 0)
        limit: Max strings per page (default 500, max 10000)
        start_ea: Optional start address filter
        end_ea: Optional end address filter
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if start_ea:
        params["start"] = start_ea
    if end_ea:
        params["end"] = end_ea
    return json.dumps(_get("/api/strings", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_names(
    filter: Optional[str] = None,
    offset: int = 0,
    limit: int = 500,
    start_ea: Optional[str] = None,
    end_ea: Optional[str] = None,
) -> str:
    """List named items (functions, variables, labels) with full pagination and filters.
    
    Args:
        filter: Optional substring or regex filter
        offset: Pagination start index (default 0)
        limit: Max names per page (default 500, max 10000)
        start_ea: Optional start address filter
        end_ea: Optional end address filter
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    if start_ea:
        params["start"] = start_ea
    if end_ea:
        params["end"] = end_ea
    return json.dumps(_get("/api/names", **params), indent=2)

# ─── Binary Structure ────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_imports() -> str:
    """List imported functions grouped by module (DLL/library)."""
    return json.dumps(_get("/api/imports"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_exports() -> str:
    """List exported functions with addresses."""
    return json.dumps(_get("/api/exports"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_segments() -> str:
    """List memory segments with permissions (read/write/execute)."""
    return json.dumps(_get("/api/segments"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def read_bytes(ea: str, size: int) -> str:
    """Read raw bytes from binary at specified address.
    
    Args:
        ea: Start address as hex string or 'module.dll+0xRVA'
        size: Number of bytes to read
    """
    return json.dumps(_get(f"/api/bytes/{_component(ea)}/{size}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def read_vtable(ea: str, max_entries: int = 64) -> str:
    """Read virtual function table entries at address with offsets, demangled names, and prototypes.
    
    Args:
        ea: Vtable start address (hex or 'module.dll+0xRVA')
        max_entries: Max vtable slots to inspect (default 64)
    """
    return json.dumps(_get(f"/api/vtable/{_component(ea)}", max=max_entries), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def create_vtable_struct(ea: str, name: str = "", max_entries: int = 64) -> str:
    """Automatically generate and register a C structure with typed function pointers from a vtable at address.
    
    Args:
        ea: Vtable address (hex or 'module.dll+0xRVA')
        name: Optional struct name (defaults to Vtable_<ea>)
        max_entries: Max vtable slots to include (default 64)
    """
    return json.dumps(_post("/api/vtable/create-struct", {"ea": ea, "name": name or None, "max_entries": max_entries}), indent=2)

# ─── Type System ─────────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_structs() -> str:
    """List all defined structures with sizes."""
    return json.dumps(_get("/api/structs"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_struct(name: str) -> str:
    """Get structure members with offsets, sizes, and types.
    
    Args:
        name: Structure name
    """
    return json.dumps(_get(f"/api/struct/{_component(name)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_enums() -> str:
    """List all defined enumerations."""
    return json.dumps(_get("/api/enums"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_types() -> str:
    """List all local types (structs, unions, enums, typedefs)."""
    return json.dumps(_get("/api/types"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_type(name: str) -> str:
    """Get detailed type information including struct/union members.
    
    Args:
        name: Type name
    """
    return json.dumps(_get(f"/api/type/{_component(name)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def create_type(definition: str) -> str:
    """Create a new type from C declaration.
    
    Args:
        definition: C type definition, e.g. 'struct Player { int health; float pos[3]; };'
    """
    return json.dumps(_post("/api/type/create", {"definition": definition}))

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_classes(
    filter_pattern: Optional[str] = None,
    toplevel_only: bool = False,
    include_hidden: bool = False,
) -> str:
    """List decompiler language-neutral classes (IDA 9.5+ Hex-Rays Class API for C++, Dalvik, Swift, Go, Rust)."""
    params = {}
    if filter_pattern:
        params["filter"] = filter_pattern
    if toplevel_only:
        params["toplevel"] = "1"
    if include_hidden:
        params["hidden"] = "1"
    return json.dumps(_get("/api/classes", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_class(
    name: str,
    ea: Optional[str] = None,
    render: bool = True,
    no_bodies: bool = False,
) -> str:
    """Get language-neutral class layout, rendered members, and methods (IDA 9.5+).
    
    Args:
        name: Class name
        ea: Optional class address override
        render: Include rendered C++/language representation (default True)
        no_bodies: Omit method bodies in rendered output (default False)
    """
    params = {}
    if ea is not None:
        params["ea"] = ea
    if not render:
        params["render"] = "0"
    if no_bodies:
        params["no_bodies"] = "1"
    return json.dumps(_get(f"/api/class/{_component(name)}", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_decompiler_timeout() -> str:
    """Get Hex-Rays decompiler timeout in seconds (IDA 9.5+)."""
    return json.dumps(_get("/api/decompiler/timeout"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def set_decompiler_timeout(seconds: int) -> str:
    """Set Hex-Rays decompiler timeout in seconds (0 = default, IDA 9.5+).
    
    Args:
        seconds: Timeout in seconds
    """
    return json.dumps(_post("/api/decompiler/timeout", {"seconds": seconds}))

# ─── Mutation Tools ──────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def rename_function(ea: str, name: str) -> str:
    """Rename function at address.
    
    Args:
        ea: Function address as hex string
        name: New function name
    """
    return json.dumps(_post(f"/api/function/{_component(ea)}/rename", {"name": name}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def comment_function(ea: str, comment: str) -> str:
    """Set function comment.
    
    Args:
        ea: Function address as hex string
        comment: Comment text
    """
    return json.dumps(_post(f"/api/function/{_component(ea)}/comment", {"comment": comment}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def set_inline_comment(ea: str, comment: str) -> str:
    """Set inline comment at specific address.
    
    Args:
        ea: Address as hex string
        comment: Comment text
    """
    return json.dumps(_post(f"/api/address/{_component(ea)}/comment", {"comment": comment}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def rename_variable(ea: str, old_name: str, new_name: str) -> str:
    """Rename local variable in a decompiled function.
    
    Args:
        ea: Function address
        old_name: Current variable name
        new_name: New variable name
    """
    return json.dumps(_post(f"/api/function/{_component(ea)}/lvar-rename", {"old": old_name, "new": new_name}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def set_variable_type(ea: str, var_name: str, type_str: str) -> str:
    """Change local variable type in decompiled function.
    
    Args:
        ea: Function address
        var_name: Variable name
        type_str: C type string (e.g. 'DWORD *', 'struct Player *')
    """
    return json.dumps(_post(f"/api/function/{_component(ea)}/lvar-set-type", {"var": var_name, "type": type_str}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def set_function_type(ea: str, prototype: str) -> str:
    """Set function prototype/signature.
    
    Args:
        ea: Function address
        prototype: C prototype (e.g. 'int __fastcall(void *this, int count)')
    """
    return json.dumps(_post(f"/api/function/{_component(ea)}/set-type", {"type": prototype}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def create_struct(definition: str) -> str:
    """Create structure from C definition.
    
    Args:
        definition: C struct definition, e.g. 'struct Entity { int id; char name[32]; };'
    """
    return json.dumps(_post("/api/struct/create", {"definition": definition}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def patch_bytes(ea: str, hex_bytes: str) -> str:
    """Patch bytes in the binary. Use hex string with spaces.
    
    Args:
        ea: Address to patch
        hex_bytes: Hex bytes, e.g. '90 90 90' for NOPs
    """
    return json.dumps(_post("/api/patch-bytes", {"ea": ea, "bytes": hex_bytes}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def batch_mutations(mutations: str, dry_run: bool = False, mode: str = "rollback") -> str:
    """Prevalidate a batch and compensate supported name/comment values on failure.
    Pass a JSON array string of operations.
    
    Args:
        dry_run: Preview the validated plan without database writes.
        mode: rollback for names/comments; best_effort for types/locals, without compensation.
        mutations: JSON array string, e.g. '[{"op":"rename-func","ea":"0x...","name":"new_name"}]'
    """
    ops = json.loads(mutations)
    if not isinstance(ops, list):
        raise ValueError("mutations must decode to a JSON array")
    return json.dumps(_post("/api/batch", {"mutations": ops, "dry_run": dry_run, "mode": mode}), indent=2)

# ─── Debugger Tools ──────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_status() -> str:
    """Get comprehensive debugger state: process state, IP/SP, current thread, module, function, instruction, breakpoint count, and trace configuration."""
    return json.dumps(_get("/api/dbg/status"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_load_debugger(name: str, remote: bool = False, host: str = "", port: int = 0, password: str = "") -> str:
    """Load an IDA debugger backend (e.g. 'win32', 'linux', 'macos', 'gdb', 'windbg', 'bochs', 'dalvik') and optionally configure a remote debug target.
    
    Args:
        name: Debugger backend name (e.g. 'win32', 'gdb', 'windbg')
        remote: Whether to use a remote debugging stub
        host: Remote hostname or IP
        port: Remote port number
        password: Optional remote stub password
    """
    return json.dumps(_post("/api/dbg/load", {"name": name, "remote": remote, "host": host, "port": port, "password": password}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_start(path: str = "", args: str = "", sdir: str = "") -> str:
    """Start debugging the current binary or specified executable.
    
    Args:
        path: Optional path to executable (defaults to current binary)
        args: Command line arguments
        sdir: Optional working directory
    """
    return json.dumps(_post("/api/dbg/start", {"path": path or None, "args": args, "sdir": sdir or None}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_exit() -> str:
    """Terminate the currently debugged process."""
    return json.dumps(_post("/api/dbg/exit"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_list_processes() -> str:
    """List running processes visible to the active debugger backend."""
    return json.dumps(_get("/api/dbg/processes"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_attach(pid: int) -> str:
    """Attach debugger to a running process by PID.
    
    Args:
        pid: Process ID to attach to
    """
    return json.dumps(_post("/api/dbg/attach", {"pid": pid}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_detach() -> str:
    """Detach debugger from the currently attached process."""
    return json.dumps(_post("/api/dbg/detach"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_pause() -> str:
    """Pause/suspend the running debugged process."""
    return json.dumps(_post("/api/dbg/pause"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_set_breakpoint(
    ea: str,
    hardware: bool = False,
    mode: str = "exec",
    size: int = 1,
    condition: str = "",
    elang: str = "",
    pass_count: int = 0,
    trace_only: bool = False,
    enabled: bool = True,
    tid: Optional[int] = None,
    action: str = "stop",
    auto_continue: bool = False,
    log_regs: Optional[list[str]] = None,
    delete: bool = False,
) -> str:
    """Set, update, or delete a software/hardware breakpoint or memory watchpoint at address.
    Supports module+RVA addresses (e.g. 'networksystem.dll+0xC3EA7'), read/write watchpoints,
    conditions, thread filtering (tid), and 'log_and_continue' hit actions.
    
    Args:
        ea: Address for breakpoint (hex '0x...', symbol, or 'module.dll+0xRVA')
        hardware: Use hardware breakpoint (default False; auto-enabled when mode is read/write/rw)
        mode: Access mode ('exec', 'write', 'read', 'rw', 'soft')
        size: Breakpoint/watchpoint range size in bytes (e.g. 1, 2, 4, 8)
        condition: Optional IDC/Python condition expression (e.g. 'rdx >= 0x1000 && rdx < 0x2000')
        elang: Condition language ('Python' or 'IDC'; auto-detected if empty)
        pass_count: Number of hits to ignore before breaking
        trace_only: Log hit to trace without stopping execution
        enabled: Whether the breakpoint is enabled initially
        tid: Optional thread ID filter (only trigger on this thread; auto-continues other threads)
        action: Hit action ('stop' or 'log_and_continue' to log registers and resume automatically)
        auto_continue: Automatically resume execution after logging registers in breakpoint event log
        log_regs: Optional list of register names to log on hit (defaults to all GPRs)
        delete: If True, delete the breakpoint at 'ea' instead of setting it
    """
    return json.dumps(_post("/api/dbg/breakpoint", {
        "ea": ea,
        "hardware": hardware,
        "mode": mode,
        "size": size,
        "condition": condition,
        "elang": elang,
        "pass_count": pass_count,
        "trace_only": trace_only,
        "enabled": enabled,
        "tid": tid,
        "action": action,
        "auto_continue": auto_continue,
        "log_regs": log_regs,
        "delete": delete,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_set_watchpoint(
    ea: str,
    mode: str = "rw",
    size: int = 4,
    condition: str = "",
    elang: str = "",
    pass_count: int = 0,
    trace_only: bool = False,
    tid: Optional[int] = None,
    action: str = "stop",
    auto_continue: bool = False,
    log_regs: Optional[list[str]] = None,
) -> str:
    """Set a hardware data watchpoint (read, write, or read/write) on a memory address or range.
    
    Args:
        ea: Memory address to watch (hex '0x...' or 'module.dll+0xRVA')
        mode: Watch mode: 'rw' (read/write), 'write', or 'read'
        size: Watch size in bytes (1, 2, 4, 8, or range size)
        condition: Optional condition expression
        elang: Condition language ('Python' or 'IDC')
        pass_count: Pass count before breaking
        trace_only: Record trace event without stopping
        tid: Optional thread ID filter
        action: Hit action ('stop' or 'log_and_continue')
        auto_continue: Automatically continue after logging registers on hit
        log_regs: Optional list of register names to capture on hit
    """
    return json.dumps(_post("/api/dbg/watchpoint", {
        "ea": ea,
        "mode": mode,
        "size": size,
        "condition": condition,
        "elang": elang,
        "pass_count": pass_count,
        "trace_only": trace_only,
        "enabled": True,
        "tid": tid,
        "action": action,
        "auto_continue": auto_continue,
        "log_regs": log_regs,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_list_breakpoints() -> str:
    """List all breakpoints and watchpoints with conditions, pass counts, hit counts, thread filters, and module+RVA."""
    return json.dumps(_get("/api/dbg/breakpoints"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_delete_breakpoint(ea: str) -> str:
    """Delete a breakpoint or watchpoint at address.
    
    Args:
        ea: Breakpoint address (hex '0x...' or 'module.dll+0xRVA')
    """
    return json.dumps(_post("/api/dbg/del-breakpoint", {"ea": ea}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': True})
def dbg_toggle_breakpoint(ea: str, enable: bool = True) -> str:
    """Enable or disable an existing breakpoint at address.
    
    Args:
        ea: Breakpoint address (hex '0x...' or 'module.dll+0xRVA')
        enable: True to enable, False to disable
    """
    return json.dumps(_post("/api/dbg/toggle-breakpoint", {"ea": ea, "enable": enable}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_update_breakpoint(
    ea: str,
    condition: Optional[str] = None,
    elang: Optional[str] = None,
    pass_count: Optional[int] = None,
    trace_only: Optional[bool] = None,
    enabled: Optional[bool] = None,
    mode: Optional[str] = None,
    size: Optional[int] = None,
    tid: Optional[int] = None,
    action: Optional[str] = None,
    auto_continue: Optional[bool] = None,
    log_regs: Optional[list[str]] = None,
) -> str:
    """Update condition, pass count, thread filter, log-and-continue action, or mode on an existing breakpoint.
    
    Args:
        ea: Breakpoint address
        condition: New condition expression
        elang: Condition language ('Python' or 'IDC')
        pass_count: New pass count
        trace_only: Whether to trace without stopping
        enabled: Enable or disable
        mode: Access mode ('exec', 'write', 'read', 'rw', 'soft')
        size: Watchpoint size in bytes
        tid: Optional thread ID filter (0 to clear)
        action: Hit action ('stop' or 'log_and_continue')
        auto_continue: Auto-continue after logging registers
        log_regs: List of register names to log on hit
    """
    return json.dumps(_post("/api/dbg/update-breakpoint", {
        "ea": ea,
        "condition": condition,
        "elang": elang,
        "pass_count": pass_count,
        "trace_only": trace_only,
        "enabled": enabled,
        "mode": mode,
        "size": size,
        "tid": tid,
        "action": action,
        "auto_continue": auto_continue,
        "log_regs": log_regs,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_export_breakpoints(save_path: str = "") -> str:
    """Export all current breakpoints and watchpoints (with module+RVA, conditions, and policies) for persistence across runs.
    
    Args:
        save_path: Optional local file path to save the exported breakpoints JSON
    """
    res = _get("/api/dbg/breakpoints/export")
    if save_path and save_path.strip():
        out_file = _safe_client_file_path(save_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        res["saved_to"] = str(out_file)
    return json.dumps(res, indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_import_breakpoints(load_path: str = "", breakpoints_json: str = "[]", clear_existing: bool = False) -> str:
    """Restore breakpoints and watchpoints from a saved JSON file or JSON array (resolving module+RVA against current ASLR base).
    
    Args:
        load_path: Optional local path to a JSON file exported by dbg_export_breakpoints
        breakpoints_json: Optional JSON array of breakpoint definitions if load_path is not used
        clear_existing: Delete existing breakpoints before importing
    """
    if load_path and load_path.strip():
        in_file = _safe_client_file_path(load_path)
        loaded = json.loads(in_file.read_text(encoding="utf-8"))
        bps = loaded.get("breakpoints", []) if isinstance(loaded, dict) else loaded
    else:
        bps = json.loads(breakpoints_json) if breakpoints_json else []
    if not isinstance(bps, list):
        raise ValueError("breakpoints must decode to a list")
    return json.dumps(_post("/api/dbg/breakpoints/import", {
        "breakpoints": bps,
        "clear_existing": clear_existing,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def capture_evidence(
    ea: str = "",
    include_stack: bool = True,
    include_modules: bool = True,
    include_breakpoints: bool = True,
    memory_ranges_json: str = "[]",
    notes: str = "",
    save_path: str = "",
) -> str:
    """Capture structured reverse-engineering and debugging evidence (binary hashes/build ID, module+RVA, registers, stack, memory dumps) to JSON.
    
    Args:
        ea: Optional target address to include function/disassembly context for
        include_stack: Include call stack trace
        include_modules: Include loaded modules list
        include_breakpoints: Include active breakpoints and hit counts
        memory_ranges_json: Optional JSON array of [{'ea': '...', 'size': 64, 'label': '...'}] memory ranges to dump
        notes: Optional analyst notes to embed in the evidence artifact
        save_path: Optional local file path to save the evidence JSON
    """
    mem_ranges = json.loads(memory_ranges_json) if memory_ranges_json else []
    raw_res = client.call_api("POST", "/api/dbg/evidence", {
        "ea": ea,
        "include_stack": include_stack,
        "include_modules": include_modules,
        "include_breakpoints": include_breakpoints,
        "memory_ranges": mem_ranges,
        "notes": notes,
    })
    if raw_res.get("error") == "Bridge is configured read-only":
        ev_params = {"ea": ea} if ea else {}
        raw_res = client.call_api("GET", "/api/dbg/evidence", ev_params)
        if not raw_res.get("error") and notes:
            raw_res["notes"] = notes
    res = _checked(raw_res)
    if notes and "notes" not in res:
        res["notes"] = notes
    if save_path and save_path.strip():
        out_file = _safe_client_file_path(save_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
        res["saved_to"] = str(out_file)
    return json.dumps(res, indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_continue(wait: bool = False, timeout: int = 5) -> str:
    """Continue process execution (resume from breakpoint/pause).
    
    Args:
        wait: Wait synchronously for next debugger event and return updated CPU state
        timeout: Wait timeout in seconds when wait=True
    """
    req_timeout = max(client.timeout, float(timeout) + 5.0) if wait else None
    return json.dumps(_post("/api/dbg/continue", {"wait": wait, "timeout": timeout}, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_step_into(wait: bool = False, timeout: int = 5) -> str:
    """Step into the next instruction (follows calls).
    
    Args:
        wait: Wait synchronously for step completion and return updated CPU state
        timeout: Wait timeout in seconds when wait=True
    """
    req_timeout = max(client.timeout, float(timeout) + 5.0) if wait else None
    return json.dumps(_post("/api/dbg/step-into", {"wait": wait, "timeout": timeout}, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_step_over(wait: bool = False, timeout: int = 5) -> str:
    """Step over the next instruction (skips calls).
    
    Args:
        wait: Wait synchronously for step completion and return updated CPU state
        timeout: Wait timeout in seconds when wait=True
    """
    req_timeout = max(client.timeout, float(timeout) + 5.0) if wait else None
    return json.dumps(_post("/api/dbg/step-over", {"wait": wait, "timeout": timeout}, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_step_out(wait: bool = False, timeout: int = 5) -> str:
    """Step execution until the current function returns.
    
    Args:
        wait: Wait synchronously for return and return updated CPU state
        timeout: Wait timeout in seconds when wait=True
    """
    req_timeout = max(client.timeout, float(timeout) + 5.0) if wait else None
    return json.dumps(_post("/api/dbg/step-out", {"wait": wait, "timeout": timeout}, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_run_to(ea: str, wait: bool = False, timeout: int = 5) -> str:
    """Run execution until reaching the target address.
    
    Args:
        ea: Target address to run to
        wait: Wait synchronously until target is reached
        timeout: Wait timeout in seconds when wait=True
    """
    req_timeout = max(client.timeout, float(timeout) + 5.0) if wait else None
    return json.dumps(_post("/api/dbg/run-to", {"ea": ea, "wait": wait, "timeout": timeout}, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': False, 'openWorldHint': True})
def dbg_wait_event(
    timeout: int = 5,
    wfne: Optional[int] = None,
    wait_for_suspend: bool = True,
    resume: bool = False,
    silent: bool = True,
) -> str:
    """Wait synchronously for the next debugger event without freezing IDA's UI thread.
    
    Args:
        timeout: Timeout in seconds (0..300)
        wfne: Optional explicit IDA WFNE_* bitmask override
        wait_for_suspend: Wait for process suspension event (default True)
        resume: Resume execution before waiting (default False)
        silent: Suppress modal IDA dialogs during wait (default True)
    """
    payload = {
        "timeout": timeout,
        "wait_for_suspend": wait_for_suspend,
        "resume": resume,
        "silent": silent,
    }
    if wfne is not None:
        payload["wfne"] = wfne
    req_timeout = max(client.timeout, float(timeout) + 5.0)
    return json.dumps(_post("/api/dbg/wait", payload, timeout=req_timeout), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_registers(tid: Optional[int] = None, include_all: bool = False) -> str:
    """Read CPU registers with pointer/symbol telescoping (debugger must be active).
    
    Args:
        tid: Optional thread ID (defaults to current thread)
        include_all: Include FPU/XMM/YMM/vector registers in addition to general-purpose registers
    """
    params = {}
    if tid is not None:
        params["tid"] = str(tid)
    if include_all:
        params["all"] = "1"
    return json.dumps(_get("/api/dbg/regs", **params), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_set_register(reg: str, value: str, tid: Optional[int] = None) -> str:
    """Modify a CPU register value in the active debug session.
    
    Args:
        reg: Register name (e.g. 'RAX', 'EIP', 'RIP', 'ZF')
        value: New value as hex string (e.g. '0x1') or integer string
        tid: Optional thread ID
    """
    return json.dumps(_post("/api/dbg/set-reg", {"reg": reg, "value": value, "tid": tid}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_read_memory(ea: str, size: int) -> str:
    """Read process memory at runtime with hex, ASCII, and pointer annotations (debugger must be active).
    
    Args:
        ea: Memory address
        size: Number of bytes to read
    """
    return json.dumps(_get(f"/api/dbg/memory/{_component(ea)}/{size}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_write_memory(ea: str, hex_bytes: str) -> str:
    """Write bytes into live debugged process memory.
    
    Args:
        ea: Target memory address
        hex_bytes: Hex byte string (e.g. '90 90' or '9090')
    """
    return json.dumps(_post("/api/dbg/write-memory", {"ea": ea, "bytes": hex_bytes}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_memory_map() -> str:
    """Get the live virtual memory map of the debugged process with permissions (RWX)."""
    return json.dumps(_get("/api/dbg/memory-map"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_refresh_memory() -> str:
    """Force IDA to refresh debugger memory layout and segmentation from the live process."""
    return json.dumps(_post("/api/dbg/refresh-memory"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_search_memory(
    pattern: str,
    start: Optional[str] = None,
    end: Optional[str] = None,
    max_results: int = 100,
) -> str:
    """Search live debugged process memory for a hex byte pattern (with ?? wildcards) or ASCII string.
    
    Args:
        pattern: Hex pattern (e.g. '48 8B ?? ??') or ASCII text
        start: Optional start address
        end: Optional end address
        max_results: Maximum matches to return (default 100)
    """
    return json.dumps(_post("/api/dbg/search-memory", {
        "pattern": pattern,
        "start": start,
        "end": end,
        "max_results": max_results,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_list_modules() -> str:
    """List loaded modules/DLLs/shared libraries in the debugged process."""
    return json.dumps(_get("/api/dbg/modules"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_list_threads() -> str:
    """List all threads in the debugged process and identify the active thread."""
    return json.dumps(_get("/api/dbg/threads"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_thread_action(tid: int, action: str = "select") -> str:
    """Select, suspend, or resume a thread in the debugged process.
    
    Args:
        tid: Thread ID
        action: One of 'select', 'suspend', 'resume'
    """
    return json.dumps(_post("/api/dbg/thread-action", {"tid": tid, "action": action}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_stack() -> str:
    """Get call stack trace with module/function symbol resolution (debugger must be active)."""
    return json.dumps(_get("/api/dbg/stack"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_configure_trace(
    insn: Optional[bool] = None,
    func: Optional[bool] = None,
    bblk: Optional[bool] = None,
    step: Optional[bool] = None,
    buf_size: Optional[int] = None,
) -> str:
    """Configure instruction, function, basic-block, or step tracing in the debugger.
    
    Args:
        insn: Enable/disable instruction tracing
        func: Enable/disable function call/return tracing
        bblk: Enable/disable basic block tracing
        step: Enable/disable step tracing
        buf_size: Trace buffer size
    """
    return json.dumps(_post("/api/dbg/trace/configure", {
        "insn": insn,
        "func": func,
        "bblk": bblk,
        "step": step,
        "buf_size": buf_size,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_trace(count: int = 50, offset: int = 0) -> str:
    """Read recorded trace events (instruction/function/basic-block trace).
    
    Args:
        count: Max trace records to return (default 50, max 500)
        offset: Offset from newest trace event (default 0)
    """
    return json.dumps(_get("/api/dbg/trace", count=count, offset=offset), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': True})
def dbg_clear_trace() -> str:
    """Clear the debugger's recorded trace buffer."""
    return json.dumps(_post("/api/dbg/trace/clear"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_list_exceptions() -> str:
    """List debugger exception handling rules (signals/SEH codes, break/pass flags)."""
    return json.dumps(_get("/api/dbg/exceptions"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': True})
def dbg_configure_exception(
    code: str,
    break_on: Optional[bool] = None,
    handle: Optional[bool] = None,
    msg: Optional[bool] = None,
    save: bool = True,
) -> str:
    """Configure how the debugger handles a specific exception or signal code.
    
    Args:
        code: Exception code (e.g. '0xC0000005' or '11')
        break_on: Suspend into debugger when exception occurs
        handle: Debugger handles/suppresses exception instead of passing to application
        msg: Log exception to IDA output window
        save: Persist updated exception table to IDB
    """
    return json.dumps(_post("/api/dbg/exceptions", {
        "code": code,
        "break": break_on,
        "handle": handle,
        "msg": msg,
        "save": save,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': True})
def dbg_get_events(limit: int = 50) -> str:
    """Get buffered debugger hook events (breakpoints hit, exceptions, thread/library load/unload).
    
    Args:
        limit: Max events to return (default 50)
    """
    return json.dumps(_get("/api/dbg/events", limit=limit), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': True})
def dbg_clear_events() -> str:
    """Clear the buffered debugger hook event log."""
    return json.dumps(_post("/api/dbg/events/clear"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_send_command(cmd: str) -> str:
    """Send a raw command to the underlying debugger backend (WinDbg, GDB, Bochs, etc.). Requires IDA_BRIDGE_ALLOW_EXEC=1.
    
    Args:
        cmd: Debugger CLI command (e.g. '!peb', 'info proc mappings')
    """
    return json.dumps(_post("/api/dbg/cmd", {"cmd": cmd}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def dbg_appcall(ea: str, proto: str = "", args_json: str = "[]", tid: Optional[int] = None) -> str:
    """Execute a function inside the suspended debugged process using IDA Appcall. Requires IDA_BRIDGE_ALLOW_EXEC=1.
    
    Args:
        ea: Target function address or name
        proto: Optional C function prototype override (e.g. 'int __fastcall(int a, const char *b)')
        args_json: JSON array of arguments (e.g. '[42, "hello"]')
        tid: Optional thread ID to run the Appcall on
    """
    parsed_args = json.loads(args_json) if args_json else []
    if not isinstance(parsed_args, list):
        raise ValueError("args_json must decode to a JSON array")
    return json.dumps(_post("/api/dbg/appcall", {
        "ea": ea,
        "proto": proto,
        "args": parsed_args,
        "tid": tid,
    }), indent=2)

# ─── Utility Tools ───────────────────────────────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': True})
def execute_idapython(script: str) -> str:
    """Execute IDAPython with full SDK access when the server explicitly enables it.
    Use the global 'result' dict to return structured data.
    
    Args:
        script: Python code to execute in IDA's environment
    """
    return json.dumps(_post("/api/exec", {"script": script}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def undo() -> str:
    """Undo the last action in IDA."""
    return json.dumps(_post("/api/undo"))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def redo() -> str:
    """Redo the last undone action."""
    return json.dumps(_post("/api/redo"))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def navigate_to(ea: str) -> str:
    """Move IDA's cursor to the specified address.
    
    Args:
        ea: Address to navigate to
    """
    return json.dumps(_post("/api/navigate", {"ea": ea}))

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def save_database() -> str:
    """Save the current IDA database (.idb/.i64)."""
    return json.dumps(_post("/api/save"))

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_ida_instances() -> str:
    """List all running IDA Pro bridge instances (ports, PIDs, binary names, IDB paths) registered on this machine."""
    return json.dumps(client.list_instances(), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def select_ida_instance(target: str) -> str:
    """Switch the active IDA Pro bridge connection to another running IDA instance by binary name (e.g. 'networksystem.dll', 'tier0.dll'), port ('13371'), or PID.
    
    Args:
        target: Binary name substring, port number, or PID of the IDA instance to select
    """
    return json.dumps(client.select_instance(target), indent=2)

# ─── Extended Type, Structure & Enum Tools ───────────────────────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_enum(name: str) -> str:
    """Get detailed enumeration members and constant values by enum name."""
    return json.dumps(_get(f"/api/enum/{_component(name)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def create_enum(name: str, width: int = 4) -> str:
    """Create a new enumeration in the IDA database (width: 1, 2, 4, or 8 bytes)."""
    return json.dumps(_post("/api/enum/create", {"name": name, "width": width}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def add_enum_member(enum_name: str, member: str, value: int = 0) -> str:
    """Add a named constant member to an existing enumeration."""
    return json.dumps(_post("/api/enum/add-member", {"enum": enum_name, "member": member, "value": value}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_enum(name: str) -> str:
    """Delete an enumeration from the IDA database."""
    return json.dumps(_post("/api/delete-enum", {"name": name}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def add_struct_member(
    struct_name: str,
    member: str,
    offset: int = -1,
    size: int = 4,
    type_str: Optional[str] = None,
) -> str:
    """Add a field/member to an existing structure or union."""
    payload = {"struct": struct_name, "member": member, "offset": offset, "size": size}
    if type_str is not None:
        payload["type"] = type_str
    return json.dumps(_post("/api/struct/add-member", payload), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_struct(name: str) -> str:
    """Delete a structure or union by name."""
    return json.dumps(_post("/api/delete-struct", {"name": name}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def apply_struct(ea: str, struct_name: str) -> str:
    """Apply a structure layout at a data address in the binary."""
    return json.dumps(_post("/api/apply-struct", {"ea": ea, "struct": struct_name}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_type(name: str) -> str:
    """Delete a local type from IDA's type library."""
    return json.dumps(_post("/api/type/delete", {"name": name}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_type_libraries() -> str:
    """List loaded IDA type libraries (.til)."""
    return json.dumps(_get("/api/type-libraries"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def load_type_library(name: str) -> str:
    """Load an IDA type library (.til) by name (e.g. 'mssdk64_win10', 'gnulnx_x64')."""
    return json.dumps(_post("/api/type-library/load", {"name": name}), indent=2)

# ─── Code, Data, Function & Analysis Control Tools ───────────────────────────

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def make_function(ea: str) -> str:
    """Define a function starting at the given address."""
    return json.dumps(_post("/api/make-func", {"ea": ea}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_function(ea: str) -> str:
    """Delete the function definition at the given address."""
    return json.dumps(_post("/api/delete-func", {"ea": ea}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def make_code(ea: str, size: int = 0) -> str:
    """Convert raw bytes at address into disassembled instructions."""
    return json.dumps(_post("/api/make-code", {"ea": ea, "size": size}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def make_data(ea: str, size: int = 4) -> str:
    """Convert bytes at address into typed data items (1, 2, 4, or 8 bytes)."""
    return json.dumps(_post("/api/make-data", {"ea": ea, "size": size}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def undefine(ea: str, size: int = 1) -> str:
    """Undefine code or data items across an address range."""
    return json.dumps(_post("/api/undefine", {"ea": ea, "size": size}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def set_name(ea: str, name: str) -> str:
    """Set or clear a symbol/label name at any code or data address."""
    return json.dumps(_post("/api/set-name", {"ea": ea, "name": name}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def reanalyze(start_ea: str, end_ea: str) -> str:
    """Trigger IDA auto-analysis across `[start_ea, end_ea)` and wait for completion."""
    return json.dumps(_post("/api/reanalyze", {"start": start_ea, "end": end_ea}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def wait_for_analysis() -> str:
    """Wait until IDA's background auto-analyzer queue becomes idle."""
    return json.dumps(_get("/api/wait-analysis"), indent=2)

# ─── Deep Inspection, Metadata, Bookmarks, UI & Segment Tools ────────────────

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_global_vars() -> str:
    """List global data variables in non-executable segments."""
    return json.dumps(_get("/api/global-vars"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_stack_vars(ea: str) -> str:
    """Get stack frame variables, offsets, sizes, and types for a function."""
    return json.dumps(_get(f"/api/function/{_component(ea)}/stack-vars"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_switch_info(ea: str) -> str:
    """Inspect switch/jump-table cases and target addresses at an indirect jump instruction."""
    return json.dumps(_get(f"/api/function/{_component(ea)}/switch"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_instruction(ea: str) -> str:
    """Decode a single machine instruction with mnemonic, size, and structured operands."""
    return json.dumps(_get(f"/api/insn/{_component(ea)}"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_patches() -> str:
    """List all patched bytes in the current IDA database."""
    return json.dumps(_get("/api/patches"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_function_gaps() -> str:
    """Find unanalyzed or non-function gaps between defined functions."""
    return json.dumps(_get("/api/gaps"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def list_bookmarks() -> str:
    """List all marked positions (bookmarks) in the IDA database."""
    return json.dumps(_get("/api/bookmarks"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': False, 'openWorldHint': False})
def add_bookmark(ea: str, description: str = "", slot: int = -1) -> str:
    """Add a bookmark at the given address (auto-selecting a free slot when slot=-1)."""
    return json.dumps(_post("/api/add-bookmark", {"ea": ea, "description": description, "slot": slot}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_bookmark(slot: int) -> str:
    """Delete an IDA bookmark by slot index."""
    return json.dumps(_post("/api/delete-bookmark", {"slot": slot}), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_cursor() -> str:
    """Get the current IDA GUI cursor address (`here()`)."""
    return json.dumps(_get("/api/cursor"), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def get_selection() -> str:
    """Get the currently selected address range in the IDA GUI."""
    return json.dumps(_get("/api/selection"), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False})
def create_segment(
    start_ea: str,
    end_ea: str,
    name: str = "seg",
    seg_class: str = "DATA",
    bitness: int = 2,
) -> str:
    """Create a new memory segment (`bitness`: 0=16-bit, 1=32-bit, 2=64-bit)."""
    return json.dumps(_post("/api/segment/create", {
        "start": start_ea,
        "end": end_ea,
        "name": name,
        "class": seg_class,
        "bitness": bitness,
    }), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def delete_segment(ea: str) -> str:
    """Delete the memory segment containing `ea`."""
    return json.dumps(_post("/api/segment/delete", {"ea": ea}), indent=2)

@mcp.tool(annotations={'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': True, 'openWorldHint': False})
def set_segment_attrs(
    ea: str,
    name: Optional[str] = None,
    seg_class: Optional[str] = None,
    perm: Optional[str] = None,
) -> str:
    """Modify segment attributes (`name`, `seg_class` e.g. 'CODE'/'DATA'/'CONST', `perm` e.g. 'r-x'/'rw-')."""
    payload: dict = {"ea": ea}
    if name is not None:
        payload["name"] = name
    if seg_class is not None:
        payload["class"] = seg_class
    if perm is not None:
        payload["perm"] = perm
    return json.dumps(_post("/api/segment/set-attrs", payload), indent=2)

@mcp.tool(annotations={'readOnlyHint': True, 'destructiveHint': False, 'idempotentHint': True, 'openWorldHint': False})
def analyze_function_context(ea: str) -> str:
    """Fetch complete combined analysis context for a function in one call (pseudocode, local vars, callers, callees, strings, xrefs, basic blocks)."""
    return json.dumps(_get("/api/macro/analyze_context", ea=ea), indent=2)

# ─── Entry Point ─────────────────────────────────────────────────────────────


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()

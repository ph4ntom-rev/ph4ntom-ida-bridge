"""
Antigravity-IDA Bridge Server Plugin
=====================================
Lightweight HTTP server running inside IDA Pro 9.x.
All operations are thread-safe via ida_kernwin.execute_sync().

Installation:
  Copy this file to IDA's plugins directory or run via File > Script File.

Usage:
  Once loaded, the server listens on http://127.0.0.1:13370
  Use bridge_cli.py to interact from outside.
"""

import json
import threading
import traceback
import re
import secrets
import tempfile
import os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# IDA imports
import ida_kernwin
import ida_funcs
import ida_name
import ida_bytes
import ida_segment
import ida_nalt
import ida_entry
import ida_idaapi
import ida_auto
import ida_lines
import ida_xref  # noqa: F401
import ida_typeinf
try:
    import ida_range
except ImportError:
    pass
import idautils
import idc

# Hex-Rays (optional — decompiler may not be available)
try:
    import ida_hexrays
    HAS_HEXRAYS = True
except ImportError:
    HAS_HEXRAYS = False

# ─── Configuration ───────────────────────────────────────────────────────────

HOST = "127.0.0.1"
PORT = 13370
MAX_FUNCTIONS = 5000
MAX_STRINGS = 2000
_cached_schema = None

# ─── Authentication ──────────────────────────────────────────────────────────

AUTH_TOKEN = secrets.token_hex(16)
_token_path = os.path.join(tempfile.gettempdir(), ".antigravity_token")
with open(_token_path, "w") as _f:
    _f.write(AUTH_TOKEN)
AUTH_ENABLED = True  # Set to False to disable auth (not recommended)

# ─── Thread-Safe Execution ───────────────────────────────────────────────────

def safe_read(func):
    """Execute function in IDA's main thread (read mode)."""
    result = [None]
    error = [None]
    def wrapper():
        try:
            result[0] = func()
        except Exception:
            error[0] = traceback.format_exc()
    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_READ)
    if error[0]:
        raise RuntimeError(error[0])
    return result[0]

def safe_write(func):
    """Execute function in IDA's main thread (write mode)."""
    result = [None]
    error = [None]
    def wrapper():
        try:
            result[0] = func()
        except Exception:
            error[0] = traceback.format_exc()
    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
    if error[0]:
        raise RuntimeError(error[0])
    return result[0]

def _xref_type_str(t):
    """Convert xref type to string (IDA 9.x compat)."""
    _MAP = {0: "Data_Unknown", 1: "Data_Offset", 2: "Data_Write", 3: "Data_Read",
            16: "Code_Far_Call", 17: "Code_Near_Call", 18: "Code_Far_Jump",
            19: "Code_Near_Jump", 20: "Code_User", 21: "Code_Ordinary_Flow"}
    return _MAP.get(t, f"type_{t}")

# ─── Sensor Functions (Read API) ─────────────────────────────────────────────

def get_info():
    """Get basic information about the loaded binary."""
    def _inner():
        import ida_ida
        # IDA 9.x compatible — use ida_ida / idc.get_inf_attr
        procname = ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else "unknown"
        is_64 = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else False
        is_32 = ida_ida.inf_is_32bit() if hasattr(ida_ida, 'inf_is_32bit') else True
        min_ea = ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0
        max_ea = ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else 0
        start_ea = ida_ida.inf_get_start_ea() if hasattr(ida_ida, 'inf_get_start_ea') else 0
        return {
            "filename": ida_nalt.get_root_filename(),
            "filepath": ida_nalt.get_input_file_path(),
            "processor": procname,
            "bitness": 64 if is_64 else (32 if is_32 else 16),
            "file_type": ida_loader_type(),
            "entry_point": hex(start_ea),
            "min_ea": hex(min_ea),
            "max_ea": hex(max_ea),
            "hexrays_available": HAS_HEXRAYS,
            "analysis_done": ida_auto.auto_is_ok(),
        }
    return safe_read(_inner)

def ida_loader_type():
    """Get file type string."""
    try:
        import ida_loader
        ft = ida_loader.get_file_type_name()
        return ft if ft else "unknown"
    except:
        return "unknown"

def get_functions():
    """List all functions with address, name, and size."""
    def _inner():
        funcs = []
        count = 0
        for ea in idautils.Functions():
            if count >= MAX_FUNCTIONS:
                break
            f = ida_funcs.get_func(ea)
            funcs.append({
                "ea": hex(ea),
                "name": ida_funcs.get_func_name(ea),
                "size": f.size() if f else 0,
            })
            count += 1
        return {"functions": funcs, "total": count, "truncated": count >= MAX_FUNCTIONS}
    return safe_read(_inner)

def get_pseudocode(ea):
    """Decompile function at ea and return pseudocode text."""
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays decompiler is not available"}
    def _inner():
        try:
            cfunc = ida_hexrays.decompile(ea)
        except ida_hexrays.DecompilationFailure as e:
            return {"error": f"Decompilation failed: {str(e)}", "ea": hex(ea)}
        if cfunc is None:
            return {"error": "Decompilation returned None", "ea": hex(ea)}
        lines = []
        sv = cfunc.get_pseudocode()
        for i in range(sv.size()):
            line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)
        # Collect local variable info
        lvars = []
        for lv in cfunc.lvars:
            lvars.append({
                "name": lv.name,
                "type": str(lv.type()),
                "is_arg": lv.is_arg_var,
            })
        func_name = ida_funcs.get_func_name(ea)
        return {
            "ea": hex(ea),
            "name": func_name,
            "pseudocode": "\n".join(lines),
            "local_vars": lvars,
        }
    return safe_read(_inner)

def get_disasm(ea):
    """Get disassembly listing for function at ea."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        lines = []
        current = f.start_ea
        while current < f.end_ea and current != ida_idaapi.BADADDR:
            disasm = idc.generate_disasm_line(current, 0)
            lines.append({"ea": hex(current), "text": disasm})
            current = idc.next_head(current, f.end_ea)
        return {"ea": hex(ea), "name": ida_funcs.get_func_name(ea), "disasm": lines}
    return safe_read(_inner)

def get_xrefs_to(ea):
    """Get all cross-references TO this address."""
    def _inner():
        refs = []
        for xref in idautils.XrefsTo(ea):
            func = ida_funcs.get_func(xref.frm)
            refs.append({
                "from_ea": hex(xref.frm),
                "from_func": ida_funcs.get_func_name(func.start_ea) if func else None,
                "from_func_ea": hex(func.start_ea) if func else None,
                "type": _xref_type_str(xref.type),
            })
        return {"ea": hex(ea), "xrefs_to": refs, "count": len(refs)}
    return safe_read(_inner)

def get_xrefs_from(ea):
    """Get all cross-references FROM this function."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        refs = []
        seen = set()
        current = f.start_ea
        while current < f.end_ea and current != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(current):
                target_func = ida_funcs.get_func(xref.to)
                key = xref.to
                if key not in seen:
                    seen.add(key)
                    refs.append({
                        "to_ea": hex(xref.to),
                        "to_func": ida_funcs.get_func_name(target_func.start_ea) if target_func else ida_name.get_name(xref.to),
                        "to_func_ea": hex(target_func.start_ea) if target_func else None,
                        "type": _xref_type_str(xref.type),
                    })
            current = idc.next_head(current, f.end_ea)
        return {"ea": hex(ea), "xrefs_from": refs, "count": len(refs)}
    return safe_read(_inner)

def get_strings(filter_regex=None):
    """Get all strings in the binary, optionally filtered by regex (compiled for performance)."""
    def _inner():
        import ida_strlist
        ida_strlist.build_strlist()
        sl = ida_strlist.string_info_t()
        result = []
        count = 0
        pattern = re.compile(filter_regex, re.IGNORECASE) if filter_regex else None
        for i in range(ida_strlist.get_strlist_qty()):
            if count >= MAX_STRINGS:
                break
            if ida_strlist.get_strlist_item(sl, i):
                s = ida_bytes.get_strlit_contents(sl.ea, sl.length, getattr(sl, 'strtype', getattr(sl, 'type', 0)))
                if s is not None:
                    try:
                        text = s.decode("utf-8", errors="replace")
                    except:
                        text = str(s)
                    if pattern and not pattern.search(text):
                        continue
                    result.append({"ea": hex(sl.ea), "value": text, "length": sl.length})
                    count += 1
        return {"strings": result, "total": count, "truncated": count >= MAX_STRINGS}
    return safe_read(_inner)

def get_imports():
    """Get all imported functions grouped by module."""
    def _inner():
        modules = {}
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            mod_name = ida_nalt.get_import_module_name(i)
            if not mod_name:
                continue
            entries = []
            def cb(ea, name, ordinal):
                entries.append({
                    "ea": hex(ea) if ea else None,
                    "name": name if name else f"ordinal_{ordinal}",
                    "ordinal": ordinal,
                })
                return True
            ida_nalt.enum_import_names(i, cb)
            modules[mod_name] = entries
        return {"imports": modules, "module_count": nimps}
    return safe_read(_inner)

def get_exports():
    """Get all exported functions."""
    def _inner():
        exports = []
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            exports.append({"ea": hex(ea), "name": name, "ordinal": ordinal})
        return {"exports": exports, "count": len(exports)}
    return safe_read(_inner)

def get_segments():
    """Get all segments."""
    def _inner():
        segs = []
        for seg in idautils.Segments():
            s = ida_segment.getseg(seg)
            segs.append({
                "ea": hex(s.start_ea),
                "end_ea": hex(s.end_ea),
                "name": ida_segment.get_segm_name(s),
                "size": s.size(),
                "perm": f"{'r' if s.perm & ida_segment.SFL_READ else '-'}{'w' if s.perm & ida_segment.SFL_WRITE else '-'}{'x' if s.perm & ida_segment.SFL_EXEC else '-'}",
            })
        return {"segments": segs, "count": len(segs)}
    return safe_read(_inner)

def get_structs():
    """Get all defined structures."""
    def _inner():
        structs = []
        idx = idc.get_first_struc_idx()
        while idx != idc.BADADDR:
            sid = idc.get_struc_by_idx(idx)
            name = idc.get_struc_name(sid)
            size = idc.get_struc_size(sid)
            structs.append({"id": sid, "name": name, "size": size})
            idx = idc.get_next_struc_idx(idx)
        return {"structs": structs, "count": len(structs)}
    return safe_read(_inner)

def get_struct_details(name_or_id):
    """Get struct members with offsets and types."""
    def _inner():
        import ida_struct
        if isinstance(name_or_id, str):
            sid = idc.get_struc_id(name_or_id)
        else:
            sid = name_or_id
        if sid == idc.BADADDR:
            return {"error": f"Structure not found: {name_or_id}"}
        sname = idc.get_struc_name(sid)
        ssize = idc.get_struc_size(sid)
        sptr = ida_struct.get_struc(sid)
        members = []
        if sptr:
            for i in range(sptr.memqty):
                m = sptr.get_member(i)
                mname = ida_struct.get_member_name(m.id)
                moff = m.soff
                msize = ida_struct.get_member_size(m)
                tinfo = ida_typeinf.tinfo_t()
                mtype = "unknown"
                if ida_struct.get_member_tinfo(tinfo, m):
                    mtype = str(tinfo)
                members.append({"name": mname, "offset": hex(moff), "offset_dec": moff, "size": msize, "type": mtype})
        return {"name": sname, "id": sid, "size": ssize, "members": members, "count": len(members)}
    return safe_read(_inner)

def get_enums():
    """Get all enums."""
    def _inner():
        enums = []
        for i in range(idc.get_enum_qty()):
            eid = idc.getn_enum(i)
            enums.append({"id": eid, "name": idc.get_enum_name(eid), "width": idc.get_enum_width(eid), "count": idc.get_enum_size(eid)})
        return {"enums": enums, "count": len(enums)}
    return safe_read(_inner)

def get_enum_details(name_or_id):
    """Get enum members with values."""
    def _inner():
        if isinstance(name_or_id, str):
            eid = idc.get_enum(name_or_id)
        else:
            eid = name_or_id
        if eid == idc.BADADDR:
            return {"error": f"Enum not found: {name_or_id}"}
        ename = idc.get_enum_name(eid)
        members = []
        val = idc.get_first_enum_member(eid)
        while val != idc.BADADDR:
            mid = idc.get_enum_member(eid, val, 0, 0)
            mname = idc.get_enum_member_name(mid) if mid != idc.BADADDR else f"val_{val}"
            members.append({"name": mname, "value": val, "value_hex": hex(val)})
            val = idc.get_next_enum_member(eid, val)
        return {"name": ename, "id": eid, "members": members, "count": len(members)}
    return safe_read(_inner)

def find_func_by_name(name):
    """Find function by name (exact or partial match)."""
    def _inner():
        results = []
        for ea in idautils.Functions():
            fname = ida_funcs.get_func_name(ea)
            if fname and (name in fname or name.lower() in fname.lower()):
                results.append({"ea": hex(ea), "name": fname})
        return {"results": results, "count": len(results)}
    return safe_read(_inner)

def search_bytes(pattern, start_ea=None, max_results=50):
    """Search for byte pattern. Pattern format: 'E8 ?? ?? ?? ?? 48 8B' where ?? = wildcard."""
    def _inner():
        import ida_ida
        import ida_search
        s_ea = start_ea if start_ea else (ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0)
        max_ea = ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else 0xFFFFFFFF
        results = []
        # Convert pattern: "E8 ?? ?? ?? ??" -> IDA binary search format
        ida_pattern = pattern.replace('??', '?').replace('  ', ' ')
        current = s_ea
        for _ in range(max_results):
            found = ida_search.find_binary(current, max_ea, ida_pattern, 16, ida_search.SEARCH_DOWN)
            if found == idc.BADADDR:
                break
            func = ida_funcs.get_func(found)
            results.append({
                "ea": hex(found),
                "func": ida_funcs.get_func_name(func.start_ea) if func else None,
                "func_ea": hex(func.start_ea) if func else None,
            })
            current = found + 1
        return {"pattern": pattern, "results": results, "count": len(results)}
    return safe_read(_inner)

def read_bytes(ea, size):
    """Read raw bytes at address."""
    def _inner():
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            return {"error": f"Cannot read {size} bytes at {hex(ea)}"}
        hex_str = ' '.join(f'{b:02X}' for b in data)
        return {"ea": hex(ea), "size": size, "hex": hex_str}
    return safe_read(_inner)

def get_names(filter_str=None, max_count=1000):
    """List all named items (functions, data labels, etc.)."""
    def _inner():
        names = []
        count = 0
        for ea, name in idautils.Names():
            if count >= max_count:
                break
            if filter_str and filter_str.lower() not in name.lower():
                continue
            names.append({"ea": hex(ea), "name": name})
            count += 1
        return {"names": names, "count": count, "truncated": count >= max_count}
    return safe_read(_inner)

def get_vtable(ea):
    """Read vtable at address — follows consecutive function pointers."""
    def _inner():
        import ida_ida
        is_64 = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else True
        ptr_size = 8 if is_64 else 4
        entries = []
        current = ea
        for i in range(256):  # max 256 virtual methods
            if is_64:
                ptr = ida_bytes.get_qword(current)
            else:
                ptr = ida_bytes.get_dword(current)
            if ptr == 0 or ptr == idc.BADADDR:
                break
            func = ida_funcs.get_func(ptr)
            if not func:
                break
            entries.append({
                "index": i,
                "ea": hex(current),
                "target": hex(ptr),
                "name": ida_funcs.get_func_name(func.start_ea),
            })
            current += ptr_size
        return {"vtable_ea": hex(ea), "entries": entries, "count": len(entries)}
    return safe_read(_inner)

def decompile_batch(ea_list):
    """Decompile multiple functions at once."""
    results = []
    for ea in ea_list:
        results.append(get_pseudocode(ea))
    return {"results": results, "count": len(results)}

def get_func_details(ea):
    """Get detailed function info: calling convention, frame, flags."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        name = ida_funcs.get_func_name(ea)
        flags = f.flags
        flag_names = []
        if flags & ida_funcs.FUNC_NORET: flag_names.append("NORET")
        if flags & ida_funcs.FUNC_LIB: flag_names.append("LIB")
        if flags & ida_funcs.FUNC_THUNK: flag_names.append("THUNK")
        if flags & ida_funcs.FUNC_FRAME: flag_names.append("FRAME")
        tinfo = ida_typeinf.tinfo_t()
        proto = None
        if ida_nalt.get_tinfo(tinfo, ea):
            proto = str(tinfo)
        cmt = idc.get_func_cmt(ea, True) or idc.get_func_cmt(ea, False)
        return {
            "ea": hex(ea), "name": name, "start": hex(f.start_ea), "end": hex(f.end_ea),
            "size": f.size(), "flags": flag_names, "prototype": proto, "comment": cmt,
            "frame_size": idc.get_frame_size(ea),
        }
    return safe_read(_inner)

def save_database():
    """Save the IDA database."""
    def _inner():
        import ida_loader
        ida_loader.save_database(ida_nalt.get_input_file_path() + ".idb", 0)
        return {"success": True, "message": "Database saved"}
    return safe_write(_inner)

def wait_for_analysis():
    """Wait for auto-analysis to complete."""
    def _inner():
        ida_auto.auto_wait()
        return {"success": True, "message": "Analysis complete"}
    return safe_read(_inner)

def set_color(ea, color_rgb):
    """Set background color of an address (RGB as int, e.g. 0x00FF00 for green)."""
    def _inner():
        idc.set_color(ea, idc.CIC_ITEM, color_rgb)
        return {"success": True, "ea": hex(ea), "color": hex(color_rgb)}
    return safe_write(_inner)

def make_function(ea):
    """Create a function at address."""
    def _inner():
        ok = ida_funcs.add_func(ea)
        return {"success": ok, "ea": hex(ea)}
    return safe_write(_inner)

def delete_function(ea):
    """Delete function at address."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        ok = ida_funcs.del_func(f.start_ea)
        return {"success": ok, "ea": hex(ea)}
    return safe_write(_inner)

def add_struct_member_api(struct_name, member_name, offset, size, type_str=None):
    """Add a member to an existing structure."""
    def _inner():
        import ida_struct
        sid = idc.get_struc_id(struct_name)
        if sid == idc.BADADDR:
            return {"error": f"Structure '{struct_name}' not found"}
        sptr = ida_struct.get_struc(sid)
        flag = ida_bytes.FF_BYTE
        if size == 2: flag = ida_bytes.FF_WORD
        elif size == 4: flag = ida_bytes.FF_DWORD
        elif size == 8: flag = ida_bytes.FF_QWORD
        err = ida_struct.add_struc_member(sptr, member_name, offset, flag, None, size)
        if err != 0:
            return {"error": f"Failed to add member (error code {err})", "struct": struct_name}
        if type_str:
            m = ida_struct.get_member_by_name(sptr, member_name)
            if m:
                tinfo = ida_typeinf.tinfo_t()
                if tinfo.get_named_type(None, type_str):
                    ida_struct.set_member_tinfo(sptr, m, 0, tinfo, 0)
        return {"success": True, "struct": struct_name, "member": member_name, "offset": hex(offset)}
    return safe_write(_inner)

def create_enum_api(name, width=4):
    """Create a new enum."""
    def _inner():
        eid = idc.add_enum(-1, name, 0)
        if eid == idc.BADADDR:
            return {"error": f"Failed to create enum '{name}'"}
        return {"success": True, "name": name, "id": eid}
    return safe_write(_inner)

def add_enum_member_api(enum_name, member_name, value):
    """Add a member to an existing enum."""
    def _inner():
        eid = idc.get_enum(enum_name)
        if eid == idc.BADADDR:
            return {"error": f"Enum '{enum_name}' not found"}
        err = idc.add_enum_member(eid, member_name, value)
        if err != 0:
            return {"error": f"Failed to add member (error code {err})"}
        return {"success": True, "enum": enum_name, "member": member_name, "value": value}
    return safe_write(_inner)

# ─── Effector Functions (Write API) ──────────────────────────────────────────

def rename_function(ea, new_name):
    """Rename function at ea."""
    def _inner():
        ok = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
        return {"success": ok, "ea": hex(ea), "new_name": new_name}
    return safe_write(_inner)

def set_function_comment(ea, comment, repeatable=True):
    """Set comment on function."""
    def _inner():
        idc.set_func_cmt(ea, comment, repeatable)
        return {"success": True, "ea": hex(ea), "comment": comment}
    return safe_write(_inner)

def set_address_comment(ea, comment, repeatable=False):
    """Set inline comment at address."""
    def _inner():
        idc.set_cmt(ea, comment, repeatable)
        return {"success": True, "ea": hex(ea), "comment": comment}
    return safe_write(_inner)

def rename_local_var(func_ea, old_name, new_name):
    """Rename a local variable in a decompiled function."""
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays decompiler is not available"}
    def _inner():
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except ida_hexrays.DecompilationFailure as e:
            return {"error": f"Decompilation failed: {str(e)}"}
        if cfunc is None:
            return {"error": "Decompilation returned None"}
        found = False
        for lv in cfunc.lvars:
            if lv.name == old_name:
                lv.name = new_name
                found = True
                break
        if not found:
            available = [lv.name for lv in cfunc.lvars]
            return {"error": f"Variable '{old_name}' not found", "available_vars": available}
        cfunc.save_user_lvars()
        ida_hexrays.clear_cached_cfuncs()
        return {"success": True, "ea": hex(func_ea), "old": old_name, "new": new_name}
    return safe_write(_inner)

def create_struct(c_definition):
    """Create a structure from C syntax."""
    def _inner():
        try:
            count = idc.parse_decls(c_definition, idc.PT_TYP)
        except Exception as e:
            return {"error": f"Parse error: {str(e)}", "input": c_definition}
        if count == 0:
            return {"error": "Failed to parse structure definition (0 types parsed)", "input": c_definition}
        return {"success": True, "types_parsed": count, "definition": c_definition}
    return safe_write(_inner)

def set_func_type(ea, type_str):
    """Apply type/prototype to a function."""
    def _inner():
        result = idc.SetType(ea, type_str)
        if result:
            if HAS_HEXRAYS:
                ida_hexrays.clear_cached_cfuncs()
            return {"success": True, "ea": hex(ea), "type": type_str}
        return {"error": f"Failed to set type '{type_str}' at {hex(ea)}", "ea": hex(ea)}
    return safe_write(_inner)

def execute_batch(mutations):
    """Execute a batch of mutations atomically (best-effort rollback on error)."""
    results = []
    rollback_actions = []

    for i, mut in enumerate(mutations):
        op = mut.get("op")
        try:
            if op == "rename-func":
                ea = int(mut["ea"], 16)
                old_name = safe_read(lambda: ida_funcs.get_func_name(ea))
                result = rename_function(ea, mut["name"])
                if result.get("success"):
                    rollback_actions.append(("rename-func", ea, old_name))
            elif op == "comment-func":
                ea = int(mut["ea"], 16)
                result = set_function_comment(ea, mut["comment"])
            elif op == "comment":
                ea = int(mut["ea"], 16)
                result = set_address_comment(ea, mut["comment"])
            elif op == "rename-var":
                ea = int(mut["ea"], 16)
                result = rename_local_var(ea, mut["old"], mut["new"])
                if result.get("success"):
                    rollback_actions.append(("rename-var", ea, mut["new"], mut["old"]))
            elif op == "create-struct":
                result = create_struct(mut["definition"])
            elif op == "set-type":
                ea = int(mut["ea"], 16)
                result = set_func_type(ea, mut["type"])
            else:
                result = {"error": f"Unknown operation: {op}"}

            if result.get("error"):
                # Attempt rollback
                _do_rollback(rollback_actions)
                return {
                    "status": "error",
                    "failed_at": i,
                    "operation": mut,
                    "error": result["error"],
                    "rolled_back": len(rollback_actions),
                    "completed_before_error": results,
                }
            results.append(result)
        except Exception as e:
            _do_rollback(rollback_actions)
            return {
                "status": "error",
                "failed_at": i,
                "operation": mut,
                "error": str(e),
                "rolled_back": len(rollback_actions),
            }

    return {"status": "ok", "results": results, "count": len(results)}

def _do_rollback(actions):
    """Best-effort rollback of completed mutations."""
    for action in reversed(actions):
        try:
            if action[0] == "rename-func":
                rename_function(action[1], action[2])
            elif action[0] == "rename-var":
                rename_local_var(action[1], action[2], action[3])
        except:
            pass  # Best effort

# ─── Extended Sensor Functions ───────────────────────────────────────────────

def get_call_graph(ea, depth=3):
    """Get recursive call graph from function."""
    visited = set()
    def _walk(addr, d):
        if d <= 0 or addr in visited:
            return None
        visited.add(addr)
        def _inner():
            f = ida_funcs.get_func(addr)
            if not f:
                return None
            name = ida_funcs.get_func_name(addr)
            callees = []
            current = f.start_ea
            seen = set()
            while current < f.end_ea and current != ida_idaapi.BADADDR:
                for xref in idautils.XrefsFrom(current):
                    if xref.type in (16, 17):  # Code_Far_Call, Code_Near_Call
                        tf = ida_funcs.get_func(xref.to)
                        if tf and tf.start_ea not in seen:
                            seen.add(tf.start_ea)
                            callees.append(tf.start_ea)
                current = idc.next_head(current, f.end_ea)
            return {"ea": hex(addr), "name": name, "callees_ea": callees}
        result = safe_read(_inner)
        if not result:
            return None
        children = []
        for callee_ea in result.get("callees_ea", []):
            child = _walk(callee_ea, d - 1)
            if child:
                children.append(child)
        return {"ea": result["ea"], "name": result["name"], "calls": children, "call_count": len(children)}
    root = _walk(ea, depth)
    return root if root else {"error": f"No function at {hex(ea)}"}

def get_basic_blocks(ea):
    """Get basic blocks (CFG) of function."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        import ida_gdl
        fc = ida_gdl.FlowChart(f)
        blocks = []
        for block in fc:
            succs = [{"ea": hex(s.start_ea)} for s in block.succs()]
            preds = [{"ea": hex(p.start_ea)} for p in block.preds()]
            blocks.append({
                "start": hex(block.start_ea),
                "end": hex(block.end_ea),
                "size": block.end_ea - block.start_ea,
                "successors": succs,
                "predecessors": preds,
            })
        return {"ea": hex(ea), "name": ida_funcs.get_func_name(ea), "blocks": blocks, "count": len(blocks)}
    return safe_read(_inner)

def get_switch_info(ea):
    """Get switch/jump table info at address."""
    def _inner():
        import ida_nalt as _nalt
        si = _nalt.get_switch_info(ea)
        if not si:
            return {"error": f"No switch at {hex(ea)}"}
        cases = []
        jt = si.jumps
        ncases = si.get_jtable_size()
        for i in range(ncases):
            target = idc.get_qword(jt + i * 8) if si.get_shift() == 0 else 0
            cases.append({"index": i, "target": hex(target) if target else "indirect"})
        return {"ea": hex(ea), "cases": cases, "count": ncases, "default": hex(si.defjump) if si.defjump != idc.BADADDR else None}
    return safe_read(_inner)

def get_comment_at(ea):
    """Read all comments at address."""
    def _inner():
        regular = idc.get_cmt(ea, False) or ""
        repeatable = idc.get_cmt(ea, True) or ""
        func_cmt = ""
        func_rep = ""
        f = ida_funcs.get_func(ea)
        if f and f.start_ea == ea:
            func_cmt = idc.get_func_cmt(ea, False) or ""
            func_rep = idc.get_func_cmt(ea, True) or ""
        return {
            "ea": hex(ea),
            "comment": regular, "repeatable_comment": repeatable,
            "func_comment": func_cmt, "func_repeatable_comment": func_rep,
        }
    return safe_read(_inner)

def search_text_in_disasm(text, max_results=50):
    """Search for text in disassembly listings."""
    def _inner():
        import ida_ida, ida_search
        min_ea = ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0
        max_ea = ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else 0xFFFFFFFF
        results = []
        current = min_ea
        for _ in range(max_results):
            found = ida_search.find_text(current, 0, 0, text, ida_search.SEARCH_DOWN)
            if found == idc.BADADDR:
                break
            disasm = idc.generate_disasm_line(found, 0)
            func = ida_funcs.get_func(found)
            results.append({
                "ea": hex(found),
                "disasm": disasm,
                "func": ida_funcs.get_func_name(func.start_ea) if func else None,
            })
            current = idc.next_head(found, max_ea)
            if current == idc.BADADDR:
                break
        return {"text": text, "results": results, "count": len(results)}
    return safe_read(_inner)

def get_global_vars(max_count=500):
    """Get global variables (named data items)."""
    def _inner():
        gvars = []
        count = 0
        for ea, name in idautils.Names():
            if count >= max_count:
                break
            f = ida_funcs.get_func(ea)
            if f:
                continue  # skip function names
            seg = ida_segment.getseg(ea)
            if seg:
                sname = ida_segment.get_segm_name(seg)
                if sname in ('.text', '.plt', '.init', '.fini'):
                    continue
            size = idc.get_item_size(ea)
            gvars.append({"ea": hex(ea), "name": name, "size": size})
            count += 1
        return {"global_vars": gvars, "count": count, "truncated": count >= max_count}
    return safe_read(_inner)

def get_stack_vars(ea):
    """Get stack variables of function."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        import ida_frame, ida_struct
        frame = ida_frame.get_frame(ea)
        if not frame:
            return {"ea": hex(ea), "stack_vars": [], "count": 0}
        svars = []
        for i in range(frame.memqty):
            m = frame.get_member(i)
            mname = ida_struct.get_member_name(m.id)
            moff = m.soff
            msize = ida_struct.get_member_size(m)
            svars.append({"name": mname, "offset": hex(moff), "offset_dec": moff, "size": msize})
        return {"ea": hex(ea), "name": ida_funcs.get_func_name(ea), "stack_vars": svars, "count": len(svars)}
    return safe_read(_inner)

def get_func_args(ea):
    """Get function argument types from Hex-Rays decompiler."""
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays decompiler not available"}
    def _inner():
        try:
            cfunc = ida_hexrays.decompile(ea)
        except:
            return {"error": f"Cannot decompile {hex(ea)}"}
        if not cfunc:
            return {"error": "Decompilation returned None"}
        args = []
        for lv in cfunc.lvars:
            if lv.is_arg_var:
                args.append({"name": lv.name, "type": str(lv.type()), "index": len(args)})
        return {"ea": hex(ea), "name": ida_funcs.get_func_name(ea), "args": args, "count": len(args)}
    return safe_read(_inner)

def get_bookmarks():
    """Get all IDA bookmarks."""
    def _inner():
        bookmarks = []
        for i in range(1024):
            ea = idc.get_bookmark(i)
            if ea is None or ea == idc.BADADDR:
                continue
            desc = idc.get_bookmark_desc(i)
            bookmarks.append({"slot": i, "ea": hex(ea), "description": desc or ""})
        return {"bookmarks": bookmarks, "count": len(bookmarks)}
    return safe_read(_inner)

def get_patches():
    """List all patched bytes."""
    def _inner():
        patches = []
        def cb(ea, fpos, orig, patched):
            patches.append({
                "ea": hex(ea), "file_offset": fpos,
                "original": orig, "patched": patched,
            })
            return 0
        ida_bytes.visit_patched_bytes(0, idc.BADADDR, cb)
        return {"patches": patches, "count": len(patches)}
    return safe_read(_inner)

def get_function_gaps():
    """Find gaps between functions (potential undiscovered code)."""
    def _inner():
        gaps = []
        prev_end = None
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            if not f:
                continue
            if prev_end is not None and ea > prev_end:
                gap_size = ea - prev_end
                if gap_size >= 4:  # minimum meaningful gap
                    gaps.append({"start": hex(prev_end), "end": hex(ea), "size": gap_size})
            prev_end = f.end_ea
        return {"gaps": gaps, "count": len(gaps)}
    return safe_read(_inner)

# ─── Extended Effector Functions ─────────────────────────────────────────────

def patch_bytes_at(ea, hex_bytes):
    """Patch bytes at address. hex_bytes: '90 90 90' or '909090'."""
    def _inner():
        clean = hex_bytes.replace(' ', '')
        data = bytes.fromhex(clean)
        for i, b in enumerate(data):
            ida_bytes.patch_byte(ea + i, b)
        return {"success": True, "ea": hex(ea), "size": len(data), "patched": hex_bytes}
    return safe_write(_inner)

def make_code_at(ea, size=0):
    """Convert bytes to code at address."""
    def _inner():
        if size > 0:
            idc.del_items(ea, 0, size)
        ok = idc.create_insn(ea)
        return {"success": ok != 0, "ea": hex(ea)}
    return safe_write(_inner)

def make_data_at(ea, size, dtype=None):
    """Convert to data at address."""
    def _inner():
        flag = ida_bytes.FF_BYTE
        if size == 2: flag = ida_bytes.FF_WORD
        elif size == 4: flag = ida_bytes.FF_DWORD
        elif size == 8: flag = ida_bytes.FF_QWORD
        idc.del_items(ea, 0, size)
        ok = ida_bytes.create_data(ea, flag, size, 0)
        return {"success": ok, "ea": hex(ea), "size": size}
    return safe_write(_inner)

def undefine_range(ea, size):
    """Undefine bytes at address range."""
    def _inner():
        idc.del_items(ea, 0, size)
        return {"success": True, "ea": hex(ea), "size": size}
    return safe_write(_inner)

def set_name_at(ea, name):
    """Set name at any address (not just functions)."""
    def _inner():
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_FORCE)
        return {"success": ok, "ea": hex(ea), "name": name}
    return safe_write(_inner)

def apply_struct_at(ea, struct_name):
    """Apply structure type at address."""
    def _inner():
        sid = idc.get_struc_id(struct_name)
        if sid == idc.BADADDR:
            return {"error": f"Structure '{struct_name}' not found"}
        size = idc.get_struc_size(sid)
        idc.del_items(ea, 0, size)
        ok = idc.create_struct(ea, size, struct_name)
        return {"success": ok, "ea": hex(ea), "struct": struct_name, "size": size}
    return safe_write(_inner)

def delete_struct_api(name):
    """Delete a structure."""
    def _inner():
        import ida_struct
        sid = idc.get_struc_id(name)
        if sid == idc.BADADDR:
            return {"error": f"Structure '{name}' not found"}
        sptr = ida_struct.get_struc(sid)
        ok = ida_struct.del_struc(sptr)
        return {"success": ok, "name": name}
    return safe_write(_inner)

def delete_enum_api(name):
    """Delete an enum."""
    def _inner():
        eid = idc.get_enum(name)
        if eid == idc.BADADDR:
            return {"error": f"Enum '{name}' not found"}
        idc.del_enum(eid)
        return {"success": True, "name": name}
    return safe_write(_inner)

def add_bookmark_api(ea, description, slot=-1):
    """Add a bookmark."""
    def _inner():
        if slot < 0:
            # Find first free slot
            for s in range(1024):
                if idc.get_bookmark(s) is None or idc.get_bookmark(s) == idc.BADADDR:
                    idc.put_bookmark(ea, 0, 0, 0, s, description)
                    return {"success": True, "ea": hex(ea), "slot": s, "description": description}
            return {"error": "No free bookmark slots"}
        idc.put_bookmark(ea, 0, 0, 0, slot, description)
        return {"success": True, "ea": hex(ea), "slot": slot, "description": description}
    return safe_write(_inner)

def delete_bookmark_api(slot):
    """Delete a bookmark."""
    def _inner():
        idc.put_bookmark(0, 0, 0, 0, slot, "")
        return {"success": True, "slot": slot}
    return safe_write(_inner)

def import_c_header(filepath):
    """Import/parse a C header file securely with path validation."""
    def _inner():
        try:
            abs_path = os.path.realpath(filepath)
        except Exception:
            abs_path = os.path.abspath(filepath)

        # Security: Prevent reading sensitive system files and UNC bypasses
        blocked_prefixes = (
            '/etc/', '/proc/', '/sys/', '/var/log/',  # Unix
            'C:\\Windows\\', 'C:\\Users\\All Users\\', # Windows
            '\\\\', # UNC path bypass
        )
        if any(abs_path.lower().startswith(prefix.lower()) for prefix in blocked_prefixes):
            return {"success": False, "error": "Access to this path is restricted for security reasons."}

        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return {"success": False, "error": f"File not found: {filepath}"}

        with open(abs_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        errors = idc.parse_decls(content, idc.PT_FILE | idc.PT_TYP)
        return {"success": errors > 0, "types_parsed": errors, "file": abs_path}
    return safe_write(_inner)

def reanalyze_range(start_ea, end_ea):
    """Force reanalysis of address range."""
    def _inner():
        idc.plan_and_wait(start_ea, end_ea)
        return {"success": True, "start": hex(start_ea), "end": hex(end_ea)}
    return safe_write(_inner)

def execute_dynamic_python(script_code):
    """Execute arbitrary Python script dynamically within IDA."""
    def _inner():
        import io
        import sys
        import traceback
        import idaapi
        import idc
        import idautils
        import ida_funcs
        import ida_bytes
        import ida_typeinf
        import ida_name
        
        # Setup local variables with a 'result' dict
        local_vars = {
            "idaapi": idaapi,
            "idc": idc,
            "idautils": idautils,
            "ida_funcs": ida_funcs,
            "ida_bytes": ida_bytes,
            "ida_typeinf": ida_typeinf,
            "ida_name": ida_name,
            "result": {}
        }
        
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        redir_out = io.StringIO()
        redir_err = io.StringIO()
        sys.stdout = redir_out
        sys.stderr = redir_err
        
        success = True
        error_msg = ""
        try:
            if hasattr(ida_auto, "auto_mark_range"):
                try: ida_auto.auto_mark_range(0, ida_idaapi.BADADDR, ida_auto.AU_USED)
                except Exception: pass
            exec(script_code, globals(), local_vars)
        except Exception:
            success = False
            error_msg = traceback.format_exc()
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            
        return {
            "success": success,
            "stdout": redir_out.getvalue(),
            "stderr": redir_err.getvalue(),
            "error": error_msg,
            "result": local_vars.get("result", {})
        }
    return safe_write(_inner)

# ─── Hex-Rays Advanced API ───────────────────────────────────────────────────

def get_ctree_json(ea):
    if not HAS_HEXRAYS: return {"error": "Hex-Rays not available"}
    def _inner():
        try: cfunc = ida_hexrays.decompile(ea)
        except: return {"error": f"Decompile failed at {hex(ea)}"}
        if not cfunc: return {"error": "Decompilation returned None"}
        items = []
        class Vis(ida_hexrays.ctree_visitor_t):
            def __init__(self): ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
            def visit_insn(self, ins):
                items.append({"kind":"insn","op":ins.opname,"ea":hex(ins.ea) if ins.ea!=ida_idaapi.BADADDR else None})
                return 0
            def visit_expr(self, expr):
                d = {"kind":"expr","op":expr.opname,"ea":hex(expr.ea) if expr.ea!=ida_idaapi.BADADDR else None,"dtype":str(expr.type)}
                if expr.op == ida_hexrays.cot_num: d["value"] = expr.numval()
                elif expr.op == ida_hexrays.cot_str: d["string"] = expr.string
                elif expr.op == ida_hexrays.cot_obj:
                    d["obj_ea"] = hex(expr.obj_ea); d["obj_name"] = ida_name.get_name(expr.obj_ea)
                elif expr.op == ida_hexrays.cot_var:
                    lv = cfunc.lvars[expr.v.idx]; d["var_name"] = lv.name; d["var_type"] = str(lv.type())
                elif expr.op == ida_hexrays.cot_call and expr.x and expr.x.op == ida_hexrays.cot_obj:
                    d["call_target"] = hex(expr.x.obj_ea); d["call_name"] = ida_name.get_name(expr.x.obj_ea)
                items.append(d); return 0
        Vis().apply_to(cfunc.body, None)
        return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"ctree":items,"count":len(items)}
    return safe_read(_inner)

def set_lvar_type_api(func_ea, var_name, type_str):
    if not HAS_HEXRAYS: return {"error": "Hex-Rays not available"}
    def _inner():
        try: cfunc = ida_hexrays.decompile(func_ea)
        except: return {"error": f"Decompile failed at {hex(func_ea)}"}
        if not cfunc: return {"error": "None"}
        for lv in cfunc.lvars:
            if lv.name == var_name:
                tif = ida_typeinf.tinfo_t()
                if ida_typeinf.parse_decl(tif, None, f"{type_str};", ida_typeinf.PT_SIL):
                    lv.set_lvar_type(tif); cfunc.save_user_lvars(); ida_hexrays.clear_cached_cfuncs()
                    return {"success":True,"ea":hex(func_ea),"var":var_name,"type":type_str}
                return {"error":f"Cannot parse type: {type_str}"}
        return {"error":f"Var '{var_name}' not found","available":[v.name for v in cfunc.lvars]}
    return safe_write(_inner)

def get_lvar_map(ea):
    if not HAS_HEXRAYS: return {"error": "Hex-Rays not available"}
    def _inner():
        try: cfunc = ida_hexrays.decompile(ea)
        except: return {"error": f"Decompile failed at {hex(ea)}"}
        if not cfunc: return {"error": "None"}
        lvars = []
        for i, lv in enumerate(cfunc.lvars):
            lvars.append({"idx":i,"name":lv.name,"type":str(lv.type()),"is_arg":lv.is_arg_var,
                          "is_stk":lv.is_stk_var(),"is_reg":lv.is_reg_var(),"width":lv.width})
        return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"lvars":lvars,"count":len(lvars)}
    return safe_read(_inner)

def set_lvar_comment_api(func_ea, var_name, cmt):
    if not HAS_HEXRAYS: return {"error": "Hex-Rays not available"}
    def _inner():
        try: cfunc = ida_hexrays.decompile(func_ea)
        except: return {"error": "Decompile failed"}
        if not cfunc: return {"error": "None"}
        for lv in cfunc.lvars:
            if lv.name == var_name:
                lv.cmt = cmt; cfunc.save_user_lvars()
                return {"success":True,"ea":hex(func_ea),"var":var_name,"comment":cmt}
        return {"error":f"Var '{var_name}' not found"}
    return safe_write(_inner)

# ─── Microcode API ───────────────────────────────────────────────────────────

def get_microcode(ea, maturity=7):
    if not HAS_HEXRAYS: return {"error": "Hex-Rays not available"}
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f: return {"error": f"No function at {hex(ea)}"}
        try:
            mbr = ida_hexrays.mba_ranges_t()
            mbr.ranges.push_back(ida_range.range_t(f.start_ea, f.end_ea))
            hf = ida_hexrays.hexrays_failure_t()
            ml = ida_hexrays.mlist_t()
            mba = ida_hexrays.gen_microcode(mbr, hf, ml, ida_hexrays.DECOMP_NO_WAIT, maturity)
            if not mba: return {"error": f"Microcode gen failed: {hf.desc()}"}
            lines = []
            for i in range(mba.qty):
                blk = mba.get_mblock(i)
                insn = blk.head
                while insn:
                    lines.append({"block":i,"ea":hex(insn.ea),"text":insn.dstr()})
                    insn = insn.next
            return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"maturity":maturity,"microcode":lines,"count":len(lines)}
        except Exception as e:
            return {"error": str(e)}
    return safe_read(_inner)

# ─── Type System Extended ────────────────────────────────────────────────────

def get_local_types():
    def _inner():
        til = ida_typeinf.get_idati()
        types = []
        for ordinal in range(1, ida_typeinf.get_ordinal_qty(til) + 1):
            name = ida_typeinf.get_numbered_type_name(til, ordinal)
            if name:
                tif = ida_typeinf.tinfo_t()
                if tif.get_numbered_type(til, ordinal):
                    types.append({"ordinal":ordinal,"name":name,"type":str(tif),"size":tif.get_size()})
        return {"types":types,"count":len(types)}
    return safe_read(_inner)

def get_type_by_name(name):
    def _inner():
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(ida_typeinf.get_idati(), name):
            details = {"name":name,"type":str(tif),"size":tif.get_size(),"is_struct":tif.is_struct(),
                       "is_union":tif.is_union(),"is_enum":tif.is_enum(),"is_ptr":tif.is_ptr(),
                       "is_func":tif.is_func(),"is_array":tif.is_array()}
            if tif.is_struct() or tif.is_union():
                udt = ida_typeinf.udt_type_data_t()
                if tif.get_udt_details(udt):
                    members = []
                    for m in udt:
                        members.append({"name":m.name,"offset":m.offset//8,"size":m.size//8,"type":str(m.type)})
                    details["members"] = members
            return details
        return {"error":f"Type '{name}' not found"}
    return safe_read(_inner)

def create_type_from_c(c_decl):
    def _inner():
        count = idc.parse_decls(c_decl, idc.PT_TYP)
        return {"success":count>0,"types_parsed":count,"definition":c_decl}
    return safe_write(_inner)

def delete_local_type(name):
    def _inner():
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal == 0: return {"error":f"Type '{name}' not found"}
        ok = ida_typeinf.del_numbered_type(til, ordinal)
        return {"success":ok,"name":name,"ordinal":ordinal}
    return safe_write(_inner)

def get_type_libraries():
    def _inner():
        tils = []
        til = ida_typeinf.get_idati()
        tils.append({"name":"local","desc":"Local type library","ntypes":ida_typeinf.get_ordinal_qty(til)})
        for i in range(ida_typeinf.get_idati().nbases):
            base = ida_typeinf.get_idati().base(i)
            tils.append({"name":base.name,"desc":base.desc,"ntypes":ida_typeinf.get_ordinal_qty(base)})
        return {"libraries":tils,"count":len(tils)}
    return safe_read(_inner)

def load_til_api(name):
    def _inner():
        result = ida_typeinf.add_til(name, ida_typeinf.ADDTIL_DEFAULT)
        return {"success":result!=0,"name":name}
    return safe_write(_inner)

# ─── Segments Extended ───────────────────────────────────────────────────────

def create_segment_api(start, end, name, sclass="DATA", bitness=2):
    def _inner():
        seg = ida_segment.segment_t()
        seg.start_ea = start; seg.end_ea = end; seg.bitness = bitness
        ok = ida_segment.add_segm_ex(seg, name, sclass, ida_segment.ADDSEG_NOSREG)
        return {"success":ok!=0,"start":hex(start),"end":hex(end),"name":name}
    return safe_write(_inner)

def delete_segment_api(ea):
    def _inner():
        ok = ida_segment.del_segm(ea, ida_segment.SEGMOD_KILL)
        return {"success":ok,"ea":hex(ea)}
    return safe_write(_inner)

def set_segment_attrs_api(ea, attrs):
    def _inner():
        seg = ida_segment.getseg(ea)
        if not seg: return {"error":f"No segment at {hex(ea)}"}
        if "name" in attrs: ida_segment.set_segm_name(seg, attrs["name"])
        if "class" in attrs: ida_segment.set_segm_class(seg, attrs["class"])
        if "perm" in attrs:
            p = attrs["perm"]; seg.perm = 0
            if 'r' in p: seg.perm |= ida_segment.SFL_READ
            if 'w' in p: seg.perm |= ida_segment.SFL_WRITE
            if 'x' in p: seg.perm |= ida_segment.SFL_EXEC
            seg.update()
        return {"success":True,"ea":hex(ea)}
    return safe_write(_inner)

# ─── Instruction-Level API ───────────────────────────────────────────────────

def get_instruction(ea):
    def _inner():
        import ida_ua
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz == 0: return {"error":f"Cannot decode at {hex(ea)}"}
        ops = []
        for i in range(8):
            op = insn.ops[i]
            if op.type == 0: break
            od = {"n":i,"type":op.type,"dtype":op.dtype,"value":op.value,"addr":hex(op.addr) if op.addr else None}
            if op.type == 1: od["reg"] = op.reg
            elif op.type == 5: od["imm"] = op.value
            ops.append(od)
        return {"ea":hex(ea),"mnem":idc.print_insn_mnem(ea),"size":sz,"disasm":idc.generate_disasm_line(ea,0),"operands":ops}
    return safe_read(_inner)

def get_operands(ea):
    def _inner():
        ops = []
        for i in range(8):
            t = idc.get_operand_type(ea, i)
            if t == 0 and i > 0: break
            ops.append({"n":i,"type":t,"value":idc.get_operand_value(ea,i),"text":idc.print_operand(ea,i)})
        return {"ea":hex(ea),"operands":ops,"count":len(ops)}
    return safe_read(_inner)

# ─── Cross-References Extended ───────────────────────────────────────────────

def get_data_xrefs(ea):
    def _inner():
        refs = []
        for xref in idautils.XrefsTo(ea):
            if xref.type < 16:
                func = ida_funcs.get_func(xref.frm)
                refs.append({"from":hex(xref.frm),"type":_xref_type_str(xref.type),
                             "func":ida_funcs.get_func_name(func.start_ea) if func else None})
        return {"ea":hex(ea),"data_xrefs":refs,"count":len(refs)}
    return safe_read(_inner)

def get_code_xrefs(ea):
    def _inner():
        refs = []
        for xref in idautils.XrefsTo(ea):
            if xref.type >= 16:
                func = ida_funcs.get_func(xref.frm)
                refs.append({"from":hex(xref.frm),"type":_xref_type_str(xref.type),
                             "func":ida_funcs.get_func_name(func.start_ea) if func else None})
        return {"ea":hex(ea),"code_xrefs":refs,"count":len(refs)}
    return safe_read(_inner)

# ─── Debugger API ────────────────────────────────────────────────────────────

def _dbg_available():
    try:
        import ida_dbg  # noqa: F401
        return True
    except: return False

def dbg_start_process(path=None, args="", sdir=None):
    def _inner():
        import ida_dbg
        p = path if path else ida_nalt.get_input_file_path()
        ok = ida_dbg.start_process(p, args, sdir or "")
        return {"success":ok==1,"path":p}
    return safe_write(_inner)

def dbg_attach_process(pid):
    def _inner():
        import ida_dbg
        ok = ida_dbg.attach_process(pid, -1)
        return {"success":ok==1,"pid":pid}
    return safe_write(_inner)

def dbg_detach():
    def _inner():
        import ida_dbg
        ok = ida_dbg.detach_process()
        return {"success":ok}
    return safe_write(_inner)

def dbg_set_bp(ea, is_hw=False):
    def _inner():
        import ida_dbg
        if is_hw: ok = ida_dbg.add_bpt(ea, 1, ida_dbg.BPT_DEFAULT)
        else: ok = ida_dbg.add_bpt(ea)
        return {"success":ok,"ea":hex(ea),"hardware":is_hw}
    return safe_write(_inner)

def dbg_del_bp(ea):
    def _inner():
        import ida_dbg
        ok = ida_dbg.del_bpt(ea)
        return {"success":ok,"ea":hex(ea)}
    return safe_write(_inner)

def dbg_list_bps():
    def _inner():
        import ida_dbg
        bps = []
        for i in range(ida_dbg.get_bpt_qty()):
            bp = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(i, bp):
                bps.append({"ea":hex(bp.ea),"size":bp.size,"type":bp.type,"enabled":bool(bp.flags & ida_dbg.BPT_ENABLED)})
        return {"breakpoints":bps,"count":len(bps)}
    return safe_read(_inner)

def dbg_step_into_api():
    def _inner():
        import ida_dbg
        ok = ida_dbg.step_into()
        return {"success":ok}
    return safe_write(_inner)

def dbg_step_over_api():
    def _inner():
        import ida_dbg
        ok = ida_dbg.step_over()
        return {"success":ok}
    return safe_write(_inner)

def dbg_continue_api():
    def _inner():
        import ida_dbg
        ok = ida_dbg.continue_process()
        return {"success":ok}
    return safe_write(_inner)

def dbg_pause_api():
    def _inner():
        import ida_dbg
        ok = ida_dbg.suspend_process()
        return {"success":ok}
    return safe_write(_inner)

def dbg_get_regs():
    def _inner():
        import ida_dbg, ida_idd
        regs = {}
        rv = ida_idd.regval_t()
        for name in ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip","eflags",
                      "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"]:
            try:
                if ida_dbg.get_reg_val(name, rv): regs[name] = hex(rv.ival)
            except: pass
        return {"registers":regs}
    return safe_read(_inner)

def dbg_read_mem(ea, size):
    def _inner():
        import ida_dbg
        data = ida_dbg.dbg_read_memory(ea, size)
        if not data: return {"error":f"Cannot read {size} bytes at {hex(ea)}"}
        return {"ea":hex(ea),"size":size,"hex":' '.join(f'{b:02X}' for b in data)}
    return safe_read(_inner)

def dbg_write_mem(ea, hex_bytes):
    def _inner():
        import ida_dbg
        data = bytes.fromhex(hex_bytes.replace(' ',''))
        ok = ida_dbg.dbg_write_memory(ea, data)
        return {"success":ok>0,"ea":hex(ea),"size":len(data)}
    return safe_write(_inner)

def dbg_get_threads():
    def _inner():
        import ida_dbg
        threads = []
        for i in range(ida_dbg.get_thread_qty()):
            tid = ida_dbg.getn_thread(i)
            name = ida_dbg.get_thread_name(tid)
            threads.append({"tid":tid,"name":name or ""})
        return {"threads":threads,"count":len(threads)}
    return safe_read(_inner)

def dbg_get_stack():
    def _inner():
        import ida_dbg, ida_idd  # noqa: F401
        trace = ida_dbg.call_stack_t()
        ok = ida_dbg.get_call_stack(trace)
        if not ok: return {"error":"Cannot get call stack"}
        frames = []
        for i in range(len(trace)):
            f = trace[i]
            frames.append({"caller":hex(f.callea),"func":hex(f.funcea),"fp":hex(f.fp)})
        return {"stack":frames,"count":len(frames)}
    return safe_read(_inner)

# ─── Utility API ─────────────────────────────────────────────────────────────

def get_callers(ea):
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f: return {"error":f"No function at {hex(ea)}"}
        callers = []
        seen = set()
        for xref in idautils.XrefsTo(f.start_ea):
            if xref.type in (16,17):
                cf = ida_funcs.get_func(xref.frm)
                if cf and cf.start_ea not in seen:
                    seen.add(cf.start_ea)
                    callers.append({"ea":hex(cf.start_ea),"name":ida_funcs.get_func_name(cf.start_ea),"call_site":hex(xref.frm)})
        return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"callers":callers,"count":len(callers)}
    return safe_read(_inner)

def get_callees(ea):
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f: return {"error":f"No function at {hex(ea)}"}
        callees = []; seen = set(); cur = f.start_ea
        while cur < f.end_ea and cur != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(cur):
                if xref.type in (16,17):
                    tf = ida_funcs.get_func(xref.to)
                    if tf and tf.start_ea not in seen:
                        seen.add(tf.start_ea)
                        callees.append({"ea":hex(tf.start_ea),"name":ida_funcs.get_func_name(tf.start_ea),"call_site":hex(cur)})
            cur = idc.next_head(cur, f.end_ea)
        return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"callees":callees,"count":len(callees)}
    return safe_read(_inner)

def get_strings_used(ea):
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f: return {"error":f"No function at {hex(ea)}"}
        strings = []; cur = f.start_ea
        while cur < f.end_ea and cur != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(cur):
                s = ida_bytes.get_strlit_contents(xref.to, -1, 0)
                if s:
                    try: text = s.decode("utf-8", errors="replace")
                    except: text = str(s)
                    strings.append({"ea":hex(xref.to),"ref_from":hex(cur),"value":text})
            cur = idc.next_head(cur, f.end_ea)
        return {"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"strings":strings,"count":len(strings)}
    return safe_read(_inner)

def undo_action():
    def _inner():
        ok = ida_kernwin.process_ui_action("Undo")
        return {"success":ok}
    return safe_write(_inner)

def redo_action():
    def _inner():
        ok = ida_kernwin.process_ui_action("Redo")
        return {"success":ok}
    return safe_write(_inner)

def get_cursor_pos():
    def _inner():
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        return {"ea":hex(ea),"func":ida_funcs.get_func_name(func.start_ea) if func else None,
                "func_ea":hex(func.start_ea) if func else None}
    return safe_read(_inner)

def navigate_to(ea):
    def _inner():
        ok = ida_kernwin.jumpto(ea)
        return {"success":ok,"ea":hex(ea)}
    return safe_write(_inner)

def get_selection_range():
    def _inner():
        ok, s, e = ida_kernwin.read_range_selection(None)
        if not ok: return {"selected":False}
        return {"selected":True,"start":hex(s),"end":hex(e),"size":e-s}
    return safe_read(_inner)

def get_functions_paginated(offset=0, limit=500):
    def _inner():
        funcs = []; count = 0; skip = 0
        for ea in idautils.Functions():
            if skip < offset: skip += 1; continue
            if count >= limit: break
            f = ida_funcs.get_func(ea)
            funcs.append({"ea":hex(ea),"name":ida_funcs.get_func_name(ea),"size":f.size() if f else 0})
            count += 1
        total = sum(1 for _ in idautils.Functions())
        return {"functions":funcs,"offset":offset,"limit":limit,"returned":count,"total":total}
    return safe_read(_inner)

# ─── HTTP Request Handler ────────────────────────────────────────────────────

def parse_ea(ea_str):
    """Parse hex address string to integer."""
    ea_str = ea_str.strip()
    if ea_str.startswith("0x") or ea_str.startswith("0X"):
        return int(ea_str, 16)
    try:
        return int(ea_str, 16)
    except ValueError:
        return int(ea_str)


def get_analyze_context(ea):
    def _inner():
        ctx = {}
        try: ctx["pseudocode"] = get_pseudocode(ea)().get("pseudocode")
        except Exception: ctx["pseudocode"] = None
        try: ctx["lvars"] = get_lvar_map(ea)().get("lvars", {})
        except Exception: ctx["lvars"] = {}
        try: ctx["callers"] = get_callers(ea)().get("callers", [])
        except Exception: ctx["callers"] = []
        try: ctx["callees"] = get_callees(ea)().get("callees", [])
        except Exception: ctx["callees"] = []
        try: ctx["strings_used"] = get_strings_used(ea)().get("strings", [])
        except Exception: ctx["strings_used"] = []
        try: ctx["xrefs_to"] = get_xrefs_to(ea)().get("xrefs", [])
        except Exception: ctx["xrefs_to"] = []
        try: ctx["basic_blocks"] = get_basic_blocks(ea)().get("blocks", [])
        except Exception: ctx["basic_blocks"] = []
        return ctx
    return safe_read(_inner)


# --- Micro Router ---
import queue
sse_queue = queue.Queue()

GET_ROUTES = []
POST_ROUTES = []

def get_route(pattern):
    def decorator(func):
        GET_ROUTES.append((re.compile('^' + pattern + '$'), func))
        return func
    return decorator

def post_route(pattern):
    def decorator(func):
        POST_ROUTES.append((re.compile('^' + pattern + '$'), func))
        return func
    return decorator

@get_route(r'/api/macro/analyze_context')
def route_macro_analyze_context(self, match, params):
    ea = parse_ea(params.get("ea", ["0"])[0])
    self.send_json(get_analyze_context(ea)())

class AntigravityUIHooks(ida_kernwin.UI_Hooks):
    def screen_ea_changed(self, ea, prev_ea):
        sse_queue.put({"event": "cursor_changed", "ea": hex(ea), "prev_ea": hex(prev_ea)})
        return 0

try:
    import ida_dbg
    class AntigravityDbgHooks(ida_dbg.DbgHooks):
        def dbg_bpt(self, tid, ea):
            sse_queue.put({"event": "breakpoint_hit", "tid": tid, "ea": hex(ea)})
            return 0
    dbg_hooks = AntigravityDbgHooks()
except Exception:
    dbg_hooks = None

ui_hooks = AntigravityUIHooks()

@get_route(r'/api/info')
def route_do_get_0(self, match, params):
    self.send_json(get_info())

@get_route(r'/api/functions')
def route_do_get_1(self, match, params):
    self.send_json(get_functions())

@get_route(r'/api/strings')
def route_do_get_2(self, match, params):
    filt = params.get('filter', [None])[0]
    self.send_json(get_strings(filt))

@get_route(r'/api/imports')
def route_do_get_3(self, match, params):
    self.send_json(get_imports())

@get_route(r'/api/exports')
def route_do_get_4(self, match, params):
    self.send_json(get_exports())

@get_route(r'/api/segments')
def route_do_get_5(self, match, params):
    self.send_json(get_segments())

@get_route(r'/api/structs')
def route_do_get_6(self, match, params):
    self.send_json(get_structs())

@get_route(r'/api/enums')
def route_do_get_7(self, match, params):
    self.send_json(get_enums())

@get_route(r'/api/names')
def route_do_get_8(self, match, params):
    filt = params.get('filter', [None])[0]
    self.send_json(get_names(filt))

@get_route(r'/api/wait-analysis')
def route_do_get_9(self, match, params):
    self.send_json(wait_for_analysis())

@get_route(r'/api/global-vars')
def route_do_get_10(self, match, params):
    self.send_json(get_global_vars())

@get_route(r'/api/bookmarks')
def route_do_get_11(self, match, params):
    self.send_json(get_bookmarks())

@get_route(r'/api/patches')
def route_do_get_12(self, match, params):
    self.send_json(get_patches())

@get_route(r'/api/gaps')
def route_do_get_13(self, match, params):
    self.send_json(get_function_gaps())

@get_route(r'/api/ping')
def route_do_get_14(self, match, params):
    self.send_json({'status': 'ok', 'server': 'antigravity-ida-bridge', 'version': '4.0'})

@get_route(r'/api/struct/.*')
def route_do_get_15(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_struct_details(parts[3]))
    else:
        self.send_error_json('Use /api/struct/<name>')

@get_route(r'/api/enum/.*')
def route_do_get_16(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_enum_details(parts[3]))
    else:
        self.send_error_json('Use /api/enum/<name>')

@get_route(r'/api/vtable/.*')
def route_do_get_17(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_vtable(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/vtable/<ea>')

@get_route(r'/api/bytes/.*')
def route_do_get_18(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 5:
        self.send_json(read_bytes(parse_ea(parts[3]), int(parts[4])))
    else:
        self.send_error_json('Use /api/bytes/<ea>/<size>')

@get_route(r'/api/search-func/.*')
def route_do_get_19(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) >= 4:
        self.send_json(find_func_by_name(parts[3]))
    else:
        self.send_error_json('Use /api/search-func/<name>')

@get_route(r'/api/search-bytes/.*')
def route_do_get_20(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) >= 4:
        self.send_json(search_bytes(parts[3]))
    else:
        self.send_error_json('Use /api/search-bytes/<pattern>')

@get_route(r'/api/function/.*')
def route_do_get_21(self, match, params):
    parts = match.string.split('/')
    if len(parts) < 5:
        self.send_error_json('Invalid path. Use /api/function/<ea>/<action>')
        return
    ea = parse_ea(parts[3])
    action = parts[4]
    if action == 'pseudocode':
        self.send_json(get_pseudocode(ea))
    elif action == 'disasm':
        self.send_json(get_disasm(ea))
    elif action == 'xrefs-to':
        self.send_json(get_xrefs_to(ea))
    elif action == 'xrefs-from':
        self.send_json(get_xrefs_from(ea))
    elif action == 'details':
        self.send_json(get_func_details(ea))
    elif action == 'call-graph':
        depth = int(params.get('depth', [3])[0])
        self.send_json(get_call_graph(ea, depth))
    elif action == 'basic-blocks':
        self.send_json(get_basic_blocks(ea))
    elif action == 'stack-vars':
        self.send_json(get_stack_vars(ea))
    elif action == 'args':
        self.send_json(get_func_args(ea))
    elif action == 'switch':
        self.send_json(get_switch_info(ea))
    elif action == 'comment':
        self.send_json(get_comment_at(ea))
    else:
        self.send_error_json(f'Unknown action: {action}')

@get_route(r'/api/search-text/.*')
def route_do_get_22(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) >= 4:
        self.send_json(search_text_in_disasm(parts[3]))
    else:
        self.send_error_json('Use /api/search-text/<text>')

@get_route(r'/api/types')
def route_do_get_23(self, match, params):
    self.send_json(get_local_types())

@get_route(r'/api/type-libraries')
def route_do_get_24(self, match, params):
    self.send_json(get_type_libraries())

@get_route(r'/api/cursor')
def route_do_get_25(self, match, params):
    self.send_json(get_cursor_pos())

@get_route(r'/api/selection')
def route_do_get_26(self, match, params):
    self.send_json(get_selection_range())

@get_route(r'/api/functions-page')
def route_do_get_27(self, match, params):
    off = int(params.get('offset', [0])[0])
    lim = int(params.get('limit', [500])[0])
    self.send_json(get_functions_paginated(off, lim))

@get_route(r'/api/dbg/breakpoints')
def route_do_get_28(self, match, params):
    self.send_json(dbg_list_bps())

@get_route(r'/api/dbg/regs')
def route_do_get_29(self, match, params):
    self.send_json(dbg_get_regs())

@get_route(r'/api/dbg/threads')
def route_do_get_30(self, match, params):
    self.send_json(dbg_get_threads())

@get_route(r'/api/dbg/stack')
def route_do_get_31(self, match, params):
    self.send_json(dbg_get_stack())

@get_route(r'/api/dbg/memory/.*')
def route_do_get_32(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 6:
        self.send_json(dbg_read_mem(parse_ea(parts[4]), int(parts[5])))
    else:
        self.send_error_json('Use /api/dbg/memory/<ea>/<size>')

@get_route(r'/api/type/.*')
def route_do_get_33(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) >= 4:
        self.send_json(get_type_by_name(parts[3]))
    else:
        self.send_error_json('Use /api/type/<name>')

@get_route(r'/api/insn/.*')
def route_do_get_34(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_instruction(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/insn/<ea>')

@get_route(r'/api/operands/.*')
def route_do_get_35(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_operands(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/operands/<ea>')

@get_route(r'/api/data-xrefs/.*')
def route_do_get_36(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_data_xrefs(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/data-xrefs/<ea>')

@get_route(r'/api/code-xrefs/.*')
def route_do_get_37(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 4:
        self.send_json(get_code_xrefs(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/code-xrefs/<ea>')

@get_route(r'/api/function/.*')
def route_do_get_38(self, match, params):
    parts = match.string.split('/')
    if len(parts) >= 5:
        ea = parse_ea(parts[3])
        act = parts[4]
        if act == 'ctree':
            self.send_json(get_ctree_json(ea))
        elif act == 'lvar-map':
            self.send_json(get_lvar_map(ea))
        elif act == 'microcode':
            mat = int(params.get('maturity', [7])[0])
            self.send_json(get_microcode(ea, mat))
        elif act == 'callers':
            self.send_json(get_callers(ea))
        elif act == 'callees':
            self.send_json(get_callees(ea))
        elif act == 'strings-used':
            self.send_json(get_strings_used(ea))
        else:
            self.send_error_json(f'Unknown action: {act}')
    else:
        self.send_error_json('Use /api/function/<ea>/<action>')

@get_route(r'/api/schema')
def route_do_get_39(self, match, params):
    try:
        global _cached_schema
        if _cached_schema is None:
            schema_path = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', 'api_schema.json'))
            if os.path.basename(schema_path) != 'api_schema.json':
                raise ValueError('Invalid schema path')

            if os.path.exists(schema_path) and os.path.isfile(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    _cached_schema = json.load(f)
            else:
                self.send_error_json('api_schema.json not found', 404)
                return
        self.send_json(_cached_schema)
    except Exception as e:
        self.send_error_json(str(e), 500)

@post_route(r'/api/batch')
def route_do_post_0(self, match, data):
    mutations = data.get('mutations', [])
    if not mutations:
        self.send_error_json('No mutations provided')
        return
    self.send_json(execute_batch(mutations))

@post_route(r'/api/function/.*')
def route_do_post_1(self, match, data):
    parts = match.string.split('/')
    if len(parts) < 5:
        self.send_error_json('Invalid path')
        return
    ea = parse_ea(parts[3])
    action = parts[4]
    if action == 'rename':
        name = data.get('name')
        if not name:
            self.send_error_json("Missing 'name' field")
            return
        self.send_json(rename_function(ea, name))
    elif action == 'comment':
        comment = data.get('comment', '')
        self.send_json(set_function_comment(ea, comment))
    elif action == 'lvar-rename':
        old = data.get('old')
        new = data.get('new')
        if not old or not new:
            self.send_error_json("Missing 'old' and/or 'new' fields")
            return
        self.send_json(rename_local_var(ea, old, new))
    elif action == 'set-type':
        type_str = data.get('type')
        if not type_str:
            self.send_error_json("Missing 'type' field")
            return
        self.send_json(set_func_type(ea, type_str))
    else:
        self.send_error_json(f'Unknown POST action: {action}')

@post_route(r'/api/struct/create')
def route_do_post_2(self, match, data):
    definition = data.get('definition')
    if not definition:
        self.send_error_json("Missing 'definition' field")
        return
    self.send_json(create_struct(definition))

@post_route(r'/api/struct/add-member')
def route_do_post_3(self, match, data):
    sn = data.get('struct')
    mn = data.get('member')
    off = data.get('offset', -1)
    sz = data.get('size', 4)
    tp = data.get('type')
    self.send_json(add_struct_member_api(sn, mn, off, sz, tp))

@post_route(r'/api/enum/create')
def route_do_post_4(self, match, data):
    name = data.get('name')
    if not name:
        self.send_error_json("Missing 'name' field")
        return
    self.send_json(create_enum_api(name, data.get('width', 4)))

@post_route(r'/api/enum/add-member')
def route_do_post_5(self, match, data):
    en = data.get('enum')
    mn = data.get('member')
    val = data.get('value', 0)
    self.send_json(add_enum_member_api(en, mn, val))

@post_route(r'/api/save')
def route_do_post_6(self, match, data):
    self.send_json(save_database())

@post_route(r'/api/make-func')
def route_do_post_7(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(make_function(ea))

@post_route(r'/api/delete-func')
def route_do_post_8(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(delete_function(ea))

@post_route(r'/api/set-color')
def route_do_post_9(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    color = int(data.get('color', '0'), 16) if isinstance(data.get('color'), str) else data.get('color', 0)
    self.send_json(set_color(ea, color))

@post_route(r'/api/decompile-batch')
def route_do_post_10(self, match, data):
    ea_list = [parse_ea(e) for e in data.get('addresses', [])]
    self.send_json(decompile_batch(ea_list))

@post_route(r'/api/patch-bytes')
def route_do_post_11(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(patch_bytes_at(ea, data.get('bytes', '')))

@post_route(r'/api/make-code')
def route_do_post_12(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(make_code_at(ea, data.get('size', 0)))

@post_route(r'/api/make-data')
def route_do_post_13(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(make_data_at(ea, data.get('size', 4)))

@post_route(r'/api/undefine')
def route_do_post_14(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(undefine_range(ea, data.get('size', 1)))

@post_route(r'/api/set-name')
def route_do_post_15(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(set_name_at(ea, data.get('name', '')))

@post_route(r'/api/apply-struct')
def route_do_post_16(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(apply_struct_at(ea, data.get('struct', '')))

@post_route(r'/api/delete-struct')
def route_do_post_17(self, match, data):
    self.send_json(delete_struct_api(data.get('name', '')))

@post_route(r'/api/delete-enum')
def route_do_post_18(self, match, data):
    self.send_json(delete_enum_api(data.get('name', '')))

@post_route(r'/api/add-bookmark')
def route_do_post_19(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(add_bookmark_api(ea, data.get('description', ''), data.get('slot', -1)))

@post_route(r'/api/delete-bookmark')
def route_do_post_20(self, match, data):
    self.send_json(delete_bookmark_api(data.get('slot', 0)))

@post_route(r'/api/import-header')
def route_do_post_21(self, match, data):
    self.send_json(import_c_header(data.get('path', '')))

@post_route(r'/api/reanalyze')
def route_do_post_22(self, match, data):
    s = parse_ea(data.get('start', '0'))
    e = parse_ea(data.get('end', '0'))
    self.send_json(reanalyze_range(s, e))

@post_route(r'/api/exec')
def route_do_post_23(self, match, data):
    script = data.get('script', '')
    self.send_json(execute_dynamic_python(script))

@post_route(r'/api/address/.*')
def route_do_post_24(self, match, data):
    parts = match.string.split('/')
    if len(parts) < 5:
        self.send_error_json('Invalid path')
        return
    ea = parse_ea(parts[3])
    action = parts[4]
    if action == 'comment':
        comment = data.get('comment', '')
        self.send_json(set_address_comment(ea, comment))
    else:
        self.send_error_json(f'Unknown action: {action}')

@post_route(r'/api/type/create')
def route_do_post_25(self, match, data):
    self.send_json(create_type_from_c(data.get('definition', '')))

@post_route(r'/api/type/delete')
def route_do_post_26(self, match, data):
    self.send_json(delete_local_type(data.get('name', '')))

@post_route(r'/api/type-library/load')
def route_do_post_27(self, match, data):
    self.send_json(load_til_api(data.get('name', '')))

@post_route(r'/api/segment/create')
def route_do_post_28(self, match, data):
    self.send_json(create_segment_api(parse_ea(data.get('start', '0')), parse_ea(data.get('end', '0')), data.get('name', 'seg'), data.get('class', 'DATA'), data.get('bitness', 2)))

@post_route(r'/api/segment/delete')
def route_do_post_29(self, match, data):
    self.send_json(delete_segment_api(parse_ea(data.get('ea', '0'))))

@post_route(r'/api/segment/set-attrs')
def route_do_post_30(self, match, data):
    self.send_json(set_segment_attrs_api(parse_ea(data.get('ea', '0')), data))

@post_route(r'/api/undo')
def route_do_post_31(self, match, data):
    self.send_json(undo_action())

@post_route(r'/api/redo')
def route_do_post_32(self, match, data):
    self.send_json(redo_action())

@post_route(r'/api/navigate')
def route_do_post_33(self, match, data):
    self.send_json(navigate_to(parse_ea(data.get('ea', '0'))))

@post_route(r'/api/dbg/start')
def route_do_post_34(self, match, data):
    self.send_json(dbg_start_process(data.get('path'), data.get('args', ''), data.get('sdir')))

@post_route(r'/api/dbg/attach')
def route_do_post_35(self, match, data):
    self.send_json(dbg_attach_process(data.get('pid', 0)))

@post_route(r'/api/dbg/detach')
def route_do_post_36(self, match, data):
    self.send_json(dbg_detach())

@post_route(r'/api/dbg/breakpoint')
def route_do_post_37(self, match, data):
    self.send_json(dbg_set_bp(parse_ea(data.get('ea', '0')), data.get('hardware', False)))

@post_route(r'/api/dbg/del-breakpoint')
def route_do_post_38(self, match, data):
    self.send_json(dbg_del_bp(parse_ea(data.get('ea', '0'))))

@post_route(r'/api/dbg/step-into')
def route_do_post_39(self, match, data):
    self.send_json(dbg_step_into_api())

@post_route(r'/api/dbg/step-over')
def route_do_post_40(self, match, data):
    self.send_json(dbg_step_over_api())

@post_route(r'/api/dbg/continue')
def route_do_post_41(self, match, data):
    self.send_json(dbg_continue_api())

@post_route(r'/api/dbg/pause')
def route_do_post_42(self, match, data):
    self.send_json(dbg_pause_api())

@post_route(r'/api/dbg/write-memory')
def route_do_post_43(self, match, data):
    self.send_json(dbg_write_mem(parse_ea(data.get('ea', '0')), data.get('bytes', '')))

@post_route(r'/api/function/.*')
def route_do_post_44(self, match, data):
    parts = match.string.split('/')
    if len(parts) >= 5:
        ea = parse_ea(parts[3])
        act = parts[4]
        if act == 'lvar-set-type':
            self.send_json(set_lvar_type_api(ea, data.get('var', ''), data.get('type', '')))
        elif act == 'lvar-comment':
            self.send_json(set_lvar_comment_api(ea, data.get('var', ''), data.get('comment', '')))
        else:
            self.send_error_json(f'Unknown POST action: {act}')
    else:
        self.send_error_json('Invalid path')


@get_route(r'/api/events')
def route_events(self, match, params):
    self.send_response(200)
    self.send_header('Content-Type', 'text/event-stream')
    self.send_header('Cache-Control', 'no-cache')
    self.send_header('Connection', 'keep-alive')
    self.send_header('Access-Control-Allow-Origin', '*')
    self.end_headers()

    while True:
        try:
            event = sse_queue.get(timeout=1.0)
            self.wfile.write(f"data: {json.dumps(event)}\n\n".encode('utf-8'))
            self.wfile.flush()
        except queue.Empty:
            self.wfile.write(b": ping\n\n")
            self.wfile.flush()
        except Exception:
            break


class BridgeHandler(BaseHTTPRequestHandler):
    """HTTP handler for the Antigravity-IDA Bridge."""

    def log_message(self, format, *args):
        """Log to IDA output window."""
        msg = format % args
        safe_read(lambda: ida_kernwin.msg(f"[Antigravity] {msg}\n"))

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))

    def send_error_json(self, message, status=400):
        self.send_json({"error": message}, status)

    def _check_auth(self):
        if not AUTH_ENABLED:
            return True
        auth = self.headers.get('Authorization', '')
        if auth == f'Bearer {AUTH_TOKEN}':
            return True
        # Allow unauthenticated ping and schema for discovery
        parsed = urlparse(self.path)
        if parsed.path.rstrip('/') in ('/api/ping', '/api/schema'):
            return True
        self.send_json({"error": "Unauthorized. Pass 'Authorization: Bearer <token>' header. Token is in " + _token_path}, 401)
        return False

    def do_GET(self):
        if not self._check_auth(): return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)
        for pattern, handler in GET_ROUTES:
            m = pattern.match(path)
            if m:
                try: handler(self, m, params)
                except Exception as e: self.send_error_json(str(e))
                return
        self.send_error_json("Unknown GET endpoint: " + path, 404)

    def do_POST(self):
        if not self._check_auth(): return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        cl = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(cl).decode("utf-8") if cl > 0 else "{}"
        try: data = json.loads(body) if body else {}
        except json.JSONDecodeError: return self.send_error_json("Invalid JSON body")
        for pattern, handler in POST_ROUTES:
            m = pattern.match(path)
            if m:
                try: handler(self, m, data)
                except Exception as e: self.send_error_json(str(e))
                return
        self.send_error_json("Unknown POST endpoint: " + path, 404)

# ─── Server Lifecycle ────────────────────────────────────────────────────────

_server = None
_thread = None

def start_server(host=HOST, port=PORT):
    """Start the HTTP server in a background thread."""
    global _server, _thread
    if _server is not None:
        print(f"[Antigravity] Server already running on {host}:{port}")
        return

    _server = ThreadingHTTPServer((host, port), BridgeHandler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()

    ui_hooks.hook()
    if dbg_hooks:
        dbg_hooks.hook()

    ui_hooks.hook()
    if dbg_hooks:
        dbg_hooks.hook()

    print(f"[Antigravity] ✅ Bridge server started on http://{host}:{port}")
    print(f"[Antigravity] 🔑 Auth token: {AUTH_TOKEN}")
    print(f"[Antigravity] 🔑 Token file: {_token_path}")
    print("[Antigravity] Endpoints: /api/info, /api/functions, /api/function/<ea>/pseudocode, ...")
    ida_kernwin.msg(f"[Antigravity] Bridge server started on http://{host}:{port}\n")

def stop_server():
    """Stop the HTTP server."""
    global _server, _thread
    if _server:
        _server.shutdown()

    ui_hooks.unhook()
    if dbg_hooks:
        dbg_hooks.unhook()

        _server = None
        _thread = None
        print("[Antigravity] Server stopped.")
        ida_kernwin.msg("[Antigravity] Bridge server stopped.\n")

# ─── IDA Plugin Interface ────────────────────────────────────────────────────

class AntigravityPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Antigravity-IDA Bridge Server"
    help = "Starts an HTTP server for external AI agent control"
    wanted_name = "Antigravity Bridge"
    wanted_hotkey = "Ctrl-Shift-A"

    def init(self):
        print("[Antigravity] Plugin loaded. Press Ctrl+Shift+A to toggle server.")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if _server is None:
            start_server()
        else:
            stop_server()

    def term(self):
        stop_server()

def PLUGIN_ENTRY():
    return AntigravityPlugin()

# ─── Script Mode (File > Script File) ────────────────────────────────────────
# If run directly as a script, start the server immediately.
if __name__ == "__main__" or not hasattr(ida_idaapi, "plugin_t"):
    start_server()

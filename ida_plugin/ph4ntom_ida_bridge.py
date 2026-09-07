"""
ph4ntom IDA Bridge Server Plugin
=====================================
Lightweight HTTP server running inside IDA Pro 9.x.
All operations are thread-safe via ida_kernwin.execute_sync().

Installation:
  Copy this file to IDA's plugins directory or run via File > Script File.

Usage:
  Once loaded, the server listens on http://127.0.0.1:13370
  Use cli.py to interact from outside.
"""

import json
import threading
import traceback
import re
import secrets
import tempfile
import os
import socket
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote

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
BRIDGE_VERSION = "6.2.0"
MAX_FUNCTIONS = 5000
MAX_STRINGS = 2000
MAX_BODY_SIZE = 5 * 1024 * 1024
MAX_TRANSFER = 1024 * 1024
REQUEST_TIMEOUT = 5
MAX_CONNECTIONS = 16
_cached_schema = None


def _schema_candidates():
    """Return schema locations for both plugin imports and IDA script execution."""
    directories = []
    script_path = globals().get('__file__')
    if script_path:
        script_dir = os.path.dirname(os.path.abspath(script_path))
        directories.extend((script_dir, os.path.dirname(script_dir)))

    try:
        import ida_diskio
        directories.extend((
            ida_diskio.idadir('plugins'),
            os.path.join(ida_diskio.get_user_idadir(), 'plugins'),
        ))
    except (ImportError, AttributeError, TypeError):
        pass

    directories.append(os.getcwd())
    seen = set()
    for directory in directories:
        if not directory:
            continue
        candidate = os.path.realpath(os.path.join(directory, 'api_schema.json'))
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

# ─── Authentication ──────────────────────────────────────────────────────────

def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _write_secure_token(token):
    """Write the session token atomically with owner-only permissions."""
    configured = os.environ.get("IDA_BRIDGE_TOKEN_FILE")
    candidates = []
    if configured:
        candidates.append(os.path.abspath(os.path.expanduser(configured)))
    if not configured:
        candidates.extend([
        os.path.join(os.path.expanduser("~"), ".ph4ntom_ida_bridge_token"),
        os.path.join(tempfile.gettempdir(), ".ph4ntom_ida_bridge_token"),
        ])

    last_error = None
    for token_path in candidates:
        temp_path = None
        try:
            token_dir = os.path.dirname(token_path)
            if token_dir:
                os.makedirs(token_dir, mode=0o700, exist_ok=True)
            temp_path = token_path + "." + secrets.token_hex(8) + ".tmp"
            _create_private_file(temp_path, token.encode('ascii'))
            os.replace(temp_path, token_path)
            try:
                os.chmod(token_path, 0o600)
            except OSError:
                pass
            return token_path
        except OSError as exc:
            last_error = exc
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    raise RuntimeError("Unable to create a secure bridge token file: " + str(last_error))


def _create_private_file(path, content):
    """Protect the file before writing bytes, including a real Windows DACL."""
    if os.name != 'nt':
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return
    import ctypes
    from ctypes import wintypes
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [('length', wintypes.DWORD), ('descriptor', ctypes.c_void_p), ('inherit', wintypes.BOOL)]
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p)
    convert.restype = wintypes.BOOL
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.WriteFile.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
    kernel.WriteFile.restype = wintypes.BOOL
    kernel.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
    kernel.FlushFileBuffers.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not convert('D:P(A;;FA;;;OW)', 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        handle = kernel.CreateFileW(path, 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            written = wintypes.DWORD()
            buffer = ctypes.create_string_buffer(content)
            if not kernel.WriteFile(handle, buffer, len(content), ctypes.byref(written), None) or written.value != len(content):
                raise OSError('Incomplete token write')
            if not kernel.FlushFileBuffers(handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(handle)
    finally:
        kernel.LocalFree(descriptor)


AUTH_TOKEN = secrets.token_hex(32)
_token_path = None  # Merely importing a plugin must not rotate a running server's token.
AUTH_ENABLED = not _env_flag("IDA_BRIDGE_DISABLE_AUTH", False)
ALLOW_SCRIPT_EXECUTION = _env_flag("IDA_BRIDGE_ALLOW_EXEC", False)
READ_ONLY = _env_flag("IDA_BRIDGE_READ_ONLY", False)
ALLOWED_IMPORT_ROOTS = tuple(
    os.path.realpath(os.path.expanduser(path.strip()))
    for path in os.environ.get("IDA_BRIDGE_ALLOWED_IMPORT_ROOTS", "").split(os.pathsep)
    if path.strip()
)

# ─── Thread-Safe Execution ───────────────────────────────────────────────────

_sync_context = threading.local()


def _run_synced(func, write):
    active = getattr(_sync_context, "write", None)
    if active is not None:
        if write and not active:
            raise RuntimeError("Cannot write inside a read callback")
        return func()
    result, error, completed = [None], [None], [False]

    def wrapper():
        _sync_context.write = write
        try:
            result[0] = func()
        except Exception:
            error[0] = traceback.format_exc()
        finally:
            del _sync_context.write
            completed[0] = True
        return 0  # execute_sync callbacks must return an integer.

    status = ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ)
    if status == -1 or not completed[0]:
        raise RuntimeError("IDA rejected main-thread execution")
    if error[0]:
        raise RuntimeError(error[0])
    return result[0]


def safe_read(func):
    """Execute in IDA's main thread; reuse an enclosing bridge callback."""
    return _run_synced(func, False)


def safe_write(func):
    """Execute in IDA's main thread with write permission."""
    return _run_synced(func, True)


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
                "perm": f"{'r' if s.perm & ida_segment.SEGPERM_READ else '-'}{'w' if s.perm & ida_segment.SEGPERM_WRITE else '-'}{'x' if s.perm & ida_segment.SEGPERM_EXEC else '-'}",
            })
        return {"segments": segs, "count": len(segs)}
    return safe_read(_inner)

def get_structs():
    """Get all defined structures."""
    def _inner():
        structs = []
        til = ida_typeinf.get_idati()
        for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            if tif.is_struct() or tif.is_union():
                structs.append({
                    "id": ordinal,
                    "name": ida_typeinf.get_numbered_type_name(til, ordinal),
                    "size": tif.get_size(),
                    "is_union": tif.is_union(),
                })
        return {"structs": structs, "count": len(structs)}
    return safe_read(_inner)

def get_struct_details(name_or_id):
    """Get struct members with offsets and types."""
    def _inner():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if isinstance(name_or_id, str):
            sid = ida_typeinf.get_type_ordinal(til, name_or_id)
            found = tif.get_named_type(til, name_or_id)
        else:
            sid = name_or_id
            found = tif.get_numbered_type(til, sid)
        if not found or not (tif.is_struct() or tif.is_union()):
            return {"error": f"Structure not found: {name_or_id}"}
        sname = tif.get_type_name() or str(name_or_id)
        ssize = tif.get_size()
        members = []
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            for member in udt:
                moff = member.offset // 8
                members.append({
                    "name": member.name,
                    "offset": hex(moff),
                    "offset_dec": moff,
                    "size": member.size // 8,
                    "type": str(member.type),
                })
        return {"name": sname, "id": sid, "size": ssize, "members": members, "count": len(members)}
    return safe_read(_inner)

def get_enums():
    """Get all enums."""
    def _inner():
        enums = []
        til = ida_typeinf.get_idati()
        for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal) or not tif.is_enum():
                continue
            details = ida_typeinf.enum_type_data_t()
            count = len(details) if tif.get_enum_details(details) else 0
            enums.append({
                "id": ordinal,
                "name": ida_typeinf.get_numbered_type_name(til, ordinal),
                "width": tif.get_size(),
                "count": count,
            })
        return {"enums": enums, "count": len(enums)}
    return safe_read(_inner)

def get_enum_details(name_or_id):
    """Get enum members with values."""
    def _inner():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if isinstance(name_or_id, str):
            eid = ida_typeinf.get_type_ordinal(til, name_or_id)
            found = tif.get_named_type(til, name_or_id)
        else:
            eid = name_or_id
            found = tif.get_numbered_type(til, eid)
        if not found or not tif.is_enum():
            return {"error": f"Enum not found: {name_or_id}"}
        ename = tif.get_type_name() or str(name_or_id)
        members = []
        details = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(details):
            for member in details:
                members.append({
                    "name": member.name,
                    "value": member.value,
                    "value_hex": hex(member.value),
                })
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
        s_ea = start_ea if start_ea else (ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0)
        max_ea = ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else 0xFFFFFFFF
        results = []
        # Convert pattern: "E8 ?? ?? ?? ??" -> IDA binary search format
        ida_pattern = pattern.replace('??', '?').replace('  ', ' ')
        current = s_ea
        for _ in range(max_results):
            if hasattr(ida_bytes, 'find_bytes'):
                found = ida_bytes.find_bytes(
                    ida_pattern,
                    current,
                    range_end=max_ea,
                    flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW,
                    radix=16,
                )
            else:
                import ida_search
                found = ida_search.find_binary(
                    current, max_ea, ida_pattern, 16, ida_search.SEARCH_DOWN
                )
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
    size = bounded_int(size, 'size', 1, MAX_TRANSFER)
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
        ok = bool(ida_loader.save_database(None, 0))
        return {"success": ok, "message": "Database saved" if ok else "IDA refused to save the database"}
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
    size = bounded_int(size, 'size', 1, MAX_TRANSFER)
    offset = bounded_int(offset, 'offset', -1, MAX_TRANSFER)
    def _inner():
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), struct_name) or not (tif.is_struct() or tif.is_union()):
            return {"error": f"Structure '{struct_name}' not found"}
        member_type = ida_typeinf.tinfo_t()
        if type_str:
            ida_typeinf.parse_decl(member_type, None, type_str.rstrip(';') + ';', ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
            if member_type.empty():
                return {"error": f"Cannot parse member type: {type_str}"}
            if member_type.get_size() != size:
                return {"error": "Member type size does not match the requested size"}
        else:
            member_type = ida_typeinf.tinfo_t({1: ida_typeinf.BTF_UINT8, 2: ida_typeinf.BTF_UINT16,
                4: ida_typeinf.BTF_UINT32, 8: ida_typeinf.BTF_UINT64}.get(size, ida_typeinf.BTF_UINT8))
            if size not in (1, 2, 4, 8):
                element = ida_typeinf.tinfo_t(member_type)
                if not member_type.create_array(element, size):
                    return {"error": "Cannot create member array type"}
        actual_offset = (0 if tif.is_union() else tif.get_size()) if offset == -1 else offset
        tif.add_udm(member_name, member_type, actual_offset * 8)
        members = get_struct_details(struct_name).get('members', [])
        ok = any(m['name'] == member_name and m['offset_dec'] == actual_offset and m['size'] == size for m in members)
        return {"success": ok, "struct": struct_name, "member": member_name, "offset": hex(actual_offset)}
    return safe_write(_inner)

def create_enum_api(name, width=4):
    """Create a new enum."""
    def _inner():
        width_checked = bounded_int(width, 'width', 1, 8)
        if width_checked not in (1, 2, 4, 8):
            return {"error": "Enum width must be 1, 2, 4 or 8 bytes"}
        if idc.get_enum(name) != idc.BADADDR:
            return {"error": f"Enum '{name}' already exists"}
        eid = idc.add_enum(-1, name, 0)
        if eid == idc.BADADDR:
            return {"error": f"Failed to create enum '{name}'"}
        idc.set_enum_width(eid, width_checked)
        if idc.get_enum_width(eid) != width_checked:
            idc.del_enum(eid)
            return {"error": "IDA refused the enum width"}
        return {"success": idc.get_enum_width(eid) == width_checked, "name": name, "id": eid, "width": width_checked}
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
        func = ida_funcs.get_func(ea)
        if not func or func.start_ea != ea:
            return {"error": "Address must be a function start"}
        ok = ida_name.set_name(ea, new_name, ida_name.SN_NOWARN)
        ok = bool(ok) and ida_name.get_name(ea) == new_name
        return {"success": ok, "ea": hex(ea), "new_name": new_name}
    return safe_write(_inner)

def set_function_comment(ea, comment, repeatable=True):
    """Set comment on function."""
    def _inner():
        ok = idc.set_func_cmt(ea, comment, repeatable)
        ok = bool(ok) and (idc.get_func_cmt(ea, repeatable) or "") == comment
        return {"success": ok, "ea": hex(ea), "comment": comment}
    return safe_write(_inner)

def set_address_comment(ea, comment, repeatable=False):
    """Set inline comment at address."""
    def _inner():
        ok = idc.set_cmt(ea, comment, repeatable)
        ok = bool(ok) and (idc.get_cmt(ea, repeatable) or "") == comment
        return {"success": ok, "ea": hex(ea), "comment": comment}
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
        if not any(lv.name == old_name for lv in cfunc.lvars):
            available = [lv.name for lv in cfunc.lvars]
            return {"error": f"Variable '{old_name}' not found", "available_vars": available}
        if any(lv.name == new_name and lv.name != old_name for lv in cfunc.lvars):
            return {"error": "Another variable already has the requested name"}
        ok = bool(ida_hexrays.rename_lvar(cfunc.entry_ea, old_name, new_name))
        ida_hexrays.mark_cfunc_dirty(cfunc.entry_ea)
        refreshed = ida_hexrays.decompile(cfunc.entry_ea)
        ok = ok and any(lv.name == new_name for lv in refreshed.lvars)
        return {"success": ok, "ea": hex(func_ea), "old": old_name, "new": new_name}
    return safe_write(_inner)

def create_struct(c_definition):
    """Create a structure from C syntax."""
    def _inner():
        try:
            count = idc.parse_decls(c_definition, idc.PT_TYP)
        except Exception as e:
            return {"error": f"Parse error: {str(e)}", "input": c_definition}
        if count != 0:
            return {"success": False, "error": "C declaration parsing failed", "parse_errors": count}
        return {"success": True, "parse_errors": 0, "definition": c_definition}
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

_BATCH_FIELDS = {
    "rename-func": ("name",), "comment-func": ("comment",), "comment": ("comment",),
    "rename-var": ("old", "new"), "create-struct": ("definition",), "set-type": ("type",),
}
_BATCH_REVERSIBLE = {"rename-func", "comment-func", "comment"}


def execute_batch(mutations, dry_run=False, mode="rollback"):
    """Prevalidate a bounded batch, then compensate supported values on failure.

    This is not an IDB transaction: analysis side effects and a process crash cannot
    be undone. Types and decompiler locals require explicit best_effort mode.
    """
    if type(dry_run) is not bool or mode not in ("rollback", "best_effort"):
        return {"status": "error", "success": False, "phase": "validation", "error": "Invalid dry_run or mode"}
    if not isinstance(mutations, list) or not 1 <= len(mutations) <= 256:
        return {"status": "error", "success": False, "phase": "validation", "error": "Provide 1 to 256 mutations"}

    def _inner():
        prepared = []
        planned_names = set()
        for i, mut in enumerate(mutations):
            try:
                if not isinstance(mut, dict) or not isinstance(mut.get("op"), str):
                    raise ValueError("Each mutation requires a string op")
                op = mut["op"]
                if op not in _BATCH_FIELDS:
                    raise ValueError("Unknown operation: " + op)
                if mode == "rollback" and op not in _BATCH_REVERSIBLE:
                    raise ValueError(op + " requires mode=best_effort; rollback is not supported")
                allowed = {"op", *_BATCH_FIELDS[op]}
                if op != "create-struct":
                    allowed.add("ea")
                if op in ("comment", "comment-func"):
                    allowed.add("repeatable")
                if set(mut) - allowed:
                    raise ValueError("Unexpected mutation fields")
                for field in _BATCH_FIELDS[op]:
                    value = mut.get(field)
                    if not isinstance(value, str) or len(value) > 65536 or "\x00" in value:
                        raise ValueError("Invalid string field: " + field)
                    if field != "comment" and not value:
                        raise ValueError("Empty field: " + field)
                item = dict(mut)
                if op != "create-struct":
                    ea_text = mut.get("ea")
                    if not isinstance(ea_text, str) or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,16}", ea_text):
                        raise ValueError("ea must be a hexadecimal address string")
                    ea = int(ea_text, 16)
                    if ea == ida_idaapi.BADADDR or not ida_bytes.is_mapped(ea):
                        raise ValueError("Address is not mapped")
                    item["ea"] = ea
                    if op in ("rename-func", "comment-func", "rename-var", "set-type"):
                        function = ida_funcs.get_func(ea)
                        if not function or function.start_ea != ea:
                            raise ValueError("Address must be a function start")
                if op in ("comment", "comment-func"):
                    item["repeatable"] = mut.get("repeatable", op == "comment-func")
                    if type(item["repeatable"]) is not bool:
                        raise ValueError("repeatable must be boolean")
                if op == "rename-func":
                    name = item["name"]
                    if ida_name.validate_name(name, ida_name.VNT_IDENT) != name:
                        raise ValueError("Invalid IDA name")
                    owner = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
                    if owner not in (ida_idaapi.BADADDR, item["ea"]) or name in planned_names:
                        raise ValueError("Name already exists or is repeated in the batch")
                    planned_names.add(name)
                if op == "rename-var" and not HAS_HEXRAYS:
                    raise ValueError("Hex-Rays is not available")
                prepared.append(item)
            except Exception as exc:
                return {"status": "error", "success": False, "phase": "validation", "failed_at": i,
                        "error": str(exc), "applied": 0, "rollback_attempted": False}

        if dry_run:
            return {"status": "preview", "success": True, "mode": mode, "count": len(prepared), "applied": 0,
                    "plan": [dict(item, ea=hex(item["ea"])) if "ea" in item else item for item in prepared],
                    "limitations": "Preview checks shape, addresses and names; it does not parse types or modify IDB. Execution revalidates."}

        results, undo = [], []
        for i, item in enumerate(prepared):
            op, ea = item["op"], item.get("ea")
            try:
                # Capture immediately before each call, including a call that might
                # mutate and then raise. Reverse order restores repeated writes.
                if mode == "rollback":
                    undo.append((i, item, _batch_read_value(item)))
                if op == "rename-func":
                    result = {"success": bool(ida_name.set_name(ea, item["name"], ida_name.SN_NOWARN))}
                    result["success"] = result["success"] and ida_name.get_name(ea) == item["name"]
                elif op == "comment-func":
                    result = set_function_comment(ea, item["comment"], item["repeatable"])
                elif op == "comment":
                    result = set_address_comment(ea, item["comment"], item["repeatable"])
                elif op == "rename-var":
                    result = rename_local_var(ea, item["old"], item["new"])
                elif op == "create-struct":
                    result = create_struct(item["definition"])
                else:
                    result = set_func_type(ea, item["type"])
                if not isinstance(result, dict) or result.get("error") or result.get("success") is not True:
                    raise RuntimeError(result.get("error", "IDA rejected operation") if isinstance(result, dict) else "Invalid operation result")
                results.append(result)
            except Exception as exc:
                rollback = _do_rollback(undo) if mode == "rollback" else []
                return {"status": "error", "success": False, "phase": "execution", "mode": mode,
                        "failed_at": i, "error": str(exc), "completed_before_error": results,
                        "rollback_attempted": bool(undo), "rollback": rollback,
                        "rolled_back": sum(entry["success"] for entry in rollback),
                        "rollback_complete": all(entry["success"] for entry in rollback) if undo else False,
                        "state": "restored_values" if undo and all(entry["success"] for entry in rollback) else "inspect_required"}
        return {"status": "ok", "success": True, "mode": mode, "results": results, "count": len(results)}

    return (safe_read if dry_run else safe_write)(_inner)


def _batch_read_value(item):
    ea, op = item["ea"], item["op"]
    if op == "rename-func":
        return ida_name.get_name(ea)
    getter = idc.get_func_cmt if op == "comment-func" else idc.get_cmt
    return getter(ea, item["repeatable"]) or ""


def _do_rollback(actions):
    """Return an independently verified result for every attempted restoration."""
    results = []
    for index, item, value in reversed(actions):
        entry = {"index": index, "op": item["op"], "success": False}
        try:
            if _batch_read_value(item) == value:
                entry.update(success=True, changed=False)
            else:
                if item["op"] == "rename-func":
                    ok = ida_name.set_name(item["ea"], value, ida_name.SN_NOWARN)
                else:
                    setter = idc.set_func_cmt if item["op"] == "comment-func" else idc.set_cmt
                    ok = setter(item["ea"], value, item["repeatable"])
                entry.update(success=bool(ok) and _batch_read_value(item) == value, changed=True)
                if not entry["success"]:
                    entry["error"] = "IDA rejected restoration or readback differed"
        except Exception as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return results


# ─── Extended Sensor Functions ───────────────────────────────────────────────

def get_call_graph(ea, depth=3):
    """Get recursive call graph from function."""
    depth = bounded_int(depth, 'depth', 1, 20)
    visited = set()
    def _walk(addr, d):
        if d <= 0 or addr in visited or len(visited) >= MAX_FUNCTIONS:
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
        frame = ida_typeinf.tinfo_t()
        if not frame.get_func_frame(f):
            return {"ea": hex(ea), "stack_vars": [], "count": 0}
        svars = []
        details = ida_typeinf.udt_type_data_t()
        if frame.get_udt_details(details):
            for member in details:
                moff = member.offset // 8
                svars.append({
                    "name": member.name,
                    "offset": hex(moff),
                    "offset_dec": moff,
                    "size": member.size // 8,
                    "type": str(member.type),
                })
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
    data = bytes.fromhex(hex_bytes)
    bounded_int(len(data), 'patch size', 1, MAX_TRANSFER)
    def _inner():
        if ida_bytes.get_bytes(ea, len(data)) is None:
            return {'success': False, 'error': 'Patch range must contain initialized bytes'}
        ida_bytes.patch_bytes(ea, data)
        ok = ida_bytes.get_bytes(ea, len(data)) == data
        return {"success": ok, "ea": hex(ea), "size": len(data), "patched": hex_bytes}
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
        ok = ida_name.set_name(ea, name, ida_name.SN_NOWARN) and ida_name.get_name(ea) == name
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
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(ida_typeinf.get_idati(), name) or not (tif.is_struct() or tif.is_union()):
            return {"error": f"Structure '{name}' not found"}
        return delete_local_type(name)
    return safe_write(_inner)

def delete_enum_api(name):
    """Delete an enum."""
    def _inner():
        eid = idc.get_enum(name)
        if eid == idc.BADADDR:
            return {"error": f"Enum '{name}' not found"}
        idc.del_enum(eid)
        return {"success": idc.get_enum(name) == idc.BADADDR, "name": name}
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
    """Import a C header from an explicitly allowed directory."""
    def _inner():
        try:
            abs_path = os.path.realpath(filepath)
        except Exception:
            abs_path = os.path.abspath(filepath)

        if not ALLOWED_IMPORT_ROOTS:
            return {
                "success": False,
                "error": (
                    "Header import is disabled. Set IDA_BRIDGE_ALLOWED_IMPORT_ROOTS "
                    "to one or more trusted directories."
                ),
            }

        allowed = False
        for root in ALLOWED_IMPORT_ROOTS:
            try:
                common = os.path.commonpath((abs_path, root))
                if os.path.normcase(common) == os.path.normcase(root):
                    allowed = True
                    break
            except (ValueError, OSError):
                continue
        if not allowed:
            return {"success": False, "error": "Header path is outside the allowed directories."}

        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            return {"success": False, "error": f"File not found: {filepath}"}

        errors = idc.parse_decls(abs_path, idc.PT_FILE | idc.PT_TYP)
        return {"success": errors == 0, "parse_errors": errors, "file": abs_path}
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
                # This SDK hint is optional; script execution remains valid without it.
                except Exception: pass  # nosec B110
            # This is the explicit, authenticated, opt-in capability of /api/exec.
            exec(script_code, globals(), local_vars)  # nosec B102
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
    return _modify_lvar(func_ea, var_name, type_str=type_str)


def _modify_lvar(func_ea, var_name, *, type_str=None, comment=None):
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays not available"}
    def _inner():
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return {"error": "Decompilation returned None"}
        variable = next((v for v in cfunc.lvars if v.name == var_name), None)
        if variable is None:
            return {"error": f"Var '{var_name}' not found"}
        info = ida_hexrays.lvar_saved_info_t()
        info.ll = ida_hexrays.lvar_locator_t(variable.location, variable.defea)
        if type_str is not None:
            tif = ida_typeinf.tinfo_t()
            ida_typeinf.parse_decl(tif, None, type_str.rstrip(';') + ';', ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
            if tif.empty():
                return {"error": f"Cannot parse type: {type_str}"}
            info.type = tif
            flags = ida_hexrays.MLI_TYPE
        else:
            info.cmt = comment
            flags = ida_hexrays.MLI_CMT
        ok = bool(ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, flags, info))
        ida_hexrays.mark_cfunc_dirty(cfunc.entry_ea)
        refreshed = ida_hexrays.decompile(cfunc.entry_ea)
        found = next((v for v in refreshed.lvars if v.name == var_name), None)
        if type_str is not None:
            ok = ok and found is not None and found.type() == info.type
        else:
            saved = ida_hexrays.lvar_uservec_t()
            ida_hexrays.restore_user_lvar_settings(saved, cfunc.entry_ea)
            ok = ok and any(v.ll == info.ll and v.cmt == comment for v in saved.lvvec)
        return {"success": bool(ok), "ea": hex(func_ea), "var": var_name,
                **({"type": str(info.type)} if type_str is not None else {"comment": comment})}
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
    return _modify_lvar(func_ea, var_name, comment=cmt)

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
        for ordinal in range(1, ida_typeinf.get_ordinal_limit(til)):
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
        return {"success": count == 0, "parse_errors": count, "definition": c_decl}
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
        tils.append({"name":"local","desc":"Local type library","ntypes":ida_typeinf.get_ordinal_count(til)})
        for i in range(ida_typeinf.get_idati().nbases):
            base = ida_typeinf.get_idati().base(i)
            tils.append({"name":base.name,"desc":base.desc,"ntypes":ida_typeinf.get_ordinal_count(base)})
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
            if 'r' in p: seg.perm |= ida_segment.SEGPERM_READ
            if 'w' in p: seg.perm |= ida_segment.SEGPERM_WRITE
            if 'x' in p: seg.perm |= ida_segment.SEGPERM_EXEC
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
        import ida_dbg
        return ida_dbg is not None
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
        if is_hw: ok = ida_dbg.add_bpt(ea, 1, ida_dbg.BPT_EXEC)
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
        if not ida_dbg.is_debugger_on():
            return {'error': 'No active debugger'}
        regs = {}
        rv = ida_idd.regval_t()
        for name in ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip","eflags",
                      "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip"]:
            try:
                if ida_dbg.get_reg_val(name, rv): regs[name] = hex(rv.ival)
            except Exception:
                regs[name] = None
        return {"registers":regs}
    return safe_read(_inner)

def dbg_read_mem(ea, size):
    size = bounded_int(size, 'memory read size', 1, MAX_TRANSFER)
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        data = ida_idd.dbg_read_memory(ea, size)
        if not data: return {"error":f"Cannot read {size} bytes at {hex(ea)}"}
        return {"ea":hex(ea),"size":size,"hex":' '.join(f'{b:02X}' for b in data)}
    return safe_read(_inner)

def dbg_write_mem(ea, hex_bytes):
    data = bytes.fromhex(hex_bytes)
    bounded_int(len(data), 'memory write size', 1, MAX_TRANSFER)
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        ok = ida_idd.dbg_write_memory(ea, data)
        return {"success":ok == len(data),"ea":hex(ea),"size":len(data),"written":ok}
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
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        trace = ida_idd.call_stack_t()
        ok = ida_dbg.collect_stack_trace(ida_dbg.get_current_thread(), trace)
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
    offset = bounded_int(offset, 'offset', 0, 2 ** 31 - 1)
    limit = bounded_int(limit, 'limit', 1, MAX_FUNCTIONS)
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
    """Strings use hexadecimal notation; JSON integers are numeric addresses."""
    if isinstance(ea_str, bool) or not isinstance(ea_str, (str, int)):
        raise ValueError('Address must be a hexadecimal string or an integer')
    value = int(ea_str.strip(), 16) if isinstance(ea_str, str) else ea_str
    if not 0 <= value < ida_idaapi.BADADDR:
        raise ValueError('Address is outside the IDA address range')
    return value


def bounded_int(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f'{name} must be an integer')
    result = int(value)
    if not minimum <= result <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return result


def get_analyze_context(ea):
    def _inner():
        ctx, errors = {"ea": hex(ea)}, {}
        for name, function, field in [
            ('pseudocode', get_pseudocode, 'pseudocode'), ('lvars', get_lvar_map, 'lvars'),
            ('callers', get_callers, 'callers'), ('callees', get_callees, 'callees'),
            ('strings_used', get_strings_used, 'strings'), ('xrefs_to', get_xrefs_to, 'xrefs_to'),
            ('basic_blocks', get_basic_blocks, 'blocks'),
        ]:
            ctx[name] = None if name == 'pseudocode' else []
            try:
                result = function(ea)
                if result.get('error'):
                    errors[name] = result['error']
                else:
                    ctx[name] = result[field]
            except Exception as exc:
                errors[name] = str(exc)
        ctx['partial'] = bool(errors)
        if errors:
            ctx['errors'] = errors
        return ctx
    return safe_read(_inner)


# --- Micro Router ---
import queue
_event_subscribers = set()
_event_lock = threading.Lock()


def _publish_event(event):
    """Publish an event without allowing UI hooks to block IDA."""
    with _event_lock:
        subscribers = tuple(_event_subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                # A slow consumer gets an explicit gap instead of silently losing events.
                try:
                    while True:
                        subscriber.get_nowait()
                except queue.Empty:
                    pass
                subscriber.put_nowait({'event': 'resync_required'})


def _subscribe_events():
    with _event_lock:
        if len(_event_subscribers) >= 4:
            raise ValueError('At most four event subscribers are supported')
        subscriber = queue.Queue(maxsize=256)
        _event_subscribers.add(subscriber)
        return subscriber


def _unsubscribe_events(subscriber):
    with _event_lock:
        _event_subscribers.discard(subscriber)

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
    self.send_json(get_analyze_context(ea))

class Ph4ntomUIHooks(ida_kernwin.UI_Hooks):
    def screen_ea_changed(self, ea, prev_ea):
        _publish_event({"event": "cursor_changed", "ea": hex(ea), "prev_ea": hex(prev_ea)})
        return 0

try:
    import ida_dbg
    class Ph4ntomDbgHooks(ida_dbg.DbgHooks):
        def dbg_bpt(self, tid, ea):
            _publish_event({"event": "breakpoint_hit", "tid": tid, "ea": hex(ea)})
            return 0
    dbg_hooks = Ph4ntomDbgHooks()
except Exception:
    dbg_hooks = None

ui_hooks = Ph4ntomUIHooks()

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
    self.send_json({
        'status': 'ok',
        'server': 'ph4ntom-ida-bridge',
        'version': BRIDGE_VERSION,
        'auth_enabled': AUTH_ENABLED,
        'dynamic_exec_enabled': ALLOW_SCRIPT_EXECUTION,
        'header_import_enabled': bool(ALLOWED_IMPORT_ROOTS),
        'read_only': READ_ONLY,
    })

@get_route(r'/api/struct/.*')
def route_do_get_15(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_struct_details(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/struct/<name>')

@get_route(r'/api/enum/.*')
def route_do_get_16(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_enum_details(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/enum/<name>')

@get_route(r'/api/vtable/.*')
def route_do_get_17(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_vtable(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/vtable/<ea>')

@get_route(r'/api/bytes/.*')
def route_do_get_18(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 5:
        self.send_json(read_bytes(parse_ea(parts[3]), int(parts[4])))
    else:
        self.send_error_json('Use /api/bytes/<ea>/<size>')

@get_route(r'/api/search-func/.*')
def route_do_get_19(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) == 4:
        self.send_json(find_func_by_name(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/search-func/<name>')

@get_route(r'/api/search-bytes/.*')
def route_do_get_20(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) == 4:
        self.send_json(search_bytes(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/search-bytes/<pattern>')

@get_route(r'/api/function/.*')
def route_do_get_21(self, match, params):
    parts = match.string.split('/')
    if len(parts) != 5:
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
    elif action == 'ctree':
        self.send_json(get_ctree_json(ea))
    elif action == 'lvar-map':
        self.send_json(get_lvar_map(ea))
    elif action == 'microcode':
        maturity = int(params.get('maturity', [7])[0])
        self.send_json(get_microcode(ea, maturity))
    elif action == 'callers':
        self.send_json(get_callers(ea))
    elif action == 'callees':
        self.send_json(get_callees(ea))
    elif action == 'strings-used':
        self.send_json(get_strings_used(ea))
    else:
        self.send_error_json(f'Unknown action: {action}')

@get_route(r'/api/search-text/.*')
def route_do_get_22(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) == 4:
        self.send_json(search_text_in_disasm(unquote(parts[3])))
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
    if len(parts) == 4:
        self.send_json(get_type_by_name(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/type/<name>')

@get_route(r'/api/insn/.*')
def route_do_get_34(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_instruction(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/insn/<ea>')

@get_route(r'/api/operands/.*')
def route_do_get_35(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_operands(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/operands/<ea>')

@get_route(r'/api/data-xrefs/.*')
def route_do_get_36(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_data_xrefs(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/data-xrefs/<ea>')

@get_route(r'/api/code-xrefs/.*')
def route_do_get_37(self, match, params):
    parts = match.string.split('/')
    if len(parts) == 4:
        self.send_json(get_code_xrefs(parse_ea(parts[3])))
    else:
        self.send_error_json('Use /api/code-xrefs/<ea>')

@get_route(r'/api/schema')
def route_do_get_39(self, match, params):
    try:
        global _cached_schema
        if _cached_schema is None:
            schema_path = next(
                (path for path in _schema_candidates() if os.path.isfile(path)),
                None,
            )
            if schema_path is None:
                self.send_error_json('api_schema.json not found', 404)
                return
            with open(schema_path, 'r', encoding='utf-8') as schema_file:
                _cached_schema = json.load(schema_file)
        self.send_json(_cached_schema)
    except Exception as e:
        self.send_error_json(str(e), 500)

@post_route(r'/api/batch')
def route_do_post_0(self, match, data):
    mutations = data.get('mutations', [])
    if not mutations:
        self.send_error_json('No mutations provided')
        return
    self.send_json(execute_batch(mutations, dry_run=data.get("dry_run", False), mode=data.get("mode", "rollback")))

@post_route(r'/api/function/.*')
def route_do_post_1(self, match, data):
    parts = match.string.split('/')
    if len(parts) != 5:
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
    elif action == 'lvar-set-type':
        self.send_json(set_lvar_type_api(ea, data.get('var', ''), data.get('type', '')))
    elif action == 'lvar-comment':
        self.send_json(set_lvar_comment_api(ea, data.get('var', ''), data.get('comment', '')))
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
    if not ALLOW_SCRIPT_EXECUTION:
        self.send_error_json(
            "Dynamic IDAPython execution is disabled. Set IDA_BRIDGE_ALLOW_EXEC=1 before starting IDA to enable it.",
            403,
        )
        return
    script = data.get('script', '')
    if not isinstance(script, str) or not script.strip():
        self.send_error_json("Missing non-empty 'script' field")
        return
    self.send_json(execute_dynamic_python(script))

@post_route(r'/api/address/.*')
def route_do_post_24(self, match, data):
    parts = match.string.split('/')
    if len(parts) != 5:
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

@get_route(r'/api/events')
def route_events(self, match, params):
    subscriber = _subscribe_events()
    try:
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        origin = self.headers.get('Origin', '')
        if self._is_local_origin(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.end_headers()
        self.wfile.write(b': connected\n\n')
        self.wfile.flush()
        while not self.server.stopping.is_set():
            try:
                event = subscriber.get(timeout=1.0)
                payload = f"data: {json.dumps(event)}\n\n".encode('utf-8')
            except queue.Empty:
                payload = b': ping\n\n'
            self.wfile.write(payload)
            self.wfile.flush()
    except OSError:
        pass
    finally:
        _unsubscribe_events(subscriber)


class BridgeHandler(BaseHTTPRequestHandler):
    """Bounded authenticated HTTP transport; no IDA work in request logging."""

    server_version = "ph4ntomIDABridge/" + BRIDGE_VERSION

    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT)

    def log_message(self, format, *args):
        # BaseHTTPRequestHandler logs from worker threads. Calling execute_sync
        # here can deadlock discovery or shutdown while the UI thread is busy.
        pass

    def send_json(self, data, status=200):
        payload = json.dumps(data, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Connection', 'close')
            self.send_header('X-Content-Type-Options', 'nosniff')
            origin = self.headers.get('Origin', '')
            if self._is_local_origin(origin):
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Vary', 'Origin')
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            pass

    def send_error_json(self, message, status=400):
        self.send_json({'success': False, 'error': message}, status)

    @staticmethod
    def _is_local_origin(origin):
        try:
            parsed = urlparse(origin)
            return (parsed.scheme in ('http', 'https') and parsed.hostname in ('127.0.0.1', 'localhost', '::1')
                    and not (parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment)
                    and (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            return False

    def _check_host(self):
        hosts = self.headers.get_all('Host', [])
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        if len(hosts) != 1 or hosts[0] not in allowed:
            self.send_error_json('Invalid Host header', 403)
            return False
        origins = self.headers.get_all('Origin', [])
        if len(origins) > 1 or (origins and not self._is_local_origin(origins[0])):
            self.send_error_json('Origin is not allowed', 403)
            return False
        if not self.path.startswith('/api/') or self.path.startswith('//'):
            self.send_error_json('Invalid API request target', 400)
            return False
        return True

    def _check_auth(self):
        auth = self.headers.get_all('Authorization', [])
        if len(auth) > 1:
            self.send_error_json('Ambiguous Authorization header', 401)
            return False
        if not AUTH_ENABLED:
            return True
        if auth and secrets.compare_digest(auth[0], f'Bearer {self.server.auth_token}'):
            return True
        if self.command == 'GET' and urlparse(self.path).path.rstrip('/') in ('/api/ping', '/api/schema'):
            return True
        self.send_error_json('Unauthorized. Supply the session bearer token.', 401)
        return False

    def do_OPTIONS(self):
        if not self._check_host():
            return
        origin = self.headers.get('Origin', '')
        if not self._is_local_origin(origin):
            self.send_error_json('Origin is required', 403)
            return
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Vary', 'Origin')
        self.end_headers()

    def _dispatch(self, routes, path, data):
        if self.server.stopping.is_set():
            self.send_error_json('Bridge is stopping', 503)
            return
        for pattern, handler in routes:
            match = pattern.fullmatch(path)
            if match:
                try:
                    handler(self, match, data)
                except (ValueError, TypeError, KeyError) as exc:
                    self.send_error_json(str(exc), 400)
                except Exception as exc:
                    self.send_error_json(str(exc), 500)
                return
        self.send_error_json('Unknown API endpoint: ' + path, 404)

    def do_GET(self):
        if not self._check_host() or not self._check_auth():
            return
        parsed = urlparse(self.path)
        try:
            params = parse_qs(parsed.query, max_num_fields=64)
        except ValueError:
            self.send_error_json('Too many query parameters')
            return
        if any(len(values) != 1 for values in params.values()):
            self.send_error_json('Duplicate query parameter')
            return
        self._dispatch(GET_ROUTES, parsed.path.rstrip('/'), params)

    def do_POST(self):
        if not self._check_host() or not self._check_auth():
            return
        if READ_ONLY:
            self.send_error_json('Bridge is configured read-only', 403)
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or self.headers.get_all('Transfer-Encoding'):
            self.send_error_json('One Content-Length and no Transfer-Encoding are required')
            return
        try:
            content_length = int(lengths[0])
        except ValueError:
            self.send_error_json('Invalid Content-Length')
            return
        if not 0 <= content_length <= MAX_BODY_SIZE:
            self.send_error_json('Request body size is outside the allowed range', 413 if content_length > MAX_BODY_SIZE else 400)
            return
        content_types = self.headers.get_all('Content-Type', [])
        if len(content_types) != 1 or content_types[0].split(';', 1)[0].strip().lower() != 'application/json':
            self.send_error_json('Content-Type must be application/json', 415)
            return
        try:
            body = self.rfile.read(content_length)
            if len(body) != content_length:
                raise ValueError('Incomplete body')
            data = json.loads(body.decode('utf-8') or '{}', object_pairs_hook=_strict_object, parse_constant=_invalid_constant)
            if not isinstance(data, dict):
                raise ValueError('JSON body must be an object')
        except (ValueError, UnicodeError, RecursionError):
            self.send_error_json('Invalid JSON object body')
            return
        except (TimeoutError, socket.timeout):
            self.send_error_json('Request body timed out', 408)
            return
        self._dispatch(POST_ROUTES, urlparse(self.path).path.rstrip('/'), data)


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Non-finite JSON number')


class BridgeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address, handler):
        global AUTH_TOKEN, _token_path
        if address[0] != HOST:
            raise ValueError('Bridge must bind to 127.0.0.1')
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.stopping = threading.Event()
        # Bind first. A second instance that cannot bind must not invalidate
        # the first instance's working credentials.
        super().__init__(address, handler)
        try:
            self.auth_token = secrets.token_hex(32)
            self.token_path = _write_secure_token(self.auth_token)
            AUTH_TOKEN, _token_path = self.auth_token, self.token_path
        except Exception:
            self.server_close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def shutdown(self):
        self.stopping.set()
        super().shutdown()


_server = None
_thread = None
_hooks_active = False


def _hook_events():
    global _hooks_active
    if _hooks_active:
        return
    ui_hooks.hook()
    try:
        if dbg_hooks:
            dbg_hooks.hook()
    except Exception:
        ui_hooks.unhook()
        raise
    _hooks_active = True


def _unhook_events():
    global _hooks_active
    if not _hooks_active:
        return
    try:
        ui_hooks.unhook()
    finally:
        if dbg_hooks:
            dbg_hooks.unhook()
        _hooks_active = False

def start_server(host=HOST, port=PORT):
    """Start the HTTP server in a background thread."""
    global _server, _thread
    if _server is not None:
        print(f"[ph4ntom] Server already running on {host}:{port}")
        return

    try:
        server = BridgeHTTPServer((host, port), BridgeHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            name="ph4ntom-ida-bridge",
            daemon=True,
        )
        thread.start()
        _hook_events()
        _server = server
        _thread = thread
    except Exception:
        try:
            if thread.is_alive():
                server.shutdown()
                thread.join(timeout=2.0)
        except (NameError, OSError, RuntimeError):
            pass
        try:
            server.server_close()
        except (NameError, OSError):
            pass
        _unhook_events()
        raise

    print(f"[ph4ntom] ✅ Bridge server started on http://{host}:{port}")
    print(f"[ph4ntom] 🔑 Token file: {_token_path}")
    print(f"[ph4ntom] Dynamic execution: {'enabled' if ALLOW_SCRIPT_EXECUTION else 'disabled'}")
    print("[ph4ntom] Endpoints: /api/info, /api/functions, /api/function/<ea>/pseudocode, ...")
    ida_kernwin.msg(f"[ph4ntom] Bridge server started on http://{host}:{port}\n")

def stop_server():
    """Stop the HTTP server."""
    global _server, _thread
    server = _server
    thread = _thread
    _server = None
    _thread = None

    if server is not None:
        server.shutdown()
        server.server_close()
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=2.0)

    _unhook_events()
    if server is not None:
        print("[ph4ntom] Server stopped.")
        ida_kernwin.msg("[ph4ntom] Bridge server stopped.\n")

# ─── IDA Plugin Interface ────────────────────────────────────────────────────

class Ph4ntomPlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "ph4ntom IDA Bridge Server"
    help = "Starts an HTTP server for external AI agent control"
    wanted_name = "ph4ntom Bridge"
    wanted_hotkey = "Ctrl-Shift-A"

    def init(self):
        print("[ph4ntom] Plugin loaded. Press Ctrl+Shift+A to toggle server.")
        if _env_flag('IDA_BRIDGE_AUTOSTART'):
            start_server()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if _server is None:
            start_server()
        else:
            stop_server()

    def term(self):
        stop_server()

def PLUGIN_ENTRY():
    return Ph4ntomPlugin()

# ─── Script Mode (File > Script File) ────────────────────────────────────────
# If run directly as a script, start the server immediately.
if __name__ == "__main__" or not hasattr(ida_idaapi, "plugin_t"):
    start_server()

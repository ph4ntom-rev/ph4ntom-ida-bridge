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
BRIDGE_VERSION = "6.3.0"
try:
    IDA_VERSION = ida_kernwin.get_kernel_version() if hasattr(ida_kernwin, 'get_kernel_version') else "unknown"
except Exception:
    IDA_VERSION = "unknown"
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


def _write_secure_token(token, port=PORT):
    """Write the session token atomically with owner-only permissions."""
    configured = os.environ.get("IDA_BRIDGE_TOKEN_FILE")
    candidates = []
    if configured:
        candidates.append(os.path.abspath(os.path.expanduser(configured)))
    if not configured:
        suffix = f"_{port}" if (port and port not in (PORT, 0)) else ""
        candidates.extend([
            os.path.join(os.path.expanduser("~"), f".ph4ntom_ida_bridge_token{suffix}"),
            os.path.join(tempfile.gettempdir(), f".ph4ntom_ida_bridge_token{suffix}"),
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
        # IDA 9.5+ compatible — inf_is_32bit() was replaced by inf_is_32bit_exactly() / inf_is_16bit()
        procname = ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else "unknown"
        is_64 = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else False
        if hasattr(ida_ida, 'inf_is_32bit_exactly'):
            is_32 = ida_ida.inf_is_32bit_exactly()
        elif hasattr(ida_ida, 'inf_is_32bit'):
            is_32 = ida_ida.inf_is_32bit()
        elif hasattr(ida_ida, 'inf_is_16bit'):
            is_32 = not is_64 and not ida_ida.inf_is_16bit()
        else:
            is_32 = not is_64
        min_ea = ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0
        max_ea = ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else 0
        start_ea = ida_ida.inf_get_start_ea() if hasattr(ida_ida, 'inf_get_start_ea') else 0
        ida_ver = ida_kernwin.get_kernel_version() if hasattr(ida_kernwin, 'get_kernel_version') else "unknown"
        dbg_on = False
        try:
            import ida_dbg
            dbg_on = bool(ida_dbg.is_debugger_on()) if hasattr(ida_dbg, 'is_debugger_on') else False
        except Exception:
            pass
        imagebase = ida_nalt.get_imagebase() if hasattr(ida_nalt, 'get_imagebase') else min_ea
        md5_hex, sha256_hex, crc32_val = None, None, None
        try:
            raw_md5 = ida_nalt.retrieve_input_file_md5() if hasattr(ida_nalt, 'retrieve_input_file_md5') else None
            if isinstance(raw_md5, (bytes, bytearray)):
                md5_hex = raw_md5.hex()
            raw_sha = ida_nalt.retrieve_input_file_sha256() if hasattr(ida_nalt, 'retrieve_input_file_sha256') else None
            if isinstance(raw_sha, (bytes, bytearray)):
                sha256_hex = raw_sha.hex()
            if hasattr(ida_nalt, 'retrieve_input_file_crc32'):
                crc32_val = hex(ida_nalt.retrieve_input_file_crc32() & 0xFFFFFFFF)
        except Exception:
            pass
        return {
            "filename": ida_nalt.get_root_filename() if hasattr(ida_nalt, 'get_root_filename') else None,
            "filepath": ida_nalt.get_input_file_path() if hasattr(ida_nalt, 'get_input_file_path') else None,
            "processor": procname,
            "bitness": 64 if is_64 else (32 if is_32 else 16),
            "file_type": ida_loader_type(),
            "imagebase": hex(imagebase) if isinstance(imagebase, int) and imagebase != ida_idaapi.BADADDR else hex(min_ea),
            "entry_point": hex(start_ea),
            "min_ea": hex(min_ea),
            "max_ea": hex(max_ea),
            "md5": md5_hex,
            "sha256": sha256_hex,
            "crc32": crc32_val,
            "hexrays_available": HAS_HEXRAYS,
            "analysis_done": ida_auto.auto_is_ok() if hasattr(ida_auto, 'auto_is_ok') else True,
            "ida_version": ida_ver,
            "bridge_version": BRIDGE_VERSION,
            "debugger_on": dbg_on,
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

def get_functions(filter_str=None, start_ea=None, end_ea=None):
    """List functions with address, name, size, module_rva, and optional name/range filters."""
    def _inner():
        funcs = []
        count = 0
        pat = None
        if filter_str:
            try:
                pat = re.compile(filter_str, re.IGNORECASE)
            except re.error:
                pat = None
        filt_lower = filter_str.lower() if filter_str else None
        for ea in idautils.Functions():
            if start_ea is not None and ea < start_ea:
                continue
            if end_ea is not None and ea >= end_ea:
                continue
            name = ida_funcs.get_func_name(ea) or ""
            if filter_str:
                if pat is not None:
                    if not pat.search(name):
                        continue
                elif filt_lower not in name.lower():
                    continue
            if count >= MAX_FUNCTIONS:
                break
            f = ida_funcs.get_func(ea)
            funcs.append({
                "ea": hex(ea),
                "module_rva": _format_module_rva_inner(ea),
                "name": name,
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

def _format_module_rva_inner(ea):
    """Format an effective address as 'module+0xRVA' (must run inside safe_read/safe_write)."""
    if ea is None or ea == ida_idaapi.BADADDR:
        return None
    try:
        import ida_dbg
        if hasattr(ida_dbg, 'is_debugger_on') and ida_dbg.is_debugger_on():
            if hasattr(ida_dbg, 'get_modules'):
                for m in ida_dbg.get_modules():
                    mbase = getattr(m, 'base', ida_idaapi.BADADDR)
                    msize = getattr(m, 'size', 0)
                    if mbase != ida_idaapi.BADADDR and mbase <= ea < (mbase + msize if msize else ida_idaapi.BADADDR):
                        mod_base_name = os.path.basename(getattr(m, 'name', '') or "") or "module"
                        return f"{mod_base_name}+{hex(ea - mbase)}"
            import ida_idd
            if hasattr(ida_idd, 'modinfo_t') and hasattr(ida_dbg, 'get_module_info'):
                mi = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(ea, mi) and mi.base != ida_idaapi.BADADDR and ea >= mi.base:
                    mod_base_name = os.path.basename(mi.name) if mi.name else "module"
                    return f"{mod_base_name}+{hex(ea - mi.base)}"
    except Exception:
        pass
    try:
        root_name = ida_nalt.get_root_filename() if hasattr(ida_nalt, 'get_root_filename') else None
        img_base = ida_nalt.get_imagebase() if hasattr(ida_nalt, 'get_imagebase') else 0
        if img_base in (0, ida_idaapi.BADADDR):
            import ida_ida
            img_base = ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0
        if root_name and img_base != ida_idaapi.BADADDR and ea >= img_base:
            return f"{root_name}+{hex(ea - img_base)}"
    except Exception:
        pass
    return hex(ea)


def get_disasm(ea, end_ea=None, count=None):
    """Get disassembly listing for function at ea, or an address range if end_ea/count is given."""
    if end_ea is not None or count is not None:
        return get_disasm_range(ea, end_ea=end_ea, count=count or 200)
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        lines = []
        current = f.start_ea
        while current < f.end_ea and current != ida_idaapi.BADADDR:
            disasm = idc.generate_disasm_line(current, 0)
            lines.append({"ea": hex(current), "module_rva": _format_module_rva_inner(current), "text": disasm})
            current = idc.next_head(current, f.end_ea)
        return {
            "ea": hex(ea),
            "module_rva": _format_module_rva_inner(ea),
            "name": ida_funcs.get_func_name(ea),
            "disasm": lines,
            "count": len(lines),
        }
    return safe_read(_inner)


def get_disasm_range(start_ea, end_ea=None, count=100):
    """Disassemble an arbitrary address range [start_ea, end_ea) or up to `count` instructions."""
    count = bounded_int(count if count is not None else 100, 'count', 1, 5000)
    def _inner():
        import ida_ida
        max_limit = end_ea if end_ea is not None else (ida_ida.inf_get_max_ea() if hasattr(ida_ida, 'inf_get_max_ea') else ida_idaapi.BADADDR)
        lines = []
        current = start_ea
        steps = 0
        while current < max_limit and current != ida_idaapi.BADADDR and steps < count:
            disasm = idc.generate_disasm_line(current, 0)
            item_size = max(1, ida_bytes.get_item_size(current) if hasattr(ida_bytes, 'get_item_size') else 1)
            raw = ida_bytes.get_bytes(current, min(item_size, 16))
            f = ida_funcs.get_func(current)
            lines.append({
                "ea": hex(current),
                "module_rva": _format_module_rva_inner(current),
                "bytes": raw.hex().upper() if raw else "",
                "text": disasm,
                "func": ida_funcs.get_func_name(f.start_ea) if f else None,
            })
            steps += 1
            nxt = idc.next_head(current, max_limit)
            if nxt == ida_idaapi.BADADDR or nxt <= current:
                current += item_size
            else:
                current = nxt
        return {
            "start_ea": hex(start_ea),
            "start_module_rva": _format_module_rva_inner(start_ea),
            "end_ea": hex(end_ea) if end_ea is not None else (lines[-1]["ea"] if lines else hex(start_ea)),
            "disasm": lines,
            "count": len(lines),
        }
    return safe_read(_inner)


def get_xrefs_to(ea, exact=False, filter_str=None, start_ea=None, end_ea=None, xref_type=None):
    """Get all cross-references TO this address (supports IDA 9.5 XREF_EXACT and filtering)."""
    def _inner():
        refs = []
        flags = 0
        if exact:
            try:
                import ida_xref
                flags = getattr(ida_xref, 'XREF_EXACT', 0)
            except ImportError:
                flags = 0
        pattern = re.compile(filter_str, re.IGNORECASE) if filter_str else None
        type_filt = (xref_type or "").strip().lower()
        iterator = idautils.XrefsTo(ea, flags) if flags else idautils.XrefsTo(ea)
        for xref in iterator:
            if start_ea is not None and xref.frm < start_ea:
                continue
            if end_ea is not None and xref.frm >= end_ea:
                continue
            t_str = _xref_type_str(xref.type)
            if type_filt and type_filt not in t_str.lower():
                continue
            func = ida_funcs.get_func(xref.frm)
            fname = ida_funcs.get_func_name(func.start_ea) if func else (ida_name.get_name(xref.frm) or None)
            if pattern and not pattern.search(fname or ""):
                continue
            refs.append({
                "from_ea": hex(xref.frm),
                "from_module_rva": _format_module_rva_inner(xref.frm),
                "to_ea": hex(getattr(xref, 'to', ea)),
                "from_func": fname,
                "from_func_ea": hex(func.start_ea) if func else None,
                "type": t_str,
            })
        return {
            "ea": hex(ea),
            "module_rva": _format_module_rva_inner(ea),
            "xrefs_to": refs,
            "count": len(refs),
            "exact": bool(exact),
        }
    return safe_read(_inner)


def get_xrefs_from(ea, filter_str=None, start_ea=None, end_ea=None, xref_type=None):
    """Get all cross-references FROM this function or address."""
    def _inner():
        f = ida_funcs.get_func(ea)
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        refs = []
        seen = set()
        pattern = re.compile(filter_str, re.IGNORECASE) if filter_str else None
        type_filt = (xref_type or "").strip().lower()
        current = max(f.start_ea, start_ea) if start_ea is not None else f.start_ea
        limit_ea = min(f.end_ea, end_ea) if end_ea is not None else f.end_ea
        while current < limit_ea and current != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(current):
                if xref.type == 21:  # skip ordinary instruction flow
                    continue
                t_str = _xref_type_str(xref.type)
                if type_filt and type_filt not in t_str.lower():
                    continue
                target_func = ida_funcs.get_func(xref.to)
                tname = ida_funcs.get_func_name(target_func.start_ea) if target_func else ida_name.get_name(xref.to)
                if pattern and not pattern.search(tname or ""):
                    continue
                key = xref.to
                if key not in seen:
                    seen.add(key)
                    refs.append({
                        "from_ea": hex(current),
                        "to_ea": hex(xref.to),
                        "to_module_rva": _format_module_rva_inner(xref.to),
                        "to_func": tname,
                        "to_func_ea": hex(target_func.start_ea) if target_func else None,
                        "type": t_str,
                    })
            current = idc.next_head(current, limit_ea)
        return {
            "ea": hex(ea),
            "module_rva": _format_module_rva_inner(ea),
            "xrefs_from": refs,
            "count": len(refs),
        }
    return safe_read(_inner)


def get_strings(filter_regex=None, offset=0, limit=MAX_STRINGS, start_ea=None, end_ea=None):
    """Get strings in the binary with regex/range filtering and full pagination beyond 2000."""
    offset = bounded_int(offset, 'offset', 0, 2 ** 31 - 1)
    limit = bounded_int(limit, 'limit', 1, 10000)
    def _inner():
        import ida_strlist
        ida_strlist.build_strlist()
        sl = ida_strlist.string_info_t()
        result = []
        matched_total = 0
        pattern = re.compile(filter_regex, re.IGNORECASE) if filter_regex else None
        qty = ida_strlist.get_strlist_qty()
        for i in range(qty):
            if ida_strlist.get_strlist_item(sl, i):
                if start_ea is not None and sl.ea < start_ea:
                    continue
                if end_ea is not None and sl.ea >= end_ea:
                    continue
                s = ida_bytes.get_strlit_contents(sl.ea, sl.length, getattr(sl, 'strtype', getattr(sl, 'type', 0)))
                if s is not None:
                    try:
                        text = s.decode("utf-8", errors="replace")
                    except Exception:
                        text = str(s)
                    if pattern and not pattern.search(text):
                        continue
                    if offset <= matched_total < offset + limit:
                        result.append({
                            "ea": hex(sl.ea),
                            "module_rva": _format_module_rva_inner(sl.ea),
                            "value": text,
                            "length": sl.length,
                        })
                    matched_total += 1
        return {
            "strings": result,
            "offset": offset,
            "limit": limit,
            "returned": len(result),
            "total": matched_total,
            "truncated": (offset + len(result)) < matched_total,
        }
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

def get_names(filter_str=None, max_count=1000, offset=0, limit=None, start_ea=None, end_ea=None):
    """List named items (functions, data labels, etc.) with pagination beyond 1000 and range/regex filters."""
    eff_limit = bounded_int(limit if limit is not None else max_count, 'limit', 1, 10000)
    offset = bounded_int(offset, 'offset', 0, 2 ** 31 - 1)
    def _inner():
        names = []
        matched_total = 0
        pattern = None
        if filter_str:
            try:
                pattern = re.compile(filter_str, re.IGNORECASE)
            except re.error:
                pattern = None
        for ea, name in idautils.Names():
            if start_ea is not None and ea < start_ea:
                continue
            if end_ea is not None and ea >= end_ea:
                continue
            if filter_str:
                if pattern is not None:
                    if not pattern.search(name):
                        continue
                elif filter_str.lower() not in name.lower():
                    continue
            if offset <= matched_total < offset + eff_limit:
                names.append({
                    "ea": hex(ea),
                    "module_rva": _format_module_rva_inner(ea),
                    "name": name,
                })
            matched_total += 1
        return {
            "names": names,
            "offset": offset,
            "limit": eff_limit,
            "returned": len(names),
            "count": len(names),
            "total": matched_total,
            "truncated": (offset + len(names)) < matched_total,
        }
    return safe_read(_inner)


def get_vtable(ea, max_entries=256):
    """Read vtable at address — follows consecutive function pointers with prototypes and offsets."""
    max_entries = bounded_int(max_entries if max_entries is not None else 256, 'max_entries', 1, 1024)
    def _inner():
        import ida_ida
        is_64 = ida_ida.inf_is_64bit() if hasattr(ida_ida, 'inf_is_64bit') else True
        ptr_size = 8 if is_64 else 4
        entries = []
        current = ea
        for i in range(max_entries):
            ptr = ida_bytes.get_qword(current) if is_64 else ida_bytes.get_dword(current)
            if ptr == 0 or ptr == idc.BADADDR:
                break
            func = ida_funcs.get_func(ptr)
            if not func:
                # Also accept executable code pointers even if function boundaries aren't created yet
                flags = ida_bytes.get_full_flags(ptr) if hasattr(ida_bytes, 'get_full_flags') else ida_bytes.get_flags(ptr)
                if not ida_bytes.is_code(flags):
                    break
            fname = ida_funcs.get_func_name(func.start_ea) if func else (ida_name.get_name(ptr) or f"sub_{ptr:x}")
            demangled = None
            try:
                demangled = ida_name.demangle_name(fname, 0) if hasattr(ida_name, 'demangle_name') else None
            except Exception:
                pass
            proto = None
            tinfo = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(tinfo, ptr):
                proto = str(tinfo)
            entries.append({
                "index": i,
                "offset": hex(i * ptr_size),
                "offset_dec": i * ptr_size,
                "ea": hex(current),
                "target": hex(ptr),
                "target_module_rva": _format_module_rva_inner(ptr),
                "name": fname,
                "demangled": demangled,
                "prototype": proto,
                "func_size": func.size() if func else None,
            })
            current += ptr_size
        return {
            "vtable_ea": hex(ea),
            "vtable_module_rva": _format_module_rva_inner(ea),
            "ptr_size": ptr_size,
            "entries": entries,
            "count": len(entries),
        }
    return safe_read(_inner)


def create_vtable_struct_api(ea, struct_name=None, max_entries=256, name=None):
    """Create or update a C structure with typed function pointer members for a vtable at `ea`."""
    vt = get_vtable(ea, max_entries=max_entries)
    entries = vt.get("entries", [])
    if not entries:
        return {"success": False, "error": f"No valid vtable entries found at {hex(ea)}"}
    sname = (name or struct_name or "").strip() or f"VTable_{ea:X}"
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', sname):
        raise ValueError("Invalid struct name")
    fields = []
    seen_field_names = set()
    for entry in entries:
        idx = entry["index"]
        raw_name = entry.get("name") or f"vfunc_{idx}"
        clean = re.sub(r'[^A-Za-z0-9_]', '_', raw_name).strip('_') or f"vfunc_{idx}"
        if clean[0].isdigit():
            clean = "fn_" + clean
        if clean in seen_field_names:
            clean = f"{clean}_{idx}"
        seen_field_names.add(clean)
        fields.append(f"    void *(*{clean})(void *this);")
    c_decl = f"struct {sname} {{\n" + "\n".join(fields) + "\n};"
    res = create_struct(c_decl)
    res["vtable_ea"] = hex(ea)
    res["struct_name"] = sname
    res["entry_count"] = len(entries)
    res["c_declaration"] = c_decl
    return res


def decompile_batch(ea_list, output_path=None, fmt="json"):
    """Decompile multiple functions at once and optionally save results to a JSON or C file."""
    results = []
    succeeded = 0
    for item in ea_list:
        ea = parse_ea(item) if not isinstance(item, int) else item
        r = get_pseudocode(ea)
        results.append(r)
        if not r.get("error"):
            succeeded += 1
    out = {
        "results": results,
        "count": len(results),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
    }
    if output_path:
        out_path = os.path.abspath(os.path.expanduser(str(output_path)))
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        if str(fmt).lower() == "c" or out_path.lower().endswith((".c", ".cc", ".cpp", ".h")):
            chunks = []
            for r in results:
                chunks.append(f"// === Function: {r.get('name', 'unknown')} @ {r.get('ea', '?')} ===")
                if r.get("error"):
                    chunks.append(f"// ERROR: {r['error']}\n")
                else:
                    chunks.append(r.get("pseudocode", "") + "\n")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(chunks))
        else:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
        out["saved_to"] = out_path
    return out

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

# ─── IDA 9.5 Decompiler & Class Model API ────────────────────────────────────

def get_decompiler_timeout_api():
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays not available"}
    def _inner():
        if not hasattr(ida_hexrays, 'get_decompiler_timeout'):
            return {"supported": False, "timeout_ms": 0}
        return {"supported": True, "timeout_ms": int(ida_hexrays.get_decompiler_timeout())}
    return safe_read(_inner)

def set_decompiler_timeout_api(timeout_ms):
    timeout_ms = bounded_int(timeout_ms, 'timeout_ms', 0, 3600000)
    if not HAS_HEXRAYS:
        return {"error": "Hex-Rays not available"}
    def _inner():
        if not hasattr(ida_hexrays, 'set_decompiler_timeout'):
            return {"error": "set_decompiler_timeout requires IDA 9.5+"}
        prev = ida_hexrays.set_decompiler_timeout(timeout_ms)
        return {"success": True, "timeout_ms": timeout_ms, "previous_ms": int(prev) if prev is not None else 0}
    return safe_write(_inner)

def get_classes_api(filter_pattern=None, toplevel_only=False, include_hidden=False):
    def _inner():
        if HAS_HEXRAYS and hasattr(ida_hexrays, 'get_classes') and hasattr(ida_hexrays, 'classes_t'):
            out = ida_hexrays.classes_t()
            flt = None
            if filter_pattern or toplevel_only or include_hidden:
                flt = ida_hexrays.class_filter_t()
                if filter_pattern:
                    flt.name = str(filter_pattern)
                flags = 0
                if toplevel_only:
                    flags |= getattr(ida_hexrays, 'GCL_TOPLEVEL_ONLY', 1)
                if include_hidden:
                    flags |= getattr(ida_hexrays, 'GCL_INCLUDE_HIDDEN', 2)
                flt.flags = flags
            if ida_hexrays.get_classes(out, flt):
                kind_map = {
                    getattr(ida_hexrays, 'CK_CLASS', 0): 'class',
                    getattr(ida_hexrays, 'CK_STRUCT', 1): 'struct',
                    getattr(ida_hexrays, 'CK_INTERFACE', 2): 'interface',
                    getattr(ida_hexrays, 'CK_ENUM', 3): 'enum',
                    getattr(ida_hexrays, 'CK_UNION', 4): 'union',
                    getattr(ida_hexrays, 'CK_ANNOTATION', 5): 'annotation',
                }
                classes = []
                for i in range(out.size()):
                    c = out.at(i)
                    classes.append({
                        "name": c.name,
                        "outer": c.outer or None,
                        "ea": hex(c.ea) if c.ea != ida_idaapi.BADADDR else None,
                        "kind": kind_map.get(c.kind, str(c.kind)),
                        "flags": int(c.flags),
                        "type": str(c.tif) if c.tif and not c.tif.empty() else None,
                    })
                return {"classes": classes, "count": len(classes), "source": "hexrays_class_model"}
        # Fallback to UDT structures when decompiler class model is not active
        structs = get_structs().get("structs", [])
        if filter_pattern:
            pat = re.compile(filter_pattern.replace('*', '.*').replace('?', '.'), re.IGNORECASE)
            structs = [s for s in structs if s.get("name") and pat.search(s["name"])]
        classes = [
            {
                "name": s["name"],
                "outer": None,
                "ea": None,
                "kind": "union" if s.get("is_union") else "struct",
                "flags": 0,
                "size": s.get("size", 0),
            }
            for s in structs
        ]
        return {"classes": classes, "count": len(classes), "source": "udt_fallback"}
    return safe_read(_inner)

def get_class_details_api(name, ea=None, render=True, no_bodies=False):
    def _inner():
        if HAS_HEXRAYS and hasattr(ida_hexrays, 'get_class_info') and hasattr(ida_hexrays, 'class_info_t'):
            cls = ida_hexrays.class_t()
            cls.name = str(name)
            if ea is not None:
                cls.ea = ea
            info = ida_hexrays.class_info_t()
            if ida_hexrays.get_class_info(info, cls, 0):
                fields = []
                for f in info.fields:
                    fields.append({
                        "name": f.name,
                        "type": f.typestr or str(f.type),
                        "value": f.value or None,
                        "decl": f.decl,
                        "ea": hex(f.ea) if f.ea != ida_idaapi.BADADDR else None,
                        "flags": int(f.flags),
                    })
                methods = []
                for m in info.methods:
                    methods.append({
                        "name": m.name,
                        "type": m.typestr or str(m.type),
                        "decl": m.decl,
                        "ea": hex(m.ea) if m.ea != ida_idaapi.BADADDR else None,
                        "flags": int(m.flags),
                    })
                rendered_code = None
                if render and hasattr(ida_hexrays, 'render_class'):
                    rc_flags = getattr(ida_hexrays, 'RCF_NO_BODIES', 1) if no_bodies else 0
                    ok, lines = ida_hexrays.render_class(info.cls, rc_flags)
                    if ok and lines:
                        rendered_code = "\n".join(lines)
                return {
                    "name": info.cls.name,
                    "ea": hex(info.cls.ea) if info.cls.ea != ida_idaapi.BADADDR else None,
                    "source_file": info.source_file or None,
                    "type_params": info.type_params or None,
                    "supertypes": list(info.supertypes),
                    "interfaces": list(info.interfaces),
                    "attributes": list(info.attrs),
                    "nested": list(info.nested),
                    "header": list(info.decl),
                    "fields": fields,
                    "methods": methods,
                    "rendered": rendered_code,
                    "source": "hexrays_class_model",
                }
        struct_res = get_struct_details(name)
        if not struct_res.get("error"):
            struct_res["source"] = "udt_fallback"
            return struct_res
        return {"error": f"Class '{name}' not found"}
    return safe_read(_inner)

# ─── Debugger API (Extended for IDA 9.5) ─────────────────────────────────────

import collections
import time as _time

_dbg_events = collections.deque(maxlen=500)
_dbg_events_lock = threading.Lock()
_last_dbg_stop_reason = None
_bp_policies = {}  # ea -> {"tid": int|None, "action": str, "auto_continue": bool, "log_regs": list, "hit_count": int, "module_rva": str|None}

def _record_dbg_event(event):
    entry = dict(event)
    entry.setdefault("timestamp", round(_time.time(), 3))
    with _dbg_events_lock:
        _dbg_events.append(entry)
    _publish_event(event)

def _explicit_dbg_status(ida_dbg_mod, state=None):
    """Return explicit debugger status: not_attached, running, paused, or breakpoint_hit."""
    try:
        dbg_on = bool(ida_dbg_mod.is_debugger_on()) if hasattr(ida_dbg_mod, 'is_debugger_on') else False
        if not dbg_on:
            return "not_attached"
        if state is None:
            state = ida_dbg_mod.get_process_state() if hasattr(ida_dbg_mod, 'get_process_state') else -1
        if state == 0:
            return "not_attached"
        if state == 1:
            return "running"
        if state == -1:
            return "breakpoint_hit" if _last_dbg_stop_reason == "breakpoint_hit" else "paused"
        if hasattr(ida_dbg_mod, 'is_debugger_busy') and ida_dbg_mod.is_debugger_busy():
            return "running"
        return "breakpoint_hit" if _last_dbg_stop_reason == "breakpoint_hit" else "paused"
    except Exception:
        return "not_attached"

def _read_regs_inner(ida_dbg_mod, tid=None, include_all=False, reg_names=None):
    """Read live register values (inside safe_read/safe_write) without polluting with None values."""
    import ida_idd
    regs = {}
    rv = ida_idd.regval_t() if hasattr(ida_idd, 'regval_t') else None
    candidates = reg_names or [
        "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","rip","eflags",
        "eax","ebx","ecx","edx","esi","edi","ebp","esp","eip",
        "x0","x1","x2","x3","x4","x5","x6","x7","x8","x19","x20","x29","x30","sp","pc",
    ]
    for name in candidates:
        try:
            if rv is not None and hasattr(ida_dbg_mod, 'get_reg_val') and ida_dbg_mod.get_reg_val(name, rv):
                regs[name] = hex(rv.ival)
            elif hasattr(ida_dbg_mod, 'get_reg_val'):
                val = ida_dbg_mod.get_reg_val(name)
                if isinstance(val, int):
                    regs[name] = hex(val)
        except Exception:
            continue
    if (include_all or not regs) and not reg_names:
        try:
            target_tid = int(tid) if tid is not None else (ida_dbg_mod.get_current_thread() if hasattr(ida_dbg_mod, 'get_current_thread') else 0)
            dbg = ida_idd.get_dbg() if hasattr(ida_idd, 'get_dbg') else None
            if dbg and hasattr(ida_dbg_mod, 'get_reg_vals'):
                regvals = ida_dbg_mod.get_reg_vals(target_tid)
                for ridx, rval_obj in enumerate(regvals):
                    rinfo = dbg.regs(ridx)
                    val = rval_obj.pyval(rinfo.dtype)
                    if isinstance(val, int):
                        regs[rinfo.name] = hex(val)
                    elif isinstance(val, bytes):
                        regs[rinfo.name] = val.hex()
                    elif val is not None:
                        regs[rinfo.name] = str(val)
        except Exception:
            pass
    return regs

def _dbg_available():
    try:
        import ida_dbg
        return ida_dbg is not None
    except Exception:
        return False

def _bpt_const(ida_dbg_mod, name, default):
    if hasattr(ida_dbg_mod, name):
        return getattr(ida_dbg_mod, name)
    try:
        import ida_idd
        if hasattr(ida_idd, name):
            return getattr(ida_idd, name)
    except Exception:
        pass
    if hasattr(idc, name):
        return getattr(idc, name)
    return default

def _auto_select_debugger(ida_dbg_mod):
    """Automatically load the matching local debugger if none is loaded yet."""
    try:
        if hasattr(ida_dbg_mod, 'dbg_is_loaded') and ida_dbg_mod.dbg_is_loaded():
            return True
        if not hasattr(ida_dbg_mod, 'load_debugger'):
            return False
        import ida_ida
        ft = ida_ida.inf_get_filetype() if hasattr(ida_ida, 'inf_get_filetype') else -1
        dbg_name = None
        if hasattr(ida_ida, 'f_PE') and ft == ida_ida.f_PE:
            dbg_name = "win32"
        elif hasattr(ida_ida, 'f_ELF') and ft == ida_ida.f_ELF:
            dbg_name = "linux"
        elif hasattr(ida_ida, 'f_MACHO') and ft == ida_ida.f_MACHO:
            dbg_name = "mac"
        elif os.name == 'nt':
            dbg_name = "win32"
        if dbg_name:
            return bool(ida_dbg_mod.load_debugger(dbg_name, False))
    except Exception:
        pass
    return False

def _dbg_state_name(state):
    if state == -1:
        return "suspended"
    if state == 1:
        return "running"
    if state == 0:
        return "no_process"
    return f"state_{state}"

def _dbg_read_ip_sp(ida_dbg_mod):
    ip_val, sp_val = None, None
    try:
        if hasattr(ida_dbg_mod, 'get_ip_val'):
            v = ida_dbg_mod.get_ip_val()
            if isinstance(v, int):
                ip_val = v
            elif isinstance(v, (list, tuple)) and len(v) >= 2 and v[0]:
                ip_val = v[1]
    except Exception:
        pass
    try:
        if hasattr(ida_dbg_mod, 'get_sp_val'):
            v = ida_dbg_mod.get_sp_val()
            if isinstance(v, int):
                sp_val = v
            elif isinstance(v, (list, tuple)) and len(v) >= 2 and v[0]:
                sp_val = v[1]
    except Exception:
        pass
    if ip_val is None:
        for rname in ("rip", "eip", "pc"):
            try:
                v = ida_dbg_mod.get_reg_val(rname)
                if isinstance(v, int):
                    ip_val = v
                    break
            except Exception:
                continue
    if sp_val is None:
        for rname in ("rsp", "esp", "sp"):
            try:
                v = ida_dbg_mod.get_reg_val(rname)
                if isinstance(v, int):
                    sp_val = v
                    break
            except Exception:
                continue
    return ip_val, sp_val

def _dbg_wait_helper(ida_dbg_mod, timeout_sec=5):
    """Wait for the next debugger suspend event and return snapshot with explicit status and registers."""
    if not hasattr(ida_dbg_mod, 'wait_for_next_event'):
        return {}
    wfne = getattr(ida_dbg_mod, 'WFNE_SUSP', 2) | getattr(ida_dbg_mod, 'WFNE_SILENT', 4)
    code = ida_dbg_mod.wait_for_next_event(wfne, max(1, int(timeout_sec)))
    ip_val, sp_val = _dbg_read_ip_sp(ida_dbg_mod)
    state = ida_dbg_mod.get_process_state() if hasattr(ida_dbg_mod, 'get_process_state') else 0
    status = _explicit_dbg_status(ida_dbg_mod, state)
    snap = {
        "wait_code": int(code) if isinstance(code, int) else str(code),
        "status": status,
        "process_state": state,
        "state_name": _dbg_state_name(state),
        "ip": hex(ip_val) if ip_val is not None else None,
        "ip_module_rva": _format_module_rva_inner(ip_val) if ip_val is not None else None,
        "sp": hex(sp_val) if sp_val is not None else None,
    }
    if state == -1 or status in ("paused", "breakpoint_hit"):
        snap["registers"] = _read_regs_inner(ida_dbg_mod)
    if ip_val is not None:
        try:
            snap["disasm_at_ip"] = idc.generate_disasm_line(ip_val, 0)
            func = ida_funcs.get_func(ip_val)
            snap["func_at_ip"] = ida_funcs.get_func_name(func.start_ea) if func else None
        except Exception:
            pass
    return snap

def dbg_get_status():
    """Return comprehensive live debugger status with explicit status enum."""
    def _inner():
        import ida_dbg
        dbg_on = bool(ida_dbg.is_debugger_on()) if hasattr(ida_dbg, 'is_debugger_on') else False
        dbg_loaded = bool(ida_dbg.dbg_is_loaded()) if hasattr(ida_dbg, 'dbg_is_loaded') else dbg_on
        state = ida_dbg.get_process_state() if hasattr(ida_dbg, 'get_process_state') else 0
        can_query = bool(ida_dbg.dbg_can_query()) if hasattr(ida_dbg, 'dbg_can_query') else False
        busy = bool(ida_dbg.is_debugger_busy()) if hasattr(ida_dbg, 'is_debugger_busy') else False
        dbg_name = None
        try:
            import ida_idd
            dbg_name = ida_idd.dbg_get_name() if hasattr(ida_idd, 'dbg_get_name') else None
        except Exception:
            pass
        tid = ida_dbg.get_current_thread() if (dbg_on and hasattr(ida_dbg, 'get_current_thread')) else None
        tqty = ida_dbg.get_thread_qty() if (dbg_on and hasattr(ida_dbg, 'get_thread_qty')) else 0
        ip_val, sp_val = _dbg_read_ip_sp(ida_dbg) if dbg_on else (None, None)
        func_name, disasm = None, None
        if ip_val is not None:
            try:
                f = ida_funcs.get_func(ip_val)
                func_name = ida_funcs.get_func_name(f.start_ea) if f else None
                disasm = idc.generate_disasm_line(ip_val, 0)
            except Exception:
                pass
        return {
            "status": _explicit_dbg_status(ida_dbg, state),
            "debugger_on": dbg_on,
            "debugger_loaded": dbg_loaded,
            "debugger_name": dbg_name,
            "process_state": state,
            "state_name": _dbg_state_name(state),
            "can_query": can_query,
            "is_busy": busy,
            "current_tid": tid,
            "thread_count": tqty,
            "ip": hex(ip_val) if ip_val is not None else None,
            "ip_module_rva": _format_module_rva_inner(ip_val) if ip_val is not None else None,
            "sp": hex(sp_val) if sp_val is not None else None,
            "current_func": func_name,
            "disasm_at_ip": disasm,
            "step_trace_enabled": bool(ida_dbg.is_step_trace_enabled()) if hasattr(ida_dbg, 'is_step_trace_enabled') else False,
            "insn_trace_enabled": bool(ida_dbg.is_insn_trace_enabled()) if hasattr(ida_dbg, 'is_insn_trace_enabled') else False,
            "func_trace_enabled": bool(ida_dbg.is_func_trace_enabled()) if hasattr(ida_dbg, 'is_func_trace_enabled') else False,
            "bblk_trace_enabled": bool(ida_dbg.is_bblk_trace_enabled()) if hasattr(ida_dbg, 'is_bblk_trace_enabled') else False,
            "tev_count": int(ida_dbg.get_tev_qty()) if hasattr(ida_dbg, 'get_tev_qty') else 0,
        }
    return safe_read(_inner)

def dbg_load_backend(name=None, remote=False, host="", port=-1, password="", use_remote=None, hostname=None):
    """Load a debugger backend (e.g. win32, linux, mac, gdb, windbg, dalvik) and configure remote target."""
    if use_remote is not None:
        remote = bool(use_remote)
    if hostname is not None and not host:
        host = hostname
    def _inner():
        import ida_dbg
        dbg_name = name
        if not dbg_name:
            _auto_select_debugger(ida_dbg)
            try:
                import ida_idd
                dbg_name = ida_idd.dbg_get_name() if hasattr(ida_idd, 'dbg_get_name') else "auto"
            except Exception:
                dbg_name = "auto"
            loaded = bool(ida_dbg.dbg_is_loaded()) if hasattr(ida_dbg, 'dbg_is_loaded') else True
            return {"success": loaded, "debugger": dbg_name, "remote": bool(remote)}
        if (remote or host) and hasattr(ida_dbg, 'set_remote_debugger'):
            ida_dbg.set_remote_debugger(str(host or ""), str(password or ""), int(port if port is not None else -1))
        ok = bool(ida_dbg.load_debugger(str(dbg_name), bool(remote))) if hasattr(ida_dbg, 'load_debugger') else False
        return {"success": ok, "debugger": str(dbg_name), "remote": bool(remote), "host": host or None, "port": port}
    return safe_write(_inner)

def dbg_start_process(path=None, args="", sdir=None):
    def _inner():
        import ida_dbg
        _auto_select_debugger(ida_dbg)
        p = path if path else ida_nalt.get_input_file_path()
        ok = ida_dbg.start_process(p, args, sdir or "")
        return {"success": ok == 1, "code": ok, "path": p, "args": args}
    return safe_write(_inner)

def dbg_exit_process():
    """Terminate the debugged process."""
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        if hasattr(ida_dbg, 'is_debugger_on') and not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        ok = bool(ida_dbg.exit_process()) if hasattr(ida_dbg, 'exit_process') else False
        if ok:
            _last_dbg_stop_reason = None
        return {"success": ok}
    return safe_write(_inner)

def dbg_list_processes():
    """Snapshot running processes available to attach."""
    def _inner():
        import ida_dbg, ida_idd
        _auto_select_debugger(ida_dbg)
        if not hasattr(ida_dbg, 'get_processes') or not hasattr(ida_idd, 'procinfo_vec_t'):
            return {"processes": [], "count": 0}
        proclist = ida_idd.procinfo_vec_t()
        qty = ida_dbg.get_processes(proclist)
        if qty < 0:
            return {"error": "Cannot enumerate processes (debugger backend not ready)", "processes": [], "count": 0}
        procs = []
        for i in range(len(proclist)):
            p = proclist[i]
            procs.append({"pid": int(p.pid), "name": str(p.name)})
        return {"processes": procs, "count": len(procs)}
    return safe_read(_inner)

def dbg_attach_process(pid):
    pid = bounded_int(pid, 'pid', -1, 2 ** 31 - 1)
    def _inner():
        import ida_dbg
        _auto_select_debugger(ida_dbg)
        ok = ida_dbg.attach_process(pid, -1)
        return {"success": ok == 1, "code": ok, "pid": pid}
    return safe_write(_inner)

def dbg_detach():
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        ok = bool(ida_dbg.detach_process())
        if ok:
            _last_dbg_stop_reason = None
        return {"success": ok}
    return safe_write(_inner)

def _resolve_bpt_type(ida_dbg_mod, mode_str, is_hw):
    mode = (mode_str or "").strip().lower()
    if mode in ("write", "w"):
        return _bpt_const(ida_dbg_mod, "BPT_WRITE", 1), True, "write"
    if mode in ("read", "r"):
        return _bpt_const(ida_dbg_mod, "BPT_READ", 2), True, "read"
    if mode in ("rw", "rdwr", "readwrite"):
        return _bpt_const(ida_dbg_mod, "BPT_RDWR", 3), True, "rdwr"
    if mode == "hw_exec":
        return _bpt_const(ida_dbg_mod, "BPT_EXEC", 0), True, "exec"
    if mode in ("exec", "x"):
        if is_hw:
            return _bpt_const(ida_dbg_mod, "BPT_EXEC", 0), True, "exec"
        return _bpt_const(ida_dbg_mod, "BPT_SOFT", 4), False, "soft"
    if mode in ("soft", "sw", "software"):
        return _bpt_const(ida_dbg_mod, "BPT_SOFT", 4), False, "soft"
    if is_hw:
        return _bpt_const(ida_dbg_mod, "BPT_EXEC", 0), True, "exec"
    return _bpt_const(ida_dbg_mod, "BPT_SOFT", 4), False, "soft"

def dbg_set_bp(ea, is_hw=False, bp_type=None, size=0, condition=None, elang="Python", pass_count=0,
               trace_only=False, enabled=True, hardware=None, mode=None, tid=None, action=None,
               auto_continue=False, log_regs=None):
    if hardware is not None:
        is_hw = bool(hardware)
    if mode is not None and bp_type is None:
        bp_type = mode
    if size:
        size = bounded_int(size, 'breakpoint size', 0, 64)
    if pass_count:
        pass_count = bounded_int(pass_count, 'pass_count', 0, 2 ** 31 - 1)
    if tid is not None:
        tid = bounded_int(tid, 'tid', 0, 2 ** 31 - 1)
    act_norm = (action or ("log_and_continue" if auto_continue else "stop")).strip().lower()
    if act_norm in ("log_and_continue", "log_continue", "continue", "auto_continue"):
        auto_continue = True
        act_norm = "log_and_continue"
    else:
        act_norm = "stop"
    if isinstance(log_regs, str):
        log_regs = [r.strip() for r in log_regs.split(",") if r.strip()]
    elif isinstance(log_regs, (list, tuple)):
        log_regs = [str(r).strip() for r in log_regs if str(r).strip()]
    else:
        log_regs = []
    def _inner():
        import ida_dbg
        btype, hw_flag, mode_name = _resolve_bpt_type(ida_dbg, bp_type, is_hw)
        bp_size = size if size > 0 else (1 if hw_flag else 0)
        # Keep exact 3-arg or 1-arg add_bpt call when default software/hw exec is used
        if hw_flag or (bp_type and str(bp_type).lower() not in ("exec", "x", "soft", "sw", "software")) or size > 1:
            ok = bool(ida_dbg.add_bpt(ea, bp_size, btype))
        else:
            ok = bool(ida_dbg.add_bpt(ea))
        if ok and (condition or pass_count > 0 or trace_only or not enabled):
            if hasattr(ida_dbg, 'bpt_t') and hasattr(ida_dbg, 'get_bpt') and hasattr(ida_dbg, 'update_bpt'):
                bp = ida_dbg.bpt_t()
                if ida_dbg.get_bpt(ea, bp):
                    if condition is not None:
                        bp.condition = str(condition)
                        if elang:
                            bp.elang = str(elang)
                    if pass_count > 0:
                        bp.pass_count = int(pass_count)
                    if trace_only:
                        bpt_trace = getattr(ida_dbg, 'BPT_TRACE', 2)
                        bpt_brk = getattr(ida_dbg, 'BPT_BRK', 1)
                        bp.flags = (bp.flags | bpt_trace) & ~bpt_brk
                    if not enabled:
                        bpt_enabled = getattr(ida_dbg, 'BPT_ENABLED', 8)
                        bp.flags &= ~bpt_enabled
                    ida_dbg.update_bpt(bp)
        mod_rva = _format_module_rva_inner(ea)
        if ok:
            prev = _bp_policies.get(ea, {})
            _bp_policies[ea] = {
                "tid": tid,
                "action": act_norm,
                "auto_continue": bool(auto_continue),
                "log_regs": log_regs,
                "hit_count": int(prev.get("hit_count", 0)),
                "module_rva": mod_rva,
            }
        return {
            "success": ok,
            "ea": hex(ea),
            "module_rva": mod_rva,
            "hardware": hw_flag,
            "mode": mode_name,
            "size": bp_size,
            "condition": condition,
            "pass_count": pass_count,
            "trace_only": bool(trace_only),
            "enabled": bool(enabled),
            "tid": tid,
            "action": act_norm,
            "auto_continue": bool(auto_continue),
            "log_regs": log_regs,
        }
    return safe_write(_inner)

def dbg_del_bp(ea):
    def _inner():
        import ida_dbg
        ok = bool(ida_dbg.del_bpt(ea))
        _bp_policies.pop(ea, None)
        return {"success": ok, "ea": hex(ea), "module_rva": _format_module_rva_inner(ea)}
    return safe_write(_inner)

def dbg_toggle_bp(ea, enabled=True, enable=None):
    if enable is not None:
        enabled = bool(enable)
    def _inner():
        import ida_dbg
        if bool(enabled):
            ok = bool(ida_dbg.enable_bpt(ea, True) if hasattr(ida_dbg, 'enable_bpt') else False)
        else:
            if hasattr(ida_dbg, 'disable_bpt'):
                ok = bool(ida_dbg.disable_bpt(ea))
            elif hasattr(ida_dbg, 'enable_bpt'):
                ok = bool(ida_dbg.enable_bpt(ea, False))
            else:
                ok = False
        return {"success": ok, "ea": hex(ea), "module_rva": _format_module_rva_inner(ea), "enabled": bool(enabled)}
    return safe_write(_inner)

def dbg_update_bp(ea, condition=None, elang=None, pass_count=None, trace_only=None, enabled=None,
                  mode=None, size=None, tid=None, action=None, auto_continue=None, log_regs=None):
    if pass_count is not None:
        pass_count = bounded_int(pass_count, 'pass_count', 0, 2 ** 31 - 1)
    if size is not None:
        size = bounded_int(size, 'breakpoint size', 0, 64)
    if tid is not None and tid != -1:
        tid = bounded_int(tid, 'tid', 0, 2 ** 31 - 1)
    def _inner():
        import ida_dbg
        if not (hasattr(ida_dbg, 'bpt_t') and hasattr(ida_dbg, 'get_bpt') and hasattr(ida_dbg, 'update_bpt')):
            return {"error": "Breakpoint update API not available"}
        bp = ida_dbg.bpt_t()
        if not ida_dbg.get_bpt(ea, bp):
            return {"error": f"No breakpoint found at {hex(ea)}"}
        if condition is not None:
            bp.condition = str(condition)
        if elang is not None:
            bp.elang = str(elang)
        if pass_count is not None:
            bp.pass_count = int(pass_count)
        if mode is not None:
            btype, _, _ = _resolve_bpt_type(ida_dbg, mode, True)
            bp.type = btype
        if size is not None and size > 0:
            bp.size = int(size)
        if trace_only is not None:
            bpt_trace = getattr(ida_dbg, 'BPT_TRACE', 2)
            bpt_brk = getattr(ida_dbg, 'BPT_BRK', 1)
            if trace_only:
                bp.flags = (bp.flags | bpt_trace) & ~bpt_brk
            else:
                bp.flags = (bp.flags | bpt_brk) & ~bpt_trace
        if enabled is not None:
            bpt_enabled = getattr(ida_dbg, 'BPT_ENABLED', 8)
            if enabled:
                bp.flags |= bpt_enabled
            else:
                bp.flags &= ~bpt_enabled
        ok = bool(ida_dbg.update_bpt(bp))
        pol = _bp_policies.setdefault(ea, {
            "tid": None, "action": "stop", "auto_continue": False,
            "log_regs": [], "hit_count": 0, "module_rva": _format_module_rva_inner(ea)
        })
        if tid is not None:
            pol["tid"] = None if tid == -1 else tid
        if action is not None:
            act_norm = str(action).strip().lower()
            pol["action"] = "log_and_continue" if act_norm in ("log_and_continue", "log_continue", "continue", "auto_continue") else "stop"
            pol["auto_continue"] = pol["action"] == "log_and_continue"
        if auto_continue is not None:
            pol["auto_continue"] = bool(auto_continue)
            pol["action"] = "log_and_continue" if pol["auto_continue"] else "stop"
        if log_regs is not None:
            if isinstance(log_regs, str):
                pol["log_regs"] = [r.strip() for r in log_regs.split(",") if r.strip()]
            elif isinstance(log_regs, (list, tuple)):
                pol["log_regs"] = [str(r).strip() for r in log_regs if str(r).strip()]
        return {
            "success": ok,
            "ea": hex(ea),
            "module_rva": pol.get("module_rva") or _format_module_rva_inner(ea),
            "condition": getattr(bp, 'condition', None),
            "pass_count": getattr(bp, 'pass_count', 0),
            "enabled": bool(bp.flags & getattr(ida_dbg, 'BPT_ENABLED', 8)),
            "tid": pol.get("tid"),
            "action": pol.get("action", "stop"),
            "auto_continue": bool(pol.get("auto_continue", False)),
            "log_regs": pol.get("log_regs", []),
            "hit_count": pol.get("hit_count", 0),
        }
    return safe_write(_inner)

def dbg_list_bps():
    def _inner():
        import ida_dbg
        type_names = {
            _bpt_const(ida_dbg, "BPT_EXEC", 0): "exec",
            _bpt_const(ida_dbg, "BPT_WRITE", 1): "write",
            _bpt_const(ida_dbg, "BPT_READ", 2): "read",
            _bpt_const(ida_dbg, "BPT_RDWR", 3): "rdwr",
            _bpt_const(ida_dbg, "BPT_SOFT", 4): "soft",
        }
        bps = []
        qty = ida_dbg.get_bpt_qty() if hasattr(ida_dbg, 'get_bpt_qty') else 0
        for i in range(qty):
            bp = ida_dbg.bpt_t()
            if ida_dbg.getn_bpt(i, bp):
                bpt_enabled = getattr(ida_dbg, 'BPT_ENABLED', 8)
                bpt_trace = getattr(ida_dbg, 'BPT_TRACE', 2)
                bpt_brk = getattr(ida_dbg, 'BPT_BRK', 1)
                is_hw = bool(bp.is_hwbpt()) if hasattr(bp, 'is_hwbpt') else (bp.type != _bpt_const(ida_dbg, "BPT_SOFT", 4))
                pol = _bp_policies.get(bp.ea, {})
                bps.append({
                    "ea": hex(bp.ea),
                    "module_rva": pol.get("module_rva") or _format_module_rva_inner(bp.ea),
                    "size": bp.size,
                    "type": bp.type,
                    "type_name": type_names.get(bp.type, f"type_{bp.type}"),
                    "hardware": is_hw,
                    "enabled": bool(bp.flags & bpt_enabled),
                    "pass_count": getattr(bp, 'pass_count', 0),
                    "hit_count": int(pol.get("hit_count", 0)),
                    "condition": getattr(bp, 'condition', "") or "",
                    "elang": getattr(bp, 'elang', "") or "",
                    "trace_only": bool((bp.flags & bpt_trace) and not (bp.flags & bpt_brk)),
                    "tid": pol.get("tid"),
                    "action": pol.get("action", "stop"),
                    "auto_continue": bool(pol.get("auto_continue", False)),
                    "log_regs": pol.get("log_regs", []),
                })
        return {"breakpoints": bps, "count": len(bps)}
    return safe_read(_inner)

def dbg_export_bps(output_path=None):
    """Export all current breakpoints (including module+RVA, conditions, and hit actions) to JSON."""
    res = dbg_list_bps()
    payload = {
        "version": BRIDGE_VERSION,
        "exported_at": round(_time.time(), 3),
        "count": res.get("count", 0),
        "breakpoints": res.get("breakpoints", []),
    }
    if output_path:
        out_file = os.path.abspath(os.path.expanduser(str(output_path)))
        out_dir = os.path.dirname(out_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        payload["saved_to"] = out_file
    return payload

def dbg_import_bps(breakpoints=None, input_path=None, clear_existing=False):
    """Restore a set of breakpoints from a list or JSON file, resolving module+RVA across ASLR."""
    if input_path:
        in_file = os.path.abspath(os.path.expanduser(str(input_path)))
        if not os.path.isfile(in_file):
            return {"error": f"Breakpoint file not found: {in_file}"}
        with open(in_file, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            breakpoints = loaded.get("breakpoints", [])
        elif isinstance(loaded, list):
            breakpoints = loaded
    if not isinstance(breakpoints, list):
        raise ValueError("breakpoints must be a list or loaded via input_path")
    if clear_existing:
        existing = dbg_list_bps().get("breakpoints", [])
        for item in existing:
            try:
                dbg_del_bp(parse_ea(item["ea"]))
            except Exception:
                pass
    restored = []
    errors = []
    for item in breakpoints:
        if not isinstance(item, dict):
            continue
        addr_spec = item.get("module_rva") or item.get("ea")
        if not addr_spec:
            continue
        try:
            try:
                target_ea = parse_ea(addr_spec)
            except Exception:
                target_ea = parse_ea(item.get("ea", "0"))
            bp_res = dbg_set_bp(
                target_ea,
                hardware=item.get("hardware", False),
                mode=item.get("type_name") or item.get("mode") or "exec",
                size=item.get("size", 1),
                condition=item.get("condition") or "",
                elang=item.get("elang") or "Python",
                pass_count=item.get("pass_count", 0),
                trace_only=item.get("trace_only", False),
                enabled=item.get("enabled", True),
                tid=item.get("tid"),
                action=item.get("action", "stop"),
                auto_continue=item.get("auto_continue", False),
                log_regs=item.get("log_regs", []),
            )
            restored.append(bp_res)
        except Exception as exc:
            errors.append({"target": str(addr_spec), "error": str(exc)})
    return {
        "success": len(errors) == 0,
        "restored": restored,
        "restored_count": len(restored),
        "errors": errors,
    }

def dbg_step_into_api(wait=False, timeout=5):
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = "paused"
        ok = bool(ida_dbg.step_into())
        res = {"success": ok}
        if ok and wait:
            res.update(_dbg_wait_helper(ida_dbg, timeout))
        return res
    return safe_write(_inner)

def dbg_step_over_api(wait=False, timeout=5):
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = "paused"
        ok = bool(ida_dbg.step_over())
        res = {"success": ok}
        if ok and wait:
            res.update(_dbg_wait_helper(ida_dbg, timeout))
        return res
    return safe_write(_inner)

def dbg_step_out_api(wait=False, timeout=5):
    """Step until current function returns (step_until_ret)."""
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = "paused"
        ok = bool(ida_dbg.step_until_ret()) if hasattr(ida_dbg, 'step_until_ret') else False
        res = {"success": ok}
        if ok and wait:
            res.update(_dbg_wait_helper(ida_dbg, timeout))
        return res
    return safe_write(_inner)

def dbg_run_to_api(ea, pid=-1, tid=0, wait=False, timeout=10):
    """Run execution until address ea."""
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = "paused"
        _auto_select_debugger(ida_dbg)
        ok = bool(ida_dbg.run_to(ea)) if hasattr(ida_dbg, 'run_to') else False
        res = {"success": ok, "target_ea": hex(ea), "target_module_rva": _format_module_rva_inner(ea)}
        if ok and wait:
            res.update(_dbg_wait_helper(ida_dbg, timeout))
        return res
    return safe_write(_inner)

def dbg_continue_api(wait=False, timeout=10):
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = None
        ok = bool(ida_dbg.continue_process())
        res = {"success": ok}
        if ok and wait:
            res.update(_dbg_wait_helper(ida_dbg, timeout))
        return res
    return safe_write(_inner)

def dbg_pause_api():
    def _inner():
        global _last_dbg_stop_reason
        import ida_dbg
        _last_dbg_stop_reason = "paused"
        ok = bool(ida_dbg.suspend_process())
        return {"success": ok, "status": "paused" if ok else _explicit_dbg_status(ida_dbg)}
    return safe_write(_inner)

def dbg_wait_event(timeout=5, resume=False, wait_for_suspend=True, silent=True, wfne=None):
    """Wait synchronously for the next debugger event."""
    timeout = bounded_int(timeout, 'timeout', 0, 300)
    def _inner():
        import ida_dbg, ida_idd
        if not hasattr(ida_dbg, 'wait_for_next_event'):
            return {"error": "wait_for_next_event is not available"}
        if wfne is not None:
            wfne_flags = int(wfne)
        else:
            wfne_flags = 0
            if wait_for_suspend:
                wfne_flags |= getattr(ida_dbg, 'WFNE_SUSP', 2)
            else:
                wfne_flags |= getattr(ida_dbg, 'WFNE_ANY', 1)
            if silent:
                wfne_flags |= getattr(ida_dbg, 'WFNE_SILENT', 4)
            if resume:
                wfne_flags |= getattr(ida_dbg, 'WFNE_CONT', 8)
            if timeout == 0:
                wfne_flags |= getattr(ida_dbg, 'WFNE_NOWAIT', 16)
        code = ida_dbg.wait_for_next_event(wfne_flags, timeout)
        state = ida_dbg.get_process_state() if hasattr(ida_dbg, 'get_process_state') else 0
        status = _explicit_dbg_status(ida_dbg, state)
        ip_val, sp_val = _dbg_read_ip_sp(ida_dbg)
        out = {
            "success": isinstance(code, int) and code > 0,
            "status": status,
            "event_code": int(code) if isinstance(code, int) else str(code),
            "timed_out": code == 0 or code == getattr(ida_dbg, 'DEC_TIMEOUT', -2),
            "process_state": state,
            "state_name": _dbg_state_name(state),
            "ip": hex(ip_val) if ip_val is not None else None,
            "ip_module_rva": _format_module_rva_inner(ip_val) if ip_val is not None else None,
            "sp": hex(sp_val) if sp_val is not None else None,
        }
        if state == -1 or status in ("paused", "breakpoint_hit"):
            out["registers"] = _read_regs_inner(ida_dbg)
        if ip_val is not None:
            try:
                out["disasm_at_ip"] = idc.generate_disasm_line(ip_val, 0)
                f = ida_funcs.get_func(ip_val)
                out["func_at_ip"] = ida_funcs.get_func_name(f.start_ea) if f else None
            except Exception:
                pass
        if isinstance(code, int) and code > 0 and hasattr(ida_dbg, 'get_debug_event'):
            try:
                ev = ida_dbg.get_debug_event()
                if ev:
                    out["event"] = {
                        "eid": int(ev.eid()),
                        "event_name": ida_idd.get_debug_event_name(ev) if hasattr(ida_idd, 'get_debug_event_name') else str(ev.eid()),
                        "pid": int(ev.pid),
                        "tid": int(ev.tid),
                        "ea": hex(ev.ea) if ev.ea != ida_idaapi.BADADDR else None,
                        "handled": bool(ev.handled),
                    }
                    if hasattr(ida_idd, 'get_event_exc_code') and ev.eid() == getattr(ida_idd, 'EXCEPTION', 0x20):
                        out["event"]["exc_code"] = hex(ida_idd.get_event_exc_code(ev))
                        out["event"]["exc_ea"] = hex(ida_idd.get_event_exc_ea(ev))
                        out["event"]["exc_info"] = ida_idd.get_event_exc_info(ev)
            except Exception:
                pass
        return out
    return safe_write(_inner)

def dbg_get_regs(tid=None, include_all=False):
    def _inner():
        import ida_dbg
        state = ida_dbg.get_process_state() if hasattr(ida_dbg, 'get_process_state') else 0
        status = _explicit_dbg_status(ida_dbg, state)
        if status == "not_attached":
            return {"status": "not_attached", "registers": {}, "message": "No active debugger"}
        if status == "running":
            return {"status": "running", "registers": {}, "message": "Process is currently running (not suspended)"}
        if tid is not None and hasattr(ida_dbg, 'select_thread'):
            try:
                ida_dbg.select_thread(int(tid))
            except Exception:
                pass
        regs = _read_regs_inner(ida_dbg, tid=tid, include_all=include_all)
        ip_val, sp_val = _dbg_read_ip_sp(ida_dbg)
        cur_tid = ida_dbg.get_current_thread() if hasattr(ida_dbg, 'get_current_thread') else tid
        res = {
            "status": status,
            "current_tid": cur_tid,
            "registers": regs,
        }
        if ip_val is not None:
            res["ip"] = hex(ip_val)
            res["ip_module_rva"] = _format_module_rva_inner(ip_val)
        if sp_val is not None:
            res["sp"] = hex(sp_val)
        return res
    return safe_read(_inner)

def dbg_set_reg(name, value, tid=None):
    """Set CPU register value in the active debugger."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Register name must be a non-empty string")
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("Register value must be an int or hex string")
    int_val = int(value.strip(), 0) if isinstance(value, str) else int(value)
    def _inner():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if tid is not None and hasattr(ida_dbg, 'select_thread'):
            ida_dbg.select_thread(int(tid))
        ok = bool(ida_dbg.set_reg_val(name.strip(), int_val))
        readback = None
        try:
            rb = ida_dbg.get_reg_val(name.strip())
            if isinstance(rb, int):
                readback = hex(rb)
        except Exception:
            pass
        return {"success": ok, "register": name.strip(), "value": hex(int_val), "readback": readback}
    return safe_write(_inner)

def dbg_read_mem(ea, size):
    size = bounded_int(size, 'memory read size', 1, MAX_TRANSFER)
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        data = ida_idd.dbg_read_memory(ea, size)
        if not data:
            return {"error": f"Cannot read {size} bytes at {hex(ea)}"}
        ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:256])
        return {"ea": hex(ea), "size": len(data), "hex": ' '.join(f'{b:02X}' for b in data), "ascii": ascii_preview}
    return safe_read(_inner)

def dbg_write_mem(ea, hex_bytes):
    data = bytes.fromhex(hex_bytes)
    bounded_int(len(data), 'memory write size', 1, MAX_TRANSFER)
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        ok = ida_idd.dbg_write_memory(ea, data)
        if type(ok) is bool:
            written = len(data) if ok else 0
            success = ok
        else:
            written = int(ok) if isinstance(ok, int) else 0
            success = (ok == len(data))
        return {"success": success, "ea": hex(ea), "size": len(data), "written": written}
    return safe_write(_inner)

def dbg_get_modules():
    """List loaded modules/DLLs/shared libraries in the debugged process."""
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        modules = []
        if hasattr(ida_idd, 'modinfo_t') and hasattr(ida_dbg, 'get_first_module'):
            mod = ida_idd.modinfo_t()
            ok = ida_dbg.get_first_module(mod)
            while ok:
                modules.append({
                    "name": mod.name,
                    "base": hex(mod.base) if mod.base != ida_idaapi.BADADDR else None,
                    "size": int(mod.size),
                    "end": hex(mod.base + mod.size) if mod.base != ida_idaapi.BADADDR and mod.size else None,
                    "rebase_to": hex(mod.rebase_to) if getattr(mod, 'rebase_to', ida_idaapi.BADADDR) != ida_idaapi.BADADDR else None,
                })
                ok = ida_dbg.get_next_module(mod)
        return {"modules": modules, "count": len(modules)}
    return safe_read(_inner)

def dbg_get_memory_map(refresh=False):
    """Retrieve live process virtual memory regions and permissions."""
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if refresh and hasattr(ida_dbg, 'refresh_debugger_memory'):
            try:
                ida_dbg.refresh_debugger_memory()
            except Exception:
                pass
        regions = []
        if hasattr(ida_idd, 'meminfo_vec_t') and hasattr(ida_dbg, 'get_dbg_memory_info'):
            ranges = ida_idd.meminfo_vec_t()
            if ida_dbg.get_dbg_memory_info(ranges) > 0:
                for m in ranges:
                    perm_str = (
                        f"{'r' if m.perm & ida_segment.SEGPERM_READ else '-'}"
                        f"{'w' if m.perm & ida_segment.SEGPERM_WRITE else '-'}"
                        f"{'x' if m.perm & ida_segment.SEGPERM_EXEC else '-'}"
                    )
                    regions.append({
                        "start": hex(m.start_ea),
                        "end": hex(m.end_ea),
                        "size": int(m.end_ea - m.start_ea),
                        "name": m.name or "",
                        "sclass": m.sclass or "",
                        "perm": perm_str,
                        "bitness": {0: 16, 1: 32, 2: 64}.get(getattr(m, 'bitness', 2), 64),
                    })
        elif hasattr(ida_idd, 'dbg_get_memory_info'):
            raw = ida_idd.dbg_get_memory_info() or []
            for item in raw:
                start_ea, end_ea, mname, sclass, _sbase, bitness, perm = item
                perm_str = f"{'r' if perm & 4 else '-'}{'w' if perm & 2 else '-'}{'x' if perm & 1 else '-'}"
                regions.append({
                    "start": hex(start_ea),
                    "end": hex(end_ea),
                    "size": int(end_ea - start_ea),
                    "name": mname or "",
                    "sclass": sclass or "",
                    "perm": perm_str,
                    "bitness": {0: 16, 1: 32, 2: 64}.get(bitness, 64),
                })
        return {"regions": regions, "count": len(regions)}
    return safe_read(_inner)

def dbg_refresh_memory_api():
    """Force IDA to refresh debugger memory layout and contents."""
    def _inner():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if hasattr(ida_dbg, 'invalidate_dbgmem_config'):
            ida_dbg.invalidate_dbgmem_config()
        if hasattr(ida_dbg, 'invalidate_dbgmem_contents'):
            ida_dbg.invalidate_dbgmem_contents(0, ida_idaapi.BADADDR)
        if hasattr(ida_dbg, 'refresh_debugger_memory'):
            ida_dbg.refresh_debugger_memory()
        return {"success": True}
    return safe_write(_inner)

def _compile_wildcard_bytes(pattern_str):
    tokens = pattern_str.strip().split()
    # If not valid hex/wildcard tokens, treat as UTF-8 string bytes
    if not tokens or not all(t in ('?', '??') or re.fullmatch(r'[0-9a-fA-F]{2}', t) for t in tokens):
        raw = pattern_str.encode('utf-8')
        return re.compile(re.escape(raw), re.DOTALL)
    regex_parts = []
    for t in tokens:
        if t in ('?', '??'):
            regex_parts.append(b'.')
        else:
            regex_parts.append(re.escape(bytes([int(t, 16)])))
    return re.compile(b''.join(regex_parts), re.DOTALL)

def dbg_search_memory_api(pattern, start_ea=None, end_ea=None, max_results=50):
    """Search live process memory for hex pattern (with ?? wildcards) or string."""
    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError("pattern must be a non-empty string")
    max_results = bounded_int(max_results, 'max_results', 1, 500)
    compiled = _compile_wildcard_bytes(pattern)
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        scan_ranges = []
        if start_ea is not None and end_ea is not None and end_ea > start_ea:
            scan_ranges.append((start_ea, min(end_ea, start_ea + 64 * 1024 * 1024)))
        else:
            mmap = dbg_get_memory_map().get("regions", [])
            for reg in mmap:
                if 'r' not in reg.get("perm", ""):
                    continue
                s = int(reg["start"], 16)
                e = int(reg["end"], 16)
                if start_ea is not None and e <= start_ea:
                    continue
                if end_ea is not None and s >= end_ea:
                    continue
                s = max(s, start_ea) if start_ea is not None else s
                e = min(e, end_ea) if end_ea is not None else e
                if 0 < e - s <= 16 * 1024 * 1024:
                    scan_ranges.append((s, e))
        matches = []
        chunk_size = 256 * 1024
        for r_start, r_end in scan_ranges:
            cur = r_start
            while cur < r_end and len(matches) < max_results:
                read_len = min(chunk_size, r_end - cur)
                buf = ida_idd.dbg_read_memory(cur, read_len)
                if buf:
                    for m in compiled.finditer(buf):
                        hit_ea = cur + m.start()
                        func = ida_funcs.get_func(hit_ea)
                        matches.append({
                            "ea": hex(hit_ea),
                            "bytes": buf[m.start():m.end()].hex().upper(),
                            "func": ida_funcs.get_func_name(func.start_ea) if func else None,
                        })
                        if len(matches) >= max_results:
                            break
                cur += read_len
        return {"pattern": pattern, "results": matches, "count": len(matches)}
    return safe_read(_inner)

def dbg_get_threads():
    def _inner():
        import ida_dbg
        threads = []
        cur_tid = ida_dbg.get_current_thread() if hasattr(ida_dbg, 'get_current_thread') else None
        for i in range(ida_dbg.get_thread_qty()):
            tid = ida_dbg.getn_thread(i)
            # IDA 9.5 uses getn_thread_name(i) instead of removed get_thread_name(tid)
            if hasattr(ida_dbg, 'getn_thread_name'):
                name = ida_dbg.getn_thread_name(i)
            elif hasattr(ida_dbg, 'get_thread_name'):
                name = ida_dbg.get_thread_name(tid)
            else:
                name = ""
            threads.append({"tid": tid, "name": name or "", "is_current": tid == cur_tid})
        return {"threads": threads, "current_tid": cur_tid, "count": len(threads)}
    return safe_read(_inner)

def dbg_thread_control(tid, action="select"):
    """Select, suspend, or resume a thread by TID."""
    tid = bounded_int(tid, 'tid', 0, 2 ** 31 - 1)
    act = (action or "").strip().lower()
    if act not in ("select", "suspend", "resume"):
        raise ValueError("action must be 'select', 'suspend', or 'resume'")
    def _inner():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if act == "select":
            ok = bool(ida_dbg.select_thread(tid))
        elif act == "suspend":
            ok = ida_dbg.suspend_thread(tid) >= 0
        else:
            ok = ida_dbg.resume_thread(tid) >= 0
        return {"success": ok, "tid": tid, "action": act}
    return safe_write(_inner)

def dbg_get_stack():
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        trace = ida_idd.call_stack_t()
        ok = ida_dbg.collect_stack_trace(ida_dbg.get_current_thread(), trace)
        if not ok:
            return {"error": "Cannot get call stack"}
        frames = []
        for i in range(len(trace)):
            f = trace[i]
            func = ida_funcs.get_func(f.funcea) if f.funcea != ida_idaapi.BADADDR else None
            func_name = ida_funcs.get_func_name(func.start_ea) if func else (ida_name.get_name(f.callea) or None)
            mod_name = None
            if hasattr(ida_idd, 'modinfo_t') and hasattr(ida_dbg, 'get_module_info'):
                mi = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(f.callea, mi):
                    mod_name = os.path.basename(mi.name) if mi.name else None
            frames.append({
                "index": i,
                "caller": hex(f.callea),
                "func": hex(f.funcea),
                "func_name": func_name,
                "module": mod_name,
                "fp": hex(f.fp),
            })
        return {"stack": frames, "count": len(frames)}
    return safe_read(_inner)

def dbg_configure_trace_api(mode=None, enabled=True, trace_size=None, options=None, insn=None, func=None, bblk=None, step=None, buf_size=None):
    """Enable/disable execution tracing (insn, func, bblk, step)."""
    if buf_size is not None and trace_size is None:
        trace_size = buf_size
    if trace_size is not None:
        trace_size = bounded_int(trace_size, 'trace_size', 0, 1000000)
    def _inner():
        import ida_dbg
        if trace_size is not None and hasattr(ida_dbg, 'set_trace_size'):
            ida_dbg.set_trace_size(trace_size)
        # Support multi-flag dict-style calls (insn=..., func=..., bblk=..., step=...)
        if any(v is not None for v in (insn, func, bblk, step)):
            if insn is not None:
                if insn and hasattr(ida_dbg, 'enable_insn_trace'):
                    ida_dbg.enable_insn_trace(True)
                elif not insn and hasattr(ida_dbg, 'disable_insn_trace'):
                    ida_dbg.disable_insn_trace()
            if func is not None:
                if func and hasattr(ida_dbg, 'enable_func_trace'):
                    ida_dbg.enable_func_trace(True)
                elif not func and hasattr(ida_dbg, 'disable_func_trace'):
                    ida_dbg.disable_func_trace()
            if bblk is not None:
                if bblk and hasattr(ida_dbg, 'enable_bblk_trace'):
                    ida_dbg.enable_bblk_trace(True)
                elif not bblk and hasattr(ida_dbg, 'disable_bblk_trace'):
                    ida_dbg.disable_bblk_trace()
            if step is not None:
                if step and hasattr(ida_dbg, 'enable_step_trace'):
                    ida_dbg.enable_step_trace(1)
                elif not step and hasattr(ida_dbg, 'disable_step_trace'):
                    ida_dbg.disable_step_trace()
            return {
                "success": True,
                "insn_trace": bool(ida_dbg.is_insn_trace_enabled()) if hasattr(ida_dbg, 'is_insn_trace_enabled') else bool(insn),
                "func_trace": bool(ida_dbg.is_func_trace_enabled()) if hasattr(ida_dbg, 'is_func_trace_enabled') else bool(func),
                "bblk_trace": bool(ida_dbg.is_bblk_trace_enabled()) if hasattr(ida_dbg, 'is_bblk_trace_enabled') else bool(bblk),
                "step_trace": bool(ida_dbg.is_step_trace_enabled()) if hasattr(ida_dbg, 'is_step_trace_enabled') else bool(step),
                "trace_size": trace_size,
            }
        mode_norm = (mode or "insn").strip().lower()
        if mode_norm not in ("insn", "func", "bblk", "step"):
            raise ValueError("mode must be 'insn', 'func', 'bblk', or 'step'")
        ok = False
        if mode_norm == "insn":
            if enabled and hasattr(ida_dbg, 'enable_insn_trace'):
                ok = bool(ida_dbg.enable_insn_trace(True))
            elif not enabled and hasattr(ida_dbg, 'disable_insn_trace'):
                ok = bool(ida_dbg.disable_insn_trace())
            if options is not None and hasattr(ida_dbg, 'set_insn_trace_options'):
                ida_dbg.set_insn_trace_options(int(options))
        elif mode_norm == "func":
            if enabled and hasattr(ida_dbg, 'enable_func_trace'):
                ok = bool(ida_dbg.enable_func_trace(True))
            elif not enabled and hasattr(ida_dbg, 'disable_func_trace'):
                ok = bool(ida_dbg.disable_func_trace())
            if options is not None and hasattr(ida_dbg, 'set_func_trace_options'):
                ida_dbg.set_func_trace_options(int(options))
        elif mode_norm == "bblk":
            if enabled and hasattr(ida_dbg, 'enable_bblk_trace'):
                ok = bool(ida_dbg.enable_bblk_trace(True))
            elif not enabled and hasattr(ida_dbg, 'disable_bblk_trace'):
                ok = bool(ida_dbg.disable_bblk_trace())
            if options is not None and hasattr(ida_dbg, 'set_bblk_trace_options'):
                ida_dbg.set_bblk_trace_options(int(options))
        elif mode_norm == "step":
            if enabled and hasattr(ida_dbg, 'enable_step_trace'):
                ok = bool(ida_dbg.enable_step_trace(1))
            elif not enabled and hasattr(ida_dbg, 'disable_step_trace'):
                ok = bool(ida_dbg.disable_step_trace())
            if options is not None and hasattr(ida_dbg, 'set_step_trace_options'):
                ida_dbg.set_step_trace_options(int(options))
        return {"success": ok, "mode": mode_norm, "enabled": bool(enabled), "trace_size": trace_size}
    return safe_write(_inner)

def dbg_get_trace_events(offset=0, limit=200, count=None):
    """Retrieve recorded trace events from IDA's trace buffer."""
    if count is not None:
        limit = count
    offset = bounded_int(offset, 'offset', 0, 2 ** 31 - 1)
    limit = bounded_int(limit, 'limit', 1, 2000)
    def _inner():
        import ida_dbg
        qty = int(ida_dbg.get_tev_qty()) if hasattr(ida_dbg, 'get_tev_qty') else 0
        tev_names = {
            getattr(ida_dbg, 'tev_none', 0): "none",
            getattr(ida_dbg, 'tev_insn', 1): "insn",
            getattr(ida_dbg, 'tev_call', 2): "call",
            getattr(ida_dbg, 'tev_ret', 3): "ret",
            getattr(ida_dbg, 'tev_bpt', 4): "bpt",
            getattr(ida_dbg, 'tev_mem', 5): "mem",
            getattr(ida_dbg, 'tev_event', 6): "event",
        }
        events = []
        for idx in range(offset, min(qty, offset + limit)):
            ti = ida_dbg.tev_info_t()
            if ida_dbg.get_tev_info(idx, ti):
                tname = tev_names.get(ti.type, f"tev_{ti.type}")
                func = ida_funcs.get_func(ti.ea) if ti.ea != ida_idaapi.BADADDR else None
                item = {
                    "index": idx,
                    "type": tname,
                    "tid": int(ti.tid),
                    "ea": hex(ti.ea) if ti.ea != ida_idaapi.BADADDR else None,
                    "func": ida_funcs.get_func_name(func.start_ea) if func else None,
                    "disasm": idc.generate_disasm_line(ti.ea, 0) if ti.ea != ida_idaapi.BADADDR else None,
                }
                if tname == "call" and hasattr(ida_dbg, 'get_call_tev_callee'):
                    callee = ida_dbg.get_call_tev_callee(idx)
                    if callee != ida_idaapi.BADADDR:
                        item["callee"] = hex(callee)
                        item["callee_name"] = ida_funcs.get_func_name(callee) or ida_name.get_name(callee)
                elif tname == "ret" and hasattr(ida_dbg, 'get_ret_tev_return'):
                    ret_ea = ida_dbg.get_ret_tev_return(idx)
                    if ret_ea != ida_idaapi.BADADDR:
                        item["return_ea"] = hex(ret_ea)
                elif tname == "bpt" and hasattr(ida_dbg, 'get_bpt_tev_ea'):
                    bpt_ea = ida_dbg.get_bpt_tev_ea(idx)
                    if bpt_ea != ida_idaapi.BADADDR:
                        item["bpt_ea"] = hex(bpt_ea)
                events.append(item)
        return {"events": events, "offset": offset, "limit": limit, "returned": len(events), "total": qty}
    return safe_read(_inner)

def dbg_clear_trace_api():
    def _inner():
        import ida_dbg
        if hasattr(ida_dbg, 'clear_trace'):
            ida_dbg.clear_trace()
        return {"success": True}
    return safe_write(_inner)

def dbg_get_exceptions_api():
    """Retrieve debugger exception handling table."""
    def _inner():
        import ida_dbg
        if not hasattr(ida_dbg, 'retrieve_exceptions'):
            return {"exceptions": [], "count": 0}
        vec = ida_dbg.retrieve_exceptions()
        if not vec:
            return {"exceptions": [], "count": 0}
        excs = []
        for e in vec:
            excs.append({
                "code": hex(e.code),
                "code_int": int(e.code),
                "name": e.name or "",
                "desc": e.desc or "",
                "flags": int(e.flags),
                "break_on": bool(e.break_on()) if hasattr(e, 'break_on') else False,
                "handle": bool(e.handle()) if hasattr(e, 'handle') else False,
            })
        return {"exceptions": excs, "count": len(excs)}
    return safe_read(_inner)

def dbg_configure_exception_api(code, name="", desc="", break_on=True, handle=False, msg=True, silent=False, Break=None, save_to_idb=True):
    """Define or update how the debugger handles a specific exception code."""
    if Break is not None:
        break_on = bool(Break)
    if isinstance(code, bool) or not isinstance(code, (int, str)):
        raise ValueError("Exception code must be an int or hex string")
    exc_code = int(code.strip(), 0) if isinstance(code, str) else int(code)
    def _inner():
        import ida_dbg, ida_idd
        if not hasattr(ida_dbg, 'define_exception'):
            return {"error": "define_exception is not available"}
        flags = 0
        if break_on:
            flags |= getattr(ida_idd, 'EXC_BREAK', 1)
        if handle:
            flags |= getattr(ida_idd, 'EXC_HANDLE', 2)
        if msg:
            flags |= getattr(ida_idd, 'EXC_MSG', 4)
        if silent:
            flags |= getattr(ida_idd, 'EXC_SILENT', 8)
        err = ida_dbg.define_exception(exc_code, str(name or f"EXC_{exc_code:X}"), str(desc or ""), flags)
        if save_to_idb and hasattr(ida_dbg, 'store_exceptions'):
            ida_dbg.store_exceptions()
        return {"success": not err, "error": err or None, "code": hex(exc_code), "flags": flags}
    return safe_write(_inner)

def dbg_get_event_log(limit=100, event_type=None):
    """Read captured asynchronous debugger events from DBG_Hooks."""
    limit = bounded_int(limit, 'limit', 1, 500)
    with _dbg_events_lock:
        items = list(_dbg_events)
    if event_type:
        items = [e for e in items if e.get("event") == event_type]
    items = items[-limit:]
    return {"events": items, "count": len(items)}

def dbg_clear_event_log():
    with _dbg_events_lock:
        _dbg_events.clear()
    return {"success": True}

def dbg_send_cmd_api(command):
    """Send raw command to underlying debugger backend (WinDbg, GDB, Bochs)."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    def _inner():
        import ida_dbg
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if not hasattr(ida_dbg, 'send_dbg_command'):
            return {"error": "send_dbg_command is not supported"}
        try:
            out = ida_dbg.send_dbg_command(command)
            return {"success": True, "command": command, "output": str(out) if out is not None else ""}
        except Exception as exc:
            return {"success": False, "error": str(exc), "command": command}
    return safe_write(_inner)

def dbg_appcall_api(func_target, args=None, proto=None, tid=None):
    """Execute an IDA Appcall in the suspended process."""
    if not func_target:
        raise ValueError("func_target is required")
    if args is not None and not isinstance(args, list):
        raise ValueError("args must be a list")
    def _inner():
        import ida_dbg, ida_idd
        if not ida_dbg.is_debugger_on():
            return {"error": "No active debugger"}
        if not hasattr(ida_idd, 'Appcall'):
            return {"error": "Appcall is not available"}
        try:
            if tid is not None and hasattr(ida_dbg, 'select_thread'):
                ida_dbg.select_thread(int(tid))
            if isinstance(func_target, int) or (isinstance(func_target, str) and re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]+', func_target.strip())):
                ea = parse_ea(func_target)
                if proto and hasattr(ida_idd.Appcall, 'proto'):
                    target = ida_idd.Appcall.proto(ea, str(proto))
                else:
                    fn_name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea)
                    target = getattr(ida_idd.Appcall, fn_name) if fn_name else ida_idd.Appcall[ea]
            else:
                if proto and hasattr(ida_idd.Appcall, 'proto'):
                    target = ida_idd.Appcall.proto(str(func_target), str(proto))
                else:
                    target = ida_idd.Appcall[str(func_target)]
            ret = target(*(args or []))
            if isinstance(ret, int):
                ret_val = hex(ret)
            else:
                ret_val = str(ret)
            return {"success": True, "target": str(func_target), "return_value": ret_val}
        except Exception as exc:
            return {"success": False, "error": str(exc), "target": str(func_target)}
    return safe_write(_inner)

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
        if not f:
            return {"error": f"No function at {hex(ea)}"}
        strings = []
        seen = set()
        cur = f.start_ea
        has_flags_api = hasattr(ida_bytes, 'get_flags')
        while cur < f.end_ea and cur != ida_idaapi.BADADDR:
            for xref in idautils.XrefsFrom(cur):
                target = xref.to
                if (target, cur) in seen:
                    continue
                is_str = False
                if has_flags_api:
                    flags = ida_bytes.get_flags(target)
                    if hasattr(ida_bytes, 'is_code') and ida_bytes.is_code(flags):
                        continue
                    is_str = bool(hasattr(ida_bytes, 'is_strlit') and ida_bytes.is_strlit(flags))
                    if not is_str:
                        if getattr(xref, 'type', 0) in (16, 17, 18, 19, 20, 21):
                            continue
                        if ida_funcs.get_func(target) is not None:
                            continue
                        seg = ida_segment.getseg(target) if hasattr(ida_segment, 'getseg') else None
                        if seg is not None and (getattr(seg, 'perm', 0) & getattr(ida_segment, 'SEGPERM_EXEC', 1)):
                            continue
                s = ida_bytes.get_strlit_contents(target, -1, 0)
                if s:
                    try:
                        text = s.decode("utf-8", errors="replace")
                    except Exception:
                        text = str(s)
                    if has_flags_api and not is_str:
                        if len(text.strip()) < 2 or "\ufffd" in text:
                            continue
                        if not all((32 <= ord(ch) < 127) or ch in "\t\r\n" for ch in text):
                            continue
                    seen.add((target, cur))
                    strings.append({
                        "ea": hex(target),
                        "module_rva": _format_module_rva_inner(target),
                        "ref_from": hex(cur),
                        "value": text,
                    })
            cur = idc.next_head(cur, f.end_ea)
        return {
            "ea": hex(ea),
            "module_rva": _format_module_rva_inner(ea),
            "name": ida_funcs.get_func_name(ea),
            "strings": strings,
            "count": len(strings),
        }
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

def get_functions_paginated(offset=0, limit=500, filter_str=None, start_ea=None, end_ea=None):
    offset = bounded_int(offset, 'offset', 0, 2 ** 31 - 1)
    limit = bounded_int(limit, 'limit', 1, 10000)
    def _inner():
        funcs = []
        total = 0
        pat = None
        if filter_str:
            try:
                pat = re.compile(filter_str, re.IGNORECASE)
            except re.error:
                pat = None
        filt_lower = filter_str.lower() if filter_str else None
        for ea in idautils.Functions():
            if start_ea is not None and ea < start_ea:
                continue
            if end_ea is not None and ea >= end_ea:
                continue
            name = ida_funcs.get_func_name(ea) or ""
            if filter_str:
                if pat is not None:
                    if not pat.search(name):
                        continue
                elif filt_lower not in name.lower():
                    continue
            if total >= offset and len(funcs) < limit:
                f = ida_funcs.get_func(ea)
                funcs.append({
                    "ea": hex(ea),
                    "module_rva": _format_module_rva_inner(ea),
                    "name": name,
                    "size": f.size() if f else 0,
                })
            total += 1
        return {
            "functions": funcs,
            "offset": offset,
            "limit": limit,
            "returned": len(funcs),
            "total": total,
            "has_more": (offset + len(funcs)) < total,
        }
    return safe_read(_inner)

# ─── HTTP Request Handler ────────────────────────────────────────────────────

def _resolve_symbolic_ea_inner(expr):
    """Resolve 'module.dll+0xC3EA7', 'symbol+0x10', or 'symbol_name' inside IDA main thread."""
    s = expr.strip()
    m = re.match(r'^(.+?)\s*([+-])\s*(0[xX][0-9a-fA-F]+|[0-9a-fA-F]+)$', s)
    if m:
        base_str = m.group(1).strip()
        sign = -1 if m.group(2) == '-' else 1
        off_raw = m.group(3).strip()
        offset = int(off_raw, 16) if off_raw.lower().startswith('0x') else int(off_raw, 16)
    else:
        base_str = s
        sign = 1
        offset = 0

    base_lower = base_str.lower()
    base_no_ext = os.path.splitext(base_lower)[0]
    base_ea = None

    # 1. Check active debugger modules first (handles runtime ASLR bases)
    try:
        import ida_dbg
        if hasattr(ida_dbg, 'is_debugger_on') and ida_dbg.is_debugger_on():
            if hasattr(ida_dbg, 'get_modules'):
                for mod in ida_dbg.get_modules():
                    mname = os.path.basename(getattr(mod, 'name', '') or "").lower()
                    mfull = (getattr(mod, 'name', '') or "").lower()
                    mnoext = os.path.splitext(mname)[0]
                    if base_lower in (mname, mfull, mnoext) or (base_no_ext and base_no_ext == mnoext):
                        if getattr(mod, 'base', ida_idaapi.BADADDR) != ida_idaapi.BADADDR:
                            base_ea = int(mod.base)
                            break
            if base_ea is None:
                import ida_idd
                if hasattr(ida_idd, 'modinfo_t') and hasattr(ida_dbg, 'get_first_module'):
                    mod = ida_idd.modinfo_t()
                    ok = ida_dbg.get_first_module(mod)
                    while ok:
                        mname = os.path.basename(mod.name or "").lower()
                        mfull = (mod.name or "").lower()
                        mnoext = os.path.splitext(mname)[0]
                        if base_lower in (mname, mfull, mnoext) or (base_no_ext and base_no_ext == mnoext):
                            if mod.base != ida_idaapi.BADADDR:
                                base_ea = int(mod.base)
                                break
                        ok = ida_dbg.get_next_module(mod)
    except Exception:
        pass

    # 2. Check loaded root binary filename in IDB
    if base_ea is None:
        try:
            root_fn = (ida_nalt.get_root_filename() or "").lower() if hasattr(ida_nalt, 'get_root_filename') else ""
            root_no_ext = os.path.splitext(root_fn)[0]
            if root_fn and (base_lower in (root_fn, root_no_ext) or (base_no_ext and base_no_ext == root_no_ext)):
                img_base = ida_nalt.get_imagebase() if hasattr(ida_nalt, 'get_imagebase') else ida_idaapi.BADADDR
                if not isinstance(img_base, int) or img_base == ida_idaapi.BADADDR or img_base == 0:
                    import ida_ida
                    img_base = ida_ida.inf_get_min_ea() if hasattr(ida_ida, 'inf_get_min_ea') else 0
                base_ea = int(img_base)
        except Exception:
            pass

    # 3. Check segment name
    if base_ea is None and hasattr(ida_segment, 'get_segm_by_name'):
        try:
            seg = ida_segment.get_segm_by_name(base_str)
            if seg is not None and seg.start_ea != ida_idaapi.BADADDR:
                base_ea = int(seg.start_ea)
        except Exception:
            pass

    # 4. Check symbol / function name
    if base_ea is None and hasattr(ida_name, 'get_name_ea'):
        try:
            sym_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, base_str)
            if isinstance(sym_ea, int) and sym_ea != ida_idaapi.BADADDR:
                base_ea = sym_ea
        except Exception:
            pass

    if base_ea is None:
        raise ValueError(f"Cannot resolve address or module+RVA expression: '{expr}'")
    return base_ea + sign * offset

def parse_ea(ea_str):
    """Parse hex address ('0x140001000'), integer, or 'module.dll+0xC3EA7' / 'symbol+0x10'."""
    if isinstance(ea_str, bool) or not isinstance(ea_str, (str, int)):
        raise ValueError('Address must be a hexadecimal string, module+RVA expression, or an integer')
    if isinstance(ea_str, int):
        value = ea_str
    else:
        s = unquote(ea_str).strip()
        if not s:
            raise ValueError('Address must not be empty')
        if re.fullmatch(r'(?:0[xX])?[0-9a-fA-F]+', s):
            value = int(s, 16)
        else:
            value = safe_read(lambda: _resolve_symbolic_ea_inner(s))
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


def capture_evidence_api(ea=None, memory_ranges=None, output_path=None, stack_bytes=128):
    """Capture a complete forensic/debugging JSON evidence bundle (module, hashes, addresses, registers, stack, memory)."""
    stack_bytes = bounded_int(stack_bytes, 'stack_bytes', 0, 16384)
    target_ea = parse_ea(ea) if ea is not None and str(ea).strip() != "" else None
    parsed_ranges = []
    if memory_ranges:
        if not isinstance(memory_ranges, list):
            raise ValueError("memory_ranges must be a list of {ea, size, label} objects")
        for item in memory_ranges[:32]:
            if isinstance(item, dict) and item.get("ea") is not None:
                r_ea = parse_ea(item["ea"])
                r_sz = bounded_int(item.get("size", 64), "range size", 1, 65536)
                parsed_ranges.append((r_ea, r_sz, item.get("label") or str(item["ea"])))

    def _inner():
        info = get_info()
        dbg_stat = dbg_get_status()
        status = dbg_stat.get("status", "not_attached")
        regs_data = dbg_get_regs(include_all=False) if status in ("paused", "breakpoint_hit") else {"status": status, "registers": {}}
        stack_data = dbg_get_stack() if status in ("paused", "breakpoint_hit") else {"stack": [], "count": 0}
        mods_data = dbg_get_modules() if status != "not_attached" else {"modules": [], "count": 0}
        bps_data = dbg_list_bps()

        focus_ea = target_ea
        if focus_ea is None and dbg_stat.get("ip"):
            try:
                focus_ea = int(dbg_stat["ip"], 16)
            except Exception:
                focus_ea = None
        if focus_ea is None:
            try:
                focus_ea = idc.get_screen_ea()
            except Exception:
                focus_ea = None

        target_ctx = None
        if focus_ea is not None and focus_ea != ida_idaapi.BADADDR:
            func = ida_funcs.get_func(focus_ea) if hasattr(ida_funcs, 'get_func') else None
            func_name = ida_funcs.get_func_name(func.start_ea) if func else None
            disasm_preview = get_disasm_range(focus_ea, count=15).get("instructions", [])
            pseudo = None
            if func and HAS_HEXRAYS:
                p_res = get_pseudocode(func.start_ea)
                if not p_res.get("error"):
                    pseudo = p_res.get("pseudocode")
            target_ctx = {
                "ea": hex(focus_ea),
                "module_rva": _format_module_rva_inner(focus_ea),
                "function": func_name,
                "function_ea": hex(func.start_ea) if func else None,
                "disasm": disasm_preview,
                "pseudocode": pseudo,
            }

        raw_stack_dump = None
        if status in ("paused", "breakpoint_hit") and stack_bytes > 0 and dbg_stat.get("sp"):
            try:
                sp_ea = int(dbg_stat["sp"], 16)
                mem_res = dbg_read_mem(sp_ea, stack_bytes)
                if not mem_res.get("error"):
                    raw_stack_dump = mem_res
            except Exception:
                pass

        mem_dumps = []
        for r_ea, r_sz, r_label in parsed_ranges:
            dump_item = {
                "label": r_label,
                "ea": hex(r_ea),
                "module_rva": _format_module_rva_inner(r_ea),
                "size": r_sz,
            }
            if status in ("paused", "breakpoint_hit"):
                m_res = dbg_read_mem(r_ea, r_sz)
                if not m_res.get("error"):
                    dump_item["source"] = "debugger_memory"
                    dump_item["hex"] = m_res.get("hex")
                    dump_item["ascii"] = m_res.get("ascii")
                else:
                    b_res = read_bytes(r_ea, r_sz)
                    dump_item["source"] = "idb_bytes"
                    dump_item["hex"] = b_res.get("hex")
                    dump_item["ascii"] = b_res.get("ascii")
            else:
                b_res = read_bytes(r_ea, r_sz)
                dump_item["source"] = "idb_bytes"
                dump_item["hex"] = b_res.get("hex")
                dump_item["ascii"] = b_res.get("ascii")
            mem_dumps.append(dump_item)

        evidence = {
            "timestamp": round(_time.time(), 3),
            "bridge_version": BRIDGE_VERSION,
            "ida_version": IDA_VERSION,
            "binary": info,
            "target": target_ctx,
            "debugger": {
                "status": status,
                "current_tid": dbg_stat.get("current_tid"),
                "ip": dbg_stat.get("ip"),
                "ip_module_rva": dbg_stat.get("ip_module_rva"),
                "sp": dbg_stat.get("sp"),
                "registers": regs_data.get("registers", {}),
                "stack_frames": stack_data.get("stack", []),
                "stack_memory": raw_stack_dump,
                "modules": mods_data.get("modules", []),
                "breakpoints": bps_data.get("breakpoints", []),
                "recent_events": dbg_get_event_log(limit=25).get("events", []),
            },
            "memory_ranges": mem_dumps,
        }
        return evidence

    bundle = safe_read(_inner)
    if output_path:
        out_file = os.path.abspath(os.path.expanduser(str(output_path)))
        out_dir = os.path.dirname(out_file)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as fh:
            json.dump(bundle, fh, indent=2, ensure_ascii=False)
        bundle["saved_to"] = out_file
    return bundle


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
    _DbgHooksBase = getattr(ida_dbg, 'DBG_Hooks', getattr(ida_dbg, 'DbgHooks', object))
    class Ph4ntomDbgHooks(_DbgHooksBase):
        def dbg_bpt(self, tid, ea):
            global _last_dbg_stop_reason
            _last_dbg_stop_reason = "breakpoint_hit"
            pol = _bp_policies.get(ea)
            mod_rva = None
            try:
                mod_rva = (pol.get("module_rva") if pol else None) or _format_module_rva_inner(ea)
            except Exception:
                pass
            if pol is not None:
                filter_tid = pol.get("tid")
                if filter_tid is not None and int(filter_tid) != int(tid):
                    _record_dbg_event({
                        "event": "breakpoint_filtered",
                        "tid": tid,
                        "expected_tid": filter_tid,
                        "ea": hex(ea),
                        "module_rva": mod_rva,
                    })
                    try:
                        _last_dbg_stop_reason = None
                        if hasattr(ida_dbg, 'request_continue_process') and hasattr(ida_dbg, 'run_requests'):
                            ida_dbg.request_continue_process()
                            ida_dbg.run_requests()
                        elif hasattr(ida_dbg, 'continue_process'):
                            ida_dbg.continue_process()
                    except Exception:
                        pass
                    return 0
                pol["hit_count"] = int(pol.get("hit_count", 0)) + 1
                hit_count = pol["hit_count"]
                log_reg_names = pol.get("log_regs") or None
                auto_cont = bool(pol.get("auto_continue") or pol.get("action") == "log_and_continue")
            else:
                hit_count = 1
                log_reg_names = None
                auto_cont = False

            regs_snap = {}
            try:
                regs_snap = _read_regs_inner(ida_dbg, tid=tid, reg_names=log_reg_names)
            except Exception:
                pass
            ev_payload = {
                "event": "breakpoint_hit",
                "status": "breakpoint_hit",
                "tid": tid,
                "ea": hex(ea),
                "module_rva": mod_rva,
                "hit_count": hit_count,
                "registers": regs_snap,
                "auto_continued": auto_cont,
            }
            _record_dbg_event(ev_payload)
            if auto_cont:
                try:
                    _last_dbg_stop_reason = None
                    if hasattr(ida_dbg, 'request_continue_process') and hasattr(ida_dbg, 'run_requests'):
                        ida_dbg.request_continue_process()
                        ida_dbg.run_requests()
                    elif hasattr(ida_dbg, 'continue_process'):
                        ida_dbg.continue_process()
                except Exception:
                    pass
            return 0

        def dbg_exception(self, pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info):
            _record_dbg_event({
                "event": "exception",
                "pid": pid,
                "tid": tid,
                "ea": hex(ea),
                "code": hex(exc_code),
                "can_continue": bool(exc_can_cont),
                "exc_ea": hex(exc_ea),
                "info": str(exc_info),
            })
            return 0

        def dbg_process_start(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
            _record_dbg_event({
                "event": "process_start",
                "pid": pid,
                "tid": tid,
                "ea": hex(ea),
                "module": str(modinfo_name),
                "base": hex(modinfo_base),
                "size": modinfo_size,
            })
            return 0

        def dbg_process_exit(self, pid, tid, ea, exit_code):
            _record_dbg_event({"event": "process_exit", "pid": pid, "tid": tid, "ea": hex(ea), "exit_code": exit_code})
            return 0

        def dbg_process_attach(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
            _record_dbg_event({
                "event": "process_attach",
                "pid": pid,
                "tid": tid,
                "ea": hex(ea),
                "module": str(modinfo_name),
                "base": hex(modinfo_base),
                "size": modinfo_size,
            })
            return 0

        def dbg_process_detach(self, pid, tid, ea):
            _record_dbg_event({"event": "process_detach", "pid": pid, "tid": tid, "ea": hex(ea)})
            return 0

        def dbg_suspend_process(self):
            _record_dbg_event({"event": "process_suspended"})
            return 0

        def dbg_thread_start(self, pid, tid, ea):
            _record_dbg_event({"event": "thread_start", "pid": pid, "tid": tid, "ea": hex(ea)})
            return 0

        def dbg_thread_exit(self, pid, tid, ea, exit_code):
            _record_dbg_event({"event": "thread_exit", "pid": pid, "tid": tid, "ea": hex(ea), "exit_code": exit_code})
            return 0

        def dbg_library_load(self, pid, tid, ea, modinfo_name, modinfo_base, modinfo_size):
            _record_dbg_event({
                "event": "library_load",
                "pid": pid,
                "tid": tid,
                "ea": hex(ea),
                "module": str(modinfo_name),
                "base": hex(modinfo_base),
                "size": modinfo_size,
            })
            return 0

        def dbg_library_unload(self, pid, tid, ea, info):
            _record_dbg_event({"event": "library_unload", "pid": pid, "tid": tid, "ea": hex(ea), "module": str(info)})
            return 0

        def dbg_step_into(self):
            _record_dbg_event({"event": "step_into"})
            return 0

        def dbg_step_over(self):
            _record_dbg_event({"event": "step_over"})
            return 0

        def dbg_step_until_ret(self):
            _record_dbg_event({"event": "step_until_ret"})
            return 0

        def dbg_run_to(self, pid, tid, ea):
            _record_dbg_event({"event": "run_to", "pid": pid, "tid": tid, "ea": hex(ea)})
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
    filt = params.get('filter', [None])[0]
    start_raw = params.get('start', [None])[0]
    end_raw = params.get('end', [None])[0]
    start_ea = parse_ea(start_raw) if start_raw is not None else None
    end_ea = parse_ea(end_raw) if end_raw is not None else None
    self.send_json(get_functions(filter_str=filt, start_ea=start_ea, end_ea=end_ea))

@get_route(r'/api/strings')
def route_do_get_2(self, match, params):
    filt = params.get('filter', [None])[0]
    off_raw = params.get('offset', [None])[0]
    lim_raw = params.get('limit', [None])[0]
    start_raw = params.get('start', [None])[0]
    end_raw = params.get('end', [None])[0]
    offset = int(off_raw) if off_raw is not None else 0
    limit = int(lim_raw) if lim_raw is not None else None
    start_ea = parse_ea(start_raw) if start_raw is not None else None
    end_ea = parse_ea(end_raw) if end_raw is not None else None
    self.send_json(get_strings(filt, offset=offset, limit=limit, start_ea=start_ea, end_ea=end_ea))

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
    off_raw = params.get('offset', [None])[0]
    lim_raw = params.get('limit', [None])[0]
    start_raw = params.get('start', [None])[0]
    end_raw = params.get('end', [None])[0]
    offset = int(off_raw) if off_raw is not None else 0
    limit = int(lim_raw) if lim_raw is not None else None
    start_ea = parse_ea(start_raw) if start_raw is not None else None
    end_ea = parse_ea(end_raw) if end_raw is not None else None
    self.send_json(get_names(filt, offset=offset, limit=limit, start_ea=start_ea, end_ea=end_ea))

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
        'ida_version': IDA_VERSION,
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
        max_ent = int(params.get('max', [64])[0])
        self.send_json(get_vtable(parse_ea(parts[3]), max_entries=max_ent))
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
        end_raw = params.get('end', [None])[0]
        cnt_raw = params.get('count', [None])[0]
        end_ea = parse_ea(end_raw) if end_raw is not None else None
        cnt = int(cnt_raw) if cnt_raw is not None else None
        self.send_json(get_disasm(ea, end_ea=end_ea, count=cnt))
    elif action == 'xrefs-to':
        exact = params.get('exact', ['0'])[0] in ('1', 'true', 'True')
        filt = params.get('filter', [None])[0]
        start_raw = params.get('start', [None])[0]
        end_raw = params.get('end', [None])[0]
        xtype = params.get('type', [None])[0]
        start_ea = parse_ea(start_raw) if start_raw is not None else None
        end_ea = parse_ea(end_raw) if end_raw is not None else None
        self.send_json(get_xrefs_to(ea, exact=exact, filter_str=filt, start_ea=start_ea, end_ea=end_ea, xref_type=xtype))
    elif action == 'xrefs-from':
        filt = params.get('filter', [None])[0]
        start_raw = params.get('start', [None])[0]
        end_raw = params.get('end', [None])[0]
        xtype = params.get('type', [None])[0]
        start_ea = parse_ea(start_raw) if start_raw is not None else None
        end_ea = parse_ea(end_raw) if end_raw is not None else None
        self.send_json(get_xrefs_from(ea, filter_str=filt, start_ea=start_ea, end_ea=end_ea, xref_type=xtype))
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
    filt = params.get('filter', [None])[0]
    start_raw = params.get('start', [None])[0]
    end_raw = params.get('end', [None])[0]
    start_ea = parse_ea(start_raw) if start_raw is not None else None
    end_ea = parse_ea(end_raw) if end_raw is not None else None
    self.send_json(get_functions_paginated(off, lim, filter_str=filt, start_ea=start_ea, end_ea=end_ea))

@get_route(r'/api/disasm-range')
def route_do_get_disasm_range(self, match, params):
    start_raw = params.get('start', params.get('ea', ['0']))[0]
    end_raw = params.get('end', [None])[0]
    cnt_raw = params.get('count', [100])[0]
    start_ea = parse_ea(start_raw)
    end_ea = parse_ea(end_raw) if end_raw is not None else None
    self.send_json(get_disasm_range(start_ea, end_ea=end_ea, count=int(cnt_raw)))

@get_route(r'/api/dbg/breakpoints')
def route_do_get_28(self, match, params):
    self.send_json(dbg_list_bps())

@get_route(r'/api/dbg/regs')
def route_do_get_29(self, match, params):
    tid_raw = params.get('tid', [None])[0]
    tid = int(tid_raw) if tid_raw is not None else None
    inc_all = params.get('all', ['0'])[0] in ('1', 'true', 'True')
    self.send_json(dbg_get_regs(tid=tid, include_all=inc_all))

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

@get_route(r'/api/classes')
def route_do_get_classes(self, match, params):
    self.send_json(get_classes_api())

@get_route(r'/api/class/.*')
def route_do_get_class_details(self, match, params):
    parts = match.string.split('/', 4)
    if len(parts) == 4:
        self.send_json(get_class_details_api(unquote(parts[3])))
    else:
        self.send_error_json('Use /api/class/<name>')

@get_route(r'/api/decompiler/timeout')
def route_do_get_decomp_timeout(self, match, params):
    self.send_json(get_decompiler_timeout_api())

@get_route(r'/api/dbg/status')
def route_do_get_dbg_status(self, match, params):
    self.send_json(dbg_get_status())

@get_route(r'/api/dbg/processes')
def route_do_get_dbg_processes(self, match, params):
    self.send_json(dbg_list_processes())

@get_route(r'/api/dbg/modules')
def route_do_get_dbg_modules(self, match, params):
    self.send_json(dbg_get_modules())

@get_route(r'/api/dbg/memory-map')
def route_do_get_dbg_memory_map(self, match, params):
    self.send_json(dbg_get_memory_map())

@get_route(r'/api/dbg/trace')
def route_do_get_dbg_trace(self, match, params):
    count = int(params.get('count', [50])[0])
    offset = int(params.get('offset', [0])[0])
    self.send_json(dbg_get_trace_events(count=count, offset=offset))

@get_route(r'/api/dbg/exceptions')
def route_do_get_dbg_exceptions(self, match, params):
    self.send_json(dbg_get_exceptions_api())

@get_route(r'/api/dbg/events')
def route_do_get_dbg_events(self, match, params):
    limit = int(params.get('limit', [50])[0])
    etype = params.get('type', [None])[0]
    self.send_json(dbg_get_event_log(limit=limit, event_type=etype))

@get_route(r'/api/dbg/breakpoints/export')
def route_do_get_dbg_bps_export(self, match, params):
    out_path = params.get('output', [None])[0]
    self.send_json(dbg_export_bps(output_path=out_path))

@get_route(r'/api/dbg/evidence')
def route_do_get_dbg_evidence(self, match, params):
    ea_raw = params.get('ea', [None])[0]
    out_path = params.get('output', [None])[0]
    self.send_json(capture_evidence_api(ea=ea_raw, output_path=out_path))

@get_route(r'/api/instances')
def route_do_get_instances(self, match, params):
    self.send_json(list_instances_api())

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
    out_path = data.get('output_path') or data.get('output')
    fmt = data.get('format', 'json')
    self.send_json(decompile_batch(ea_list, output_path=out_path, fmt=fmt))

@post_route(r'/api/vtable/create-struct')
def route_do_post_vtable_create_struct(self, match, data):
    ea = parse_ea(data.get('ea', '0'))
    self.send_json(create_vtable_struct_api(ea, name=data.get('name'), max_entries=data.get('max_entries', 64)))

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
    target_ea = parse_ea(data.get('ea', '0'))
    act = str(data.get('action') or '').strip().lower()
    mode_val = str(data.get('mode') or 'exec').strip().lower()
    if data.get('delete') or act == 'delete' or mode_val == 'delete':
        self.send_json(dbg_del_bp(target_ea))
        return
    if act in ('disable', 'enable'):
        self.send_json(dbg_toggle_bp(target_ea, enable=(act == 'enable')))
        return
    self.send_json(dbg_set_bp(
        target_ea,
        hardware=data.get('hardware', False),
        mode=data.get('mode', 'exec'),
        size=data.get('size', 1),
        condition=data.get('condition', ''),
        elang=data.get('elang', 'Python'),
        pass_count=data.get('pass_count', 0),
        trace_only=data.get('trace_only', False),
        enabled=data.get('enabled', True),
        tid=data.get('tid'),
        action=data.get('action'),
        auto_continue=data.get('auto_continue', False),
        log_regs=data.get('log_regs'),
    ))

@post_route(r'/api/dbg/del-breakpoint')
def route_do_post_38(self, match, data):
    self.send_json(dbg_del_bp(parse_ea(data.get('ea', '0'))))

@post_route(r'/api/dbg/step-into')
def route_do_post_39(self, match, data):
    self.send_json(dbg_step_into_api(wait=data.get('wait', False), timeout=data.get('timeout', 5)))

@post_route(r'/api/dbg/step-over')
def route_do_post_40(self, match, data):
    self.send_json(dbg_step_over_api(wait=data.get('wait', False), timeout=data.get('timeout', 5)))

@post_route(r'/api/dbg/continue')
def route_do_post_41(self, match, data):
    self.send_json(dbg_continue_api(wait=data.get('wait', False), timeout=data.get('timeout', 5)))

@post_route(r'/api/dbg/pause')
def route_do_post_42(self, match, data):
    self.send_json(dbg_pause_api())

@post_route(r'/api/dbg/write-memory')
def route_do_post_43(self, match, data):
    self.send_json(dbg_write_mem(parse_ea(data.get('ea', '0')), data.get('bytes', '')))

@post_route(r'/api/decompiler/timeout')
def route_do_post_decomp_timeout(self, match, data):
    self.send_json(set_decompiler_timeout_api(data.get('seconds', 0)))

@post_route(r'/api/dbg/load')
def route_do_post_dbg_load(self, match, data):
    self.send_json(dbg_load_backend(
        data.get('name', ''),
        use_remote=data.get('remote', False),
        hostname=data.get('host', ''),
        port=data.get('port', 0),
        password=data.get('password', ''),
    ))

@post_route(r'/api/dbg/exit')
def route_do_post_dbg_exit(self, match, data):
    self.send_json(dbg_exit_process())

@post_route(r'/api/dbg/step-out')
def route_do_post_dbg_step_out(self, match, data):
    self.send_json(dbg_step_out_api(wait=data.get('wait', False), timeout=data.get('timeout', 5)))

@post_route(r'/api/dbg/run-to')
def route_do_post_dbg_run_to(self, match, data):
    self.send_json(dbg_run_to_api(
        parse_ea(data.get('ea', '0')),
        pid=data.get('pid', -1),
        tid=data.get('tid', 0),
        wait=data.get('wait', False),
        timeout=data.get('timeout', 5),
    ))

@post_route(r'/api/dbg/wait')
def route_do_post_dbg_wait(self, match, data):
    self.send_json(dbg_wait_event(timeout=data.get('timeout', 5), wfne=data.get('wfne', 1)))

@post_route(r'/api/dbg/set-reg')
def route_do_post_dbg_set_reg(self, match, data):
    reg_name = data.get('reg') or data.get('name') or ''
    self.send_json(dbg_set_reg(reg_name, data.get('value', 0), tid=data.get('tid')))

@post_route(r'/api/dbg/watchpoint')
def route_do_post_dbg_watchpoint(self, match, data):
    self.send_json(dbg_set_bp(
        parse_ea(data.get('ea', '0')),
        hardware=True,
        mode=data.get('mode', 'rw'),
        size=data.get('size', 4),
        condition=data.get('condition', ''),
        elang=data.get('elang', 'Python'),
        pass_count=data.get('pass_count', 0),
        trace_only=data.get('trace_only', False),
        enabled=data.get('enabled', True),
        tid=data.get('tid'),
        action=data.get('action'),
        auto_continue=data.get('auto_continue', False),
        log_regs=data.get('log_regs'),
    ))

@post_route(r'/api/dbg/toggle-breakpoint')
def route_do_post_dbg_toggle_bp(self, match, data):
    self.send_json(dbg_toggle_bp(parse_ea(data.get('ea', '0')), enable=data.get('enable', data.get('enabled', True))))

@post_route(r'/api/dbg/update-breakpoint')
def route_do_post_dbg_update_bp(self, match, data):
    self.send_json(dbg_update_bp(
        parse_ea(data.get('ea', '0')),
        condition=data.get('condition'),
        elang=data.get('elang'),
        pass_count=data.get('pass_count'),
        trace_only=data.get('trace_only'),
        enabled=data.get('enabled'),
        mode=data.get('mode'),
        size=data.get('size'),
        tid=data.get('tid'),
        action=data.get('action'),
        auto_continue=data.get('auto_continue'),
        log_regs=data.get('log_regs'),
    ))

@post_route(r'/api/dbg/breakpoints/export')
def route_do_post_dbg_bps_export(self, match, data):
    self.send_json(dbg_export_bps(output_path=data.get('output_path') or data.get('output')))

@post_route(r'/api/dbg/breakpoints/import')
def route_do_post_dbg_bps_import(self, match, data):
    self.send_json(dbg_import_bps(
        breakpoints=data.get('breakpoints', []),
        input_path=data.get('input_path') or data.get('path'),
        clear_existing=data.get('clear_existing', False),
    ))

@post_route(r'/api/dbg/evidence')
def route_do_post_dbg_evidence(self, match, data):
    self.send_json(capture_evidence_api(
        ea=data.get('ea'),
        memory_ranges=data.get('memory_ranges'),
        output_path=data.get('output_path') or data.get('output'),
        stack_bytes=data.get('stack_bytes', 128),
    ))

@post_route(r'/api/dbg/refresh-memory')
def route_do_post_dbg_refresh_mem(self, match, data):
    self.send_json(dbg_refresh_memory_api())

@post_route(r'/api/dbg/search-memory')
def route_do_post_dbg_search_mem(self, match, data):
    start_raw = data.get('start')
    end_raw = data.get('end')
    self.send_json(dbg_search_memory_api(
        data.get('pattern', ''),
        start_ea=parse_ea(start_raw) if start_raw is not None else None,
        end_ea=parse_ea(end_raw) if end_raw is not None else None,
        max_results=data.get('max_results', 100),
    ))

@post_route(r'/api/dbg/thread-action')
def route_do_post_dbg_thread_action(self, match, data):
    self.send_json(dbg_thread_control(data.get('tid', 0), data.get('action', 'select')))

@post_route(r'/api/dbg/trace/configure')
def route_do_post_dbg_trace_config(self, match, data):
    self.send_json(dbg_configure_trace_api(
        insn=data.get('insn'),
        func=data.get('func'),
        bblk=data.get('bblk'),
        step=data.get('step'),
        buf_size=data.get('buf_size'),
    ))

@post_route(r'/api/dbg/trace/clear')
def route_do_post_dbg_trace_clear(self, match, data):
    self.send_json(dbg_clear_trace_api())

@post_route(r'/api/dbg/exceptions')
def route_do_post_dbg_exceptions(self, match, data):
    code_val = data.get('code', 0)
    if isinstance(code_val, str):
        code_val = int(code_val, 0)
    self.send_json(dbg_configure_exception_api(
        code_val,
        name=data.get('name'),
        desc=data.get('desc'),
        Break=data.get('break'),
        handle=data.get('handle'),
        msg=data.get('msg'),
        save_to_idb=data.get('save', True),
    ))

@post_route(r'/api/dbg/events/clear')
def route_do_post_dbg_events_clear(self, match, data):
    self.send_json(dbg_clear_event_log())

@post_route(r'/api/dbg/cmd')
def route_do_post_dbg_cmd(self, match, data):
    if not ALLOW_SCRIPT_EXECUTION:
        self.send_error_json(
            "Debugger backend command execution requires IDA_BRIDGE_ALLOW_EXEC=1 before starting IDA.",
            403,
        )
        return
    self.send_json(dbg_send_cmd_api(data.get('cmd', '')))

@post_route(r'/api/dbg/appcall')
def route_do_post_dbg_appcall(self, match, data):
    if not ALLOW_SCRIPT_EXECUTION:
        self.send_error_json(
            "Appcall execution in target process requires IDA_BRIDGE_ALLOW_EXEC=1 before starting IDA.",
            403,
        )
        return
    self.send_json(dbg_appcall_api(
        parse_ea(data.get('ea', '0')),
        proto=data.get('proto', ''),
        args=data.get('args', []),
        tid=data.get('tid'),
    ))

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
            self.token_path = _write_secure_token(self.auth_token, port=address[1])
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


def _instances_registry_path():
    return os.path.join(os.path.expanduser("~"), ".ph4ntom_ida_instances.json")


def _register_instance(host, port, token_path):
    try:
        reg_path = _instances_registry_path()
        entries = {}
        if os.path.isfile(reg_path):
            try:
                with open(reg_path, "r", encoding="utf-8") as fh:
                    entries = json.load(fh) or {}
            except Exception:
                entries = {}
        info = get_info()
        entries[str(port)] = {
            "port": int(port),
            "url": f"http://{host}:{port}",
            "pid": os.getpid(),
            "filename": info.get("filename"),
            "filepath": info.get("filepath"),
            "token_path": token_path,
            "version": BRIDGE_VERSION,
            "ida_version": IDA_VERSION,
            "started_at": round(_time.time(), 3),
        }
        with open(reg_path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass


def _unregister_instance(port):
    try:
        reg_path = _instances_registry_path()
        if not os.path.isfile(reg_path):
            return
        with open(reg_path, "r", encoding="utf-8") as fh:
            entries = json.load(fh) or {}
        if str(port) in entries:
            del entries[str(port)]
            with open(reg_path, "w", encoding="utf-8") as fh:
                json.dump(entries, fh, indent=2, ensure_ascii=False)
    except Exception:
        pass


def list_instances_api():
    """Return all registered active IDA Bridge instances (e.g. networksystem.dll on 13370, tier0.dll on 13371)."""
    reg_path = _instances_registry_path()
    instances = []
    if os.path.isfile(reg_path):
        try:
            with open(reg_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh) or {}
            for _, item in sorted(raw.items(), key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 0):
                if isinstance(item, dict):
                    instances.append(item)
        except Exception:
            pass
    cur_port = _server.server_port if _server is not None else PORT
    if not any(i.get("port") == cur_port for i in instances):
        info = get_info()
        instances.append({
            "port": cur_port,
            "url": f"http://{HOST}:{cur_port}",
            "pid": os.getpid(),
            "filename": info.get("filename"),
            "filepath": info.get("filepath"),
            "token_path": _token_path,
            "version": BRIDGE_VERSION,
            "ida_version": IDA_VERSION,
        })
    return {"instances": instances, "current_port": cur_port, "count": len(instances)}


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
    """Start the HTTP server in a background thread, auto-selecting next free port (13370..13389) if multiple IDA instances run."""
    global _server, _thread
    if _server is not None:
        print(f"[ph4ntom] Server already running on {host}:{_server.server_port}")
        return

    env_port = os.environ.get("IDA_BRIDGE_PORT")
    if env_port:
        candidate_ports = [int(env_port)]
    elif port == PORT:
        candidate_ports = list(range(PORT, PORT + 20))
    else:
        candidate_ports = [port]

    server = None
    last_err = None
    for cand_port in candidate_ports:
        try:
            server = BridgeHTTPServer((host, cand_port), BridgeHandler)
            port = cand_port
            break
        except OSError as exc:
            last_err = exc
            continue
    if server is None:
        raise last_err or OSError(f"Could not bind to any port in {candidate_ports}")

    try:
        thread = threading.Thread(
            target=server.serve_forever,
            name="ph4ntom-ida-bridge",
            daemon=True,
        )
        thread.start()
        _hook_events()
        _server = server
        _thread = thread
        _register_instance(host, port, _token_path)
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
        _unregister_instance(server.server_port)
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

# IDAPython 9.0–9.5 SDK & Synchronization Reference

Verified against **IDA Professional 9.5** (`python/` SDK).

## 1. Removed Legacy APIs in IDA 9.0–9.5

| Legacy (< IDA 9.0) | IDA 9.0–9.5 Replacement | Notes |
|:---|:---|:---|
| `import ida_struct` | `import ida_typeinf` (`tinfo_t`, `udt_type_data_t`, `udm_t`) | `ida_struct.py` does not exist in IDA 9.x. |
| `import ida_enum` | `import ida_typeinf` (`enum_type_data_t`, `edm_t`) or `idc` enum helpers | `ida_enum.py` does not exist in IDA 9.x. |
| `idaapi.get_inf_structure()` | `ida_ida.inf_get_*()` / `ida_ida.inf_is_*()` | Direct `idainfo` struct access removed. |
| `ida_ida.inf_is_32bit()` | `ida_ida.inf_is_32bit_exactly()` | `inf_is_32bit_or_higher()` returns `True` on 64-bit IDBs! Always check `inf_is_32bit_exactly() and not inf_is_64bit()`. |
| `ida_dbg.DBG_Hooks` missing methods | Subclass `ida_dbg.DBG_Hooks` with defensive `getattr` | Always verify `is_debugger_on()` before stepping/pausing. |

## 2. Creating & Sizing Structs in IDA 9.5 (`ida_typeinf`)

When using MCP, call `create_struct(definition="struct fw_pkt_hdr_t { uint32_t magic; uint32_t len; };")` and `get_struct(name="fw_pkt_hdr_t")` directly without enabling `IDA_BRIDGE_ALLOW_EXEC=1`.

When writing standalone IDAPython 9.5 scripts:
- **`udm_t.offset` and `udm_t.size` are in BITS**, whereas **`tinfo_t.get_size()` returns BYTES** (`ida_typeinf.BADSIZE` on failure).
- Using `BTF_UINT32` avoids `<stdint.h>` typedef dependencies on bare-metal/raw-firmware TILs.
- **`ida_typeinf.parse_decls` signature**: `parse_decls(til: til_t, input: str, printer: printer_t | None, hti_flags: int) -> int` (`0` = zero errors). Pass `None` (never `False`) as the 3rd argument, or use `idc.parse_decls(c_decl, idc.PT_TYP)` (`idc.PT_FILE = 0x00010000`, `idc.PT_TYP = 0x0002`, `idc.PT_SIL = 0x0001`).

```python
import ida_ida
import ida_typeinf

# Strictly 32-bit check (False for 16-bit and 64-bit)
if not (ida_ida.inf_is_32bit_exactly() and not ida_ida.inf_is_64bit()):
    raise RuntimeError("Target IDB is not 32-bit")

til = ida_typeinf.get_idati()
u32 = ida_typeinf.tinfo_t(ida_typeinf.BTF_UINT32)

udt = ida_typeinf.udt_type_data_t()
for idx, field_name in enumerate(("magic", "len")):
    udm = ida_typeinf.udm_t()
    udm.name = field_name
    udm.type = u32
    udm.offset = idx * 32  # bits
    udm.size = 32          # bits
    udt.push_back(udm)

tif = ida_typeinf.tinfo_t()
if not tif.create_udt(udt, ida_typeinf.BTF_STRUCT):
    raise RuntimeError("Failed to construct UDT")
if tif.set_named_type(til, "fw_pkt_hdr_t", ida_typeinf.NTF_REPLACE) != ida_typeinf.TERR_OK:
    raise RuntimeError("Failed to register fw_pkt_hdr_t")

verify = ida_typeinf.tinfo_t()
assert verify.get_named_type(til, "fw_pkt_hdr_t")
size_bytes = verify.get_size()
assert size_bytes != ida_typeinf.BADSIZE  # 8 bytes
result["is_32bit"] = True
result["sizeof_fw_pkt_hdr_t"] = size_bytes
```

## 3. Main-Thread Synchronization (`execute_sync`) & `wait_for_next_event`

- **Every IDA SDK read/write from a worker thread** must run inside `ida_kernwin.execute_sync(callback, ida_kernwin.MFF_READ | MFF_WRITE)`. The `callback` **must return an `int` (`0`)**, and return code `-1` indicates main-thread rejection.
- **Critical IDA 9.5 `wait_for_next_event(wfne, timeout)` contract (`ida_dbg.py`)**:
  - Without `WFNE_USEC`, `timeout` is in **seconds** (passing `30000` blocks IDA's UI thread for 8.3 hours!).
  - **`WFNE_NOWAIT (0x10)` TRAP**: In IDA 9.5, `WFNE_NOWAIT` instructs IDA **not to dequeue** the debug event from the queue and immediately return `DEC_TIMEOUT (0)`. Never poll with `WFNE_NOWAIT`!
  - **`WFNE_SILENT (0x04)`**: Mandatory in headless (`-A`) and MCP automation so IDA suppresses the modal `"Running... Please wait"` dialog.
  - **Non-blocking sliced wait pattern** (already built into `ph4ntom_ida_bridge.py` `_dbg_wait_sliced`):
    - Resume once (if suspended and `WFNE_CONT` desired), then loop on the worker thread until `time.monotonic()` deadline:
    - Each slice runs `execute_sync(..., MFF_WRITE)` calling `ida_dbg.wait_for_next_event(ida_dbg.WFNE_USEC | ida_dbg.WFNE_SILENT | ida_dbg.WFNE_SUSP, 40000)` (`40000` us = `40ms`, IDA 9.5's minimum non-zero `WFNE_USEC` quantum).
    - Check return codes: `code > 0` -> event dequeued (for `EXCEPTION = 0x40`, read `ev.exc().code`, `ev.exc().ea`, `ev.exc().info`); `code == 0` (`DEC_TIMEOUT`) -> sleep `15ms` outside `execute_sync` so `dbg_pause` or UI events can interleave; `code < 0` (`DEC_ERROR = -1`, `DEC_NOTASK = -2`) -> stop immediately.

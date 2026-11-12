---
name: ida-pro
description: >-
  Use when reverse engineering binaries, firmware, drivers, or malware in IDA Pro 9.x,
  reconstructing C++/Rust/Go types and vtables, deobfuscating Hex-Rays ctree or microcode,
  writing IDAPython 9.5 scripts, or debugging live targets through IDA.
---

# IDA Pro 9.5 Reverse Engineering & Analysis

## Overview

Evidence-driven binary, firmware, and live-debugger analysis in **IDA Pro 9.0–9.5**. Always prefer structured MCP/CLI primitives over raw `execute_idapython` (disabled by default), lock the target IDA instance before writes, and treat database mutations as non-transactional.

**COMPANION SKILL:** Use `ida-bridge` for bridge connectivity, CLI flags, and full 131-tool MCP catalog details.

## Operational Workflow

1. **Lock Session & Capabilities**
   - Call `ping` to inspect `version`, `dynamic_exec_enabled`, `dbg_start_enabled`, and `read_only`.
   - Whenever multiple IDBs could be open, call `list_ida_instances` -> `select_ida_instance(target="<pid|port|filename>")` -> `get_binary_info` before any mutation or `save_database`.

2. **Triage & Architecture Addressing**
   - Map `list_segments`, `list_imports`, `list_exports`, `list_strings`, `list_functions`, and `list_function_gaps`.
   - **Raw Firmware (`imagebase == 0x0`)**: `entry_point` may be `null`; bridge `module_rva` formats addresses as `SEG+0xOFFSET` (e.g., `ROM+0x7498`). Persist firmware breakpoints as absolute EAs (use hardware execution BPs in flash/ROM), never bare segment offsets.
   - **ASLR Binaries/DLLs**: Persist breakpoints as `module+RVA` (`target.dll+0x1234`), computed from `runtime_ea - module_base` (not `get_imagebase()` for secondary DLLs).

3. **Decompilation, Classes & IR Inspection**
   - Start with `analyze_function_context(ea)` (one-shot pseudocode, lvars, callers, callees, strings, xrefs, CFG).
   - Drop to `get_microcode(ea, maturity=0..7)` or `get_ctree(ea)` when Hex-Rays optimizes away dead stores, opaque predicates, or indirect jumps.
   - Use `list_classes` / `get_class` for IDA 9.5 C++, Swift, Go, Rust, and Dalvik class hierarchies.

4. **Type & Vtable Reconstruction**
   - Register custom structs/enums first via `create_struct` / `create_type` / `create_enum` (`parse_errors == 0` means success).
   - Use `read_vtable` and `create_vtable_struct` (automatically strips ARM32 Thumb bit `0` via `ptr & ~1`).

5. **Safe Database Curation (No Fake ACID Claims)**
   - **Compensated Name/Comment Batch**: `batch_mutations(mutations, dry_run=True, mode="rollback")` supports **only** `rename-func`, `comment-func`, and `comment`. Execute with `dry_run=False` only after clean preview, then verify `rollback_complete` and `state`.
   - **Types & Locals**: `rename-var`, `create-struct`, and `set-type` (function prototype) require `mode="best_effort"` (no automatic rollback). **Local variable retyping (`set_variable_type`) is NOT a `batch_mutations` op** — call `set_variable_type(ea, var_name, type_str)` per variable and confirm in fresh `decompile(ea)`.
   - **Persistence**: Never call `save_database` if any step failed (`failed_at` present or `state == "inspect_required"`), and never save `.i64`/`.idb` without explicit user authorization for persistent DB writes.

6. **Live Debugging & Evidence**
   - Use built-in `dbg_step_*`, `dbg_continue(..., wait=True)`, `dbg_wait_event`, and `capture_evidence(..., save_path)` (saved client-side).
   - Respect default security gates: `IDA_BRIDGE_ALLOW_DBG_START=1` gates `dbg_start`, `dbg_attach`, local `dbg_load_debugger`, and inactive `dbg_run_to`; `IDA_BRIDGE_ALLOW_EXEC=1` gates `execute_idapython`, `dbg_send_command`, `dbg_appcall`, and breakpoint `condition` scripts.

## Red Flags & Common Mistakes

| Mistake / Rationalization | Reality in IDA Pro 9.5 + `ida-bridge` |
|:---|:---|
| Importing `ida_struct` or `ida_enum`, or calling `inf_is_32bit()` | Removed in IDA 9.0+. Use `ida_typeinf` (`tinfo_t`, `udt_type_data_t`) and `ida_ida.inf_is_32bit_exactly()`. |
| Passing `False` as 3rd arg to `ida_typeinf.parse_decls` | Signature is `parse_decls(til, input, printer, hti_flags)` — pass `None` for `printer`, or use `idc.parse_decls(decl, idc.PT_TYP)`. |
| Polling `wait_for_next_event` with `WFNE_NOWAIT` | In IDA 9.5, `WFNE_NOWAIT` does **not** dequeue events and immediately returns `DEC_TIMEOUT (0)`. Slice waits with `WFNE_USEC \| WFNE_SILENT` and `timeout >= 40000` (`40ms`). |
| Reaching for `execute_idapython` first under time pressure | Disabled by default (`HTTP 403`). Use structured MCP tools (`create_struct`, `batch_mutations`, `set_variable_type`). |
| Putting `set_variable_type` inside `batch_mutations` or claiming 100% ACID rollback | Only `rename-func`, `comment-func`, `comment` compensate in `rollback` mode; call `set_variable_type` separately and use `undo` if a `best_effort` step fails. |

## Detailed References

- **IDA 9.5 IDAPython SDK, `ida_typeinf` & Sync/Wait Contracts**: [idapython-95-sdk.md](./references/idapython-95-sdk.md)
- **Raw Firmware (`0x0` Base), ASLR RVAs, ARM Thumb Vtables & Classes**: [firmware-types-and-vtables.md](./references/firmware-types-and-vtables.md)
- **Batch Mutation Schemas, Microcode (`0..7`), `ctree` & Live Debugging**: [debugging-microcode-and-batch.md](./references/debugging-microcode-and-batch.md)

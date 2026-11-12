# Batch Mutations, Hex-Rays IR (`ctree` / Microcode) & Live Debugging

## 1. Exact `batch_mutations` Contract (`POST /api/batch`)

**CRITICAL**: IDA Pro has no ACID database transaction. `batch_mutations(mutations, dry_run, mode)` accepts `1..256` JSON operations (`mutations` is a JSON array string in MCP) with **only these 6 `op` schemas**:

| `op` | Required Fields | Optional Fields | Allowed in `mode="rollback"`? |
|:---|:---|:---|:---:|
| `"rename-func"` | `"ea"`, `"name"` | — | **Yes** (saves & restores old name; rejects collisions without `SN_FORCE`) |
| `"comment-func"` | `"ea"`, `"comment"` | `"repeatable"` (`bool`, default `true`) | **Yes** (saves & restores old repeatable/non-repeatable comment) |
| `"comment"` | `"ea"`, `"comment"` | `"repeatable"` (`bool`, default `false`) | **Yes** (saves & restores old address comment) |
| `"rename-var"` | `"ea"`, `"old"`, `"new"` | — | **No** — requires `mode="best_effort"` (no compensation) |
| `"create-struct"` | `"definition"` | — | **No** — requires `mode="best_effort"` (no compensation) |
| `"set-type"` | `"ea"`, `"type"` (function C prototype) | — | **No** — requires `mode="best_effort"` (no compensation) |

### Retyping Local Variables + Renaming Functions Safely
- **Local variable retyping (`set_variable_type`) is NOT supported inside `batch_mutations`** (passing `lvar-type` or `set_variable_type` fails validation).
- **Recommended multi-step recipe**:
  1. Lock instance (`list_ida_instances` -> `select_ida_instance(target=...)`).
  2. Register any needed structs first (`create_struct`) and verify `parse_errors == 0`.
  3. Preview function renames: `batch_mutations(mutations='[{"op":"rename-func","ea":"0x...","name":"..."}]', dry_run=True, mode="rollback")`.
  4. Apply function renames with `dry_run=False, mode="rollback"`; verify `rollback_complete` is not `False` and `state != "inspect_required"`.
  5. Apply each local variable type via `set_variable_type(ea, var_name, type_str)`; if a step fails, stop immediately, call `undo` as needed, and re-verify via `decompile(ea)`.
  6. Call `save_database` **only** when `0` failures remain **and** the user explicitly asked to persist changes to disk.

## 2. Hex-Rays Microcode (`0..7`) & `ctree` Deobfuscation

When C pseudocode hides logic or fails due to obfuscation, inspect `get_microcode(ea, maturity=N)`:
- `0` (`MMAT_GENERATED` / `PREOPT`): Raw lifted microcode — exposes dead-store elimination targets, stack strings before constant folding, and anti-analysis junk before optimization.
- `1` (`MMAT_PREOPTIMIZED`) / `2` (`MMAT_LOCOPT`): Local block-level simplifications.
- `3` (`MMAT_CALLS`): Calling conventions & call arguments resolved (`mcallinfo_t`).
- `5` (`MMAT_GLBOPT2`) / `6` (`MMAT_GLBOPT3`): Control-flow flattening / opaque predicates simplified if constants resolved.
- `7` (`MMAT_LVARS`): Final register/stack allocation matching Hex-Rays C output (`get_ctree(ea)` inspects the typed AST nodes `insn`/`expr`, call targets, and constant refs).
- If large obfuscated functions hit `DECOMPILER_TIMEOUT`, check `get_decompiler_timeout()` and raise cautiously via `set_decompiler_timeout(seconds=60)`.

## 3. Live Debugging, Thread Hygiene & Evidence Capture

1. **Status & Thread Safety**:
   - Check `dbg_get_status` (`not_attached` | `running` | `paused` | `breakpoint_hit`).
   - `dbg_get_registers(tid)`, `dbg_set_register(reg_name, value, tid)`, and `dbg_appcall` automatically preserve/restore `prev_tid` and refuse silent cross-thread writes if `select_thread(tid)` fails.
2. **Non-Blocking Waits & Breakpoint Persistence**:
   - `dbg_step_into`, `dbg_step_over`, `dbg_step_out`, `dbg_run_to`, `dbg_continue(..., wait=True)`, and `dbg_wait_event` slice waits in `40ms` `WFNE_USEC | WFNE_SILENT` intervals so `dbg_pause` can interrupt a hung target cleanly.
   - Use `dbg_export_breakpoints(save_path=...)` and `dbg_import_breakpoints(load_path=...)` (client-side JSON I/O) to persist `module+RVA` breakpoints across sessions.
3. **Memory Search & Evidence**:
   - `dbg_search_memory` scans live virtual memory with chunk-boundary overlap (`256 KiB` chunks).
   - `capture_evidence(ea, notes, include_stack=True, include_modules=True, include_breakpoints=True, save_path=...)` snapshots registers (with pointer telescoping), stack, modules, breakpoints, target disassembly, and ASCII/hex memory dumps directly to a client-side JSON file without modifying the IDB.

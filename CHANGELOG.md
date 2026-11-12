# Changelog

## 6.4.0 (2026-11-13)

### Security & Isolation
- Closed conditional-breakpoint script execution bypass: non-empty `condition` expressions on `POST /api/dbg/breakpoint`, `POST /api/dbg/watchpoint`, `POST /api/dbg/update-breakpoint`, and `POST /api/dbg/breakpoints/import` now require `IDA_BRIDGE_ALLOW_EXEC=1` (HTTP `403` otherwise).
- Gated local debugger process launch/attach (`POST /api/dbg/start`, `POST /api/dbg/attach`, local `POST /api/dbg/load`, and inactive-session `POST /api/dbg/run-to`) behind explicit `IDA_BRIDGE_ALLOW_DBG_START=1` (or `IDA_BRIDGE_ALLOW_EXEC=1`), returning HTTP `403` by default.
- Prohibited server-side file writes via `HTTP GET` (`GET /api/dbg/breakpoints/export` and `GET /api/dbg/evidence` reject `?output=` / `?save_path=` with HTTP `400`).
- Restricted server-side file exports/imports (`POST /api/decompile-batch`, `POST /api/dbg/breakpoints/export`, `POST /api/dbg/breakpoints/import`, `POST /api/dbg/evidence`) with `_validate_trusted_file_path` (`IDA_BRIDGE_ALLOWED_EXPORT_ROOTS` / `IDA_BRIDGE_ALLOWED_IMPORT_ROOTS`, symlink rejection, credential-filename block, and `READ_ONLY` enforcement), while moving MCP and CLI file persistence (`decompile_batch`, `dbg_export_breakpoints`, `dbg_import_breakpoints`, `capture_evidence`, `cli.py evidence --save`) completely client-side.
- Secured `~/.ph4ntom_ida_instances.json` (`IDA_BRIDGE_INSTANCES_FILE`) with atomic owner-only DACL / `0600` permissions, dead-PID pruning, `database_inited` metadata refresh, and strict `token_path` validation in `BridgeClient.select_instance()`.
- Removed Python tracebacks and host filesystem paths from HTTP `500` responses while preserving structured `400`/`403` client errors across `_run_synced`; gated `host.docker.internal` in `BridgeClient` behind `IDA_BRIDGE_ALLOW_DOCKER_HOST=1` and stopped retrying HTTP `500` responses.

### Architecture, Debugger Reliability & Performance
- Replaced monolithic `execute_sync` blocking waits in `dbg_wait_event` and synchronous step/continue/run-to operations with `40ms` `WFNE_USEC | WFNE_SILENT` slices (`_dbg_wait_sliced`), keeping IDA's UI responsive, dequeuing IDA 9.5 debug events cleanly (including `ev.exc()` details and immediate `DEC_NOTASK` termination), suppressing modal warning dialogs in headless/MCP sessions, and allowing concurrent `POST /api/dbg/pause` without deadlocking.
- Enforced strict thread-selection verification and `finally`-block restoration across `_read_regs_inner`, `dbg_get_regs`, `dbg_set_reg`, and `dbg_appcall_api` so failed `select_thread(tid)` calls never mutate or leak another thread's registers/IP/SP.
- Consolidated `get_call_graph` into a single `safe_read` synchronization barrier and updated it (along with `get_xrefs_from`, `get_callees`, and `get_strings_used`) to iterate `_iter_func_items` across non-contiguous function chunks while preserving multiple call sites to the same callee.
- Added chunk-boundary overlap and hit deduplication to `dbg_search_memory_api` so patterns straddling `256 KiB` boundaries are reliably detected.
- Eliminated `build_strlist()` rebuilds on paginated `GET /api/strings` requests and removed duplicate startup/shutdown banners in IDA's Output window.

### Firmware, SDK Contracts & MCP Expansion (98 → 131 Tools)
- Fixed Hex-Rays decompiler timeout conversion (`seconds` ↔ milliseconds in `DECOMPILER_TIMEOUT`), `capture_evidence` contract fields (`target.disasm`, `ascii`, `notes`, `include_*` flags), safe regex fallback (`_compile_filter_regex`) across strings/xrefs/classes, `GET /api/classes` & `GET /api/class/<name>` query routing, `dbg_update_bp(tid=0)` clearing thread filters, exception name/flag preservation in `dbg_configure_exception_api`, pointer-width telescoping, ARM Thumb vtable resolution & function prototypes, and 32/64-bit/PIC jump-table parsing in `get_switch_info`.
- Improved embedded/firmware support (`imagebase == 0` formats `module_rva` as `SEG+0xOFFSET`, `BADADDR` entry point serializes as `None`, symbol names take precedence over bare hex strings like `add`/`dead` in `parse_ea`, hyphenated `.so` module names resolve cleanly in `module+RVA`, and `execute_batch` accepts symbolic/`module+RVA` addresses).
- Exposed all **33 remaining REST capabilities** as annotated MCP tools in `mcp_server.py` (**131 total MCP tools**, plus `ph4ntom-mcp` console script), fixed query-string handling in `agent.py`, and fixed status/URL-encoding bugs in `integrations/ide_extension.py`.
- Bundled a portable **IDA Pro 9.5 Agent Skill** in `.agents/skills/ida-pro/` (`SKILL.md` + `idapython-95-sdk.md`, `firmware-types-and-vtables.md`, and `debugging-microcode-and-batch.md` references) with `ph4ntom-ida install-skill` (`--runtime antigravity|agents|claude`, `--dest`, `--force`), and added animated live workflow demo & Retina feature screenshots in `assets/`.

## 6.3.0 (2026-11-08)

- Added full **IDA Professional 9.5** SDK compatibility:
  - Updated debugger hook registration to support IDA 9.5 `ida_dbg.DBG_Hooks` while preserving backward compatibility with legacy `DbgHooks`.
  - Updated binary bitness detection to use `ida_ida.inf_is_32bit_exactly()` and `inf_is_16bit()` (replacing removed `inf_is_32bit()`).
  - Updated hardware breakpoint/watchpoint mode resolution across `ida_dbg`, `ida_idd`, and `idc` (`BPT_EXEC`, `BPT_WRITE`, `BPT_READ`, `BPT_RDWR`, `BPT_SOFT`).
  - Updated thread enumeration to use `ida_dbg.getn_thread_name(i)` (replacing removed `get_thread_name(tid)`).
  - Added IDA 9.5 Hex-Rays language-neutral Class Model endpoints (`GET /api/classes`, `GET /api/class/<name>`), Decompiler Timeout controls (`GET/POST /api/decompiler/timeout`), and exact cross-reference matching (`XREF_EXACT`).
  - Enhanced `cli.py` IDA auto-discovery to detect `IDA Professional 9.5` and added `install-plugin --user` for `$IDAUSR/plugins`.
- Expanded **Dynamic Debugging**, **Static Analysis**, and **Evidence & Multi-Instance** suite to 139 REST endpoints and 98 MCP tools:
  - Explicit debugger status enum (`not_attached`, `running`, `paused`, `breakpoint_hit`) across `/api/dbg/status` and `/api/dbg/regs`.
  - Symbolic `module+RVA` address resolution (`networksystem.dll+0xC3EA7`) across all endpoints with automatic live ASLR module base calculation.
  - Hardware data watchpoints (`BPT_READ`, `BPT_WRITE`, `BPT_RDWR`) with configurable byte range `size`, conditional breakpoints (`condition`, `elang`), thread filtering (`tid`), hit counters (`hit_count`), and `action="log_and_continue"` auto-resume register logging.
  - Breakpoint persistence (`GET/POST /api/dbg/breakpoints/export`, `POST /api/dbg/breakpoints/import`) and structured JSON evidence capture (`GET/POST /api/dbg/evidence` / `capture_evidence`).
  - Static analysis range & regex filters, full pagination beyond 2000 strings / 1000 names, arbitrary range disassembly (`GET /api/disasm-range`), clean `get_strings_used` (excluding machine code instructions), batch decompilation (`POST /api/decompile-batch`), and vtable C structure generation (`POST /api/vtable/create-struct`).
  - Multi-instance IDA support (`13370..13389`, `~/.ph4ntom_ida_instances.json`, `list_ida_instances`, `select_ida_instance`).
  - Synchronous step/continue/run-to waiting (`POST /api/dbg/step-out`, `POST /api/dbg/run-to`, `POST /api/dbg/wait`, and `wait=true` on `step-into`, `step-over`, `continue`).
  - Register telescoping & modification (`GET /api/dbg/regs`, `POST /api/dbg/set-reg`), live memory map (`GET /api/dbg/memory-map`), memory refresh (`POST /api/dbg/refresh-memory`), and live process memory search (`POST /api/dbg/search-memory`).
  - Loaded modules (`GET /api/dbg/modules`), thread control (`POST /api/dbg/thread-action`), instruction/function/basic-block tracing (`POST /api/dbg/trace/configure`, `GET /api/dbg/trace`, `POST /api/dbg/trace/clear`), exception table management (`GET/POST /api/dbg/exceptions`), and buffered debugger event hooks (`GET /api/dbg/events`, `POST /api/dbg/events/clear`).
  - Opt-in raw debugger CLI commands (`POST /api/dbg/cmd`) and target process Appcall (`POST /api/dbg/appcall`) guarded by `IDA_BRIDGE_ALLOW_EXEC=1`.

## 6.2.0 (2026-09-07)

- Fixed IDA 9.3 structure member creation/deletion, enum widths, persistent
  local-variable names/types/comments, combined analysis context, and saving
  the current database with truthful status.
- Verify byte patches and exact names after mutation; detect partial debugger
  memory writes and use the correct hardware execution-breakpoint type.
- Importing the plugin or failing to bind an occupied port no longer rotates
  a running server's token. Windows token files use a protected owner-only DACL
  before any secret bytes are written. Explicit token-file failures fail closed.
- Reject remote/ambiguous headers, duplicate JSON fields, non-finite JSON,
  malformed function paths, oversized reads and invalid pagination/depth.
  Bound HTTP connections and body-read time; add a read-only server option.
- Broadcast events to independent bounded subscriber queues, report overflow,
  and release disconnected subscribers, including failed header writes.
- Keep client tokens on loopback, ignore proxy/netrc environment settings,
  prohibit redirects, and mark uncertain writes without replaying them.
- MCP now reports bridge failures as protocol errors and annotates read/write
  tools. Launch readiness probes respect the overall deadline.
- Make plugin installation staged and recoverable with preserved backups;
  add `doctor` and process-scoped launch autostart.
- Expand socket/failure regression tests and licensed IDA integration checks,
  including saving, exiting IDA and reopening the resulting database.

## 6.1.0

### Changed

- Renamed the project, Python distribution, CLI command, server identity, token
  file, and IDA plugin to **ph4ntom IDA Bridge**.
- Renamed the canonical GitHub repository to `ph4ntom-ida-bridge`.

### Fixed

- Added IDA 9.3 compatibility for segments, local types, structures, enums,
  byte search, stack variables, debugger memory, and call stacks.
- Made `/api/schema` work when IDA executes the plugin without defining
  `__file__`.

## 6.0.0

### Fixed

- Merged duplicate function routers that made ctree, microcode, callers,
  callees, string-use, local-variable type, and local-variable comment actions
  unreachable.
- Removed the divergent second server implementation; `server.py` is now a
  compatibility wrapper around the canonical IDA plugin.
- Fixed duplicate UI/debug hook registration and incomplete shutdown cleanup.
- Corrected all CLI, MCP, and agent documentation paths.
- Added automatic token refresh after IDA restarts.

### Security

- Session tokens are 256-bit, atomically written, and owner-readable only where
  supported.
- Token values are no longer printed to the IDA log.
- Authorization comparison is constant-time.
- POST requests are limited to 5 MiB and validated as UTF-8 JSON objects.
- Host and browser-origin checks restrict access to localhost.
- Dynamic IDAPython and local header imports are disabled by default.

### Added

- Full CLI with generic API access, safe plugin installation, launch, and wait
  commands.
- Python package metadata, console entry point, optional dependency groups, and
  wheel resources.
- GitHub Actions checks for Python 3.10–3.12.
- Runtime tests for authentication, CORS, body limits, route coverage, MCP
  registration, packaging, CLI behavior, and repository contracts.
- Dry-run-by-default behavior for the swarm worker.

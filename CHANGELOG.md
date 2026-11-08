# Changelog

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

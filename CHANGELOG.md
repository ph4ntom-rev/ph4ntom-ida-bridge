# Changelog

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

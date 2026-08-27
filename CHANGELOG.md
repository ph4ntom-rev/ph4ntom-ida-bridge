# Changelog

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

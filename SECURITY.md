# Security

ph4ntom IDA Bridge runs code inside the IDA Pro process. Treat access to the
bridge as equivalent to local code execution under the IDA user's account.

## Secure defaults

- The server binds to `127.0.0.1`.
- Session tokens (`~/.ph4ntom_ida_bridge_token` and `~/.ph4ntom_ida_bridge_token_<port>`)
  and the multi-instance registry (`~/.ph4ntom_ida_instances.json`) are written
  atomically using POSIX mode `0600` or a protected Windows owner-only DACL
  before bytes hit disk. A new token is published only after successfully
  binding the port, and stale registry entries for exited PIDs are pruned.
- Dynamic IDAPython execution (`/api/exec`, `/api/dbg/cmd`, `/api/dbg/appcall`,
  and non-empty breakpoint/watchpoint `condition` expressions) is disabled unless
  `IDA_BRIDGE_ALLOW_EXEC=1` is present before IDA starts.
- Launching or attaching to a local process (`POST /api/dbg/start`,
  `POST /api/dbg/attach`, local `POST /api/dbg/load`, and `POST /api/dbg/run-to`
  when no debug session is active) is disabled unless `IDA_BRIDGE_ALLOW_DBG_START=1`
  or `IDA_BRIDGE_ALLOW_EXEC=1` is set before IDA starts.
- `HTTP GET` routes never write files to disk (`?output=` / `?save_path=` on
  `GET` returns HTTP `400`).
- Server-side file reads (`POST /api/import-header`, `POST /api/dbg/breakpoints/import`
  with `path`) and server-side file writes (`POST /api/decompile-batch`,
  `POST /api/dbg/breakpoints/export`, `POST /api/dbg/evidence` with `output_path`)
  are rejected unless trusted root directories are configured through
  `IDA_BRIDGE_ALLOWED_IMPORT_ROOTS` and `IDA_BRIDGE_ALLOWED_EXPORT_ROOTS`
  respectively, with symlink/reparse-point and credential-filename protections.
  CLI and MCP tools perform file export/import client-side by default.
- POST bodies are limited to 5 MiB; unhandled server errors never expose host
  file paths or Python tracebacks in HTTP responses.
- Browser CORS access is limited to localhost origins.
- Up to 16 HTTP connections and four event subscribers are accepted. Idle socket
  reads expire after five seconds; memory transfers are limited to 1 MiB.
- Set `IDA_BRIDGE_READ_ONLY=1` before starting IDA to reject all POST requests.
- HTTP clients ignore environment proxies/netrc, reject non-loopback URLs
  (`host.docker.internal` requires explicit `IDA_BRIDGE_ALLOW_DOCKER_HOST=1`),
  validate registry `token_path` values before reading them, never retry HTTP 500
  responses, and never follow redirects. Transport failures after writes report
  uncertain delivery; inspect the database before repeating such a request.

The socket deadline is not an IDA execution deadline: a queued main-thread
operation may finish after a caller disconnects. The bridge does not promise
transactional rollback for arbitrary IDA state, debugger operations or scripts.
Read-only mode blocks HTTP mutations; it is not a sandbox for IDA or other plugins.
Protect the local account and trusted import directories as well as the token.

Do not expose port 13370 through a public interface, port-forward, reverse
proxy, or shared development tunnel. Do not disable authentication on an
untrusted machine.

## Reporting a vulnerability

Open a private GitHub security advisory for the repository. Do not publish
working exploits or session tokens in a public issue.

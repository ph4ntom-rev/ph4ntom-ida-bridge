# Security

ph4ntom IDA Bridge runs code inside the IDA Pro process. Treat access to the
bridge as equivalent to local code execution under the IDA user's account.

## Secure defaults

- The server binds to `127.0.0.1`.
- A 256-bit session token is stored in `~/.ph4ntom_ida_bridge_token` using POSIX
  mode 0600 or a protected Windows owner-only DACL, before secret bytes are
  written. A new token is published only after successfully binding the port.
- Dynamic IDAPython execution is disabled unless `IDA_BRIDGE_ALLOW_EXEC=1` is
  present before IDA starts.
- Header imports are disabled unless trusted directories are configured through
  `IDA_BRIDGE_ALLOWED_IMPORT_ROOTS`.
- POST bodies are limited to 5 MiB.
- Browser CORS access is limited to localhost origins.
- Up to 16 HTTP connections and four event subscribers are accepted. Idle socket
  reads expire after five seconds; memory transfers are limited to 1 MiB.
- Set `IDA_BRIDGE_READ_ONLY=1` before starting IDA to reject all POST requests.
- HTTP clients ignore environment proxies/netrc, reject non-loopback URLs, and
  never follow redirects. Transport failures after writes report uncertain
  delivery; inspect the database before repeating such a request.

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

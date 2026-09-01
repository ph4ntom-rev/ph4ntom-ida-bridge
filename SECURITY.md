# Security

ph4ntom IDA Bridge runs code inside the IDA Pro process. Treat access to the
bridge as equivalent to local code execution under the IDA user's account.

## Secure defaults

- The server binds to `127.0.0.1`.
- A 256-bit session token is stored in `~/.ph4ntom_ida_bridge_token` with owner-only
  permissions where the operating system supports them.
- Dynamic IDAPython execution is disabled unless `IDA_BRIDGE_ALLOW_EXEC=1` is
  present before IDA starts.
- Header imports are disabled unless trusted directories are configured through
  `IDA_BRIDGE_ALLOWED_IMPORT_ROOTS`.
- POST bodies are limited to 5 MiB.
- Browser CORS access is limited to localhost origins.

Do not expose port 13370 through a public interface, port-forward, reverse
proxy, or shared development tunnel. Do not disable authentication on an
untrusted machine.

## Reporting a vulnerability

Open a private GitHub security advisory for the repository. Do not publish
working exploits or session tokens in a public issue.

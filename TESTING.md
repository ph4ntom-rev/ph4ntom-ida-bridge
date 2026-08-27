# IDA test checklist

Use IDA Pro 9.x with a disposable binary and a copy of the IDA database. Do not
use a production database for the first write/debugger tests.

## 1. Install the rebuilt plugin

```powershell
python -m pip install -e ".[dev,mcp]"
python cli.py install-plugin --ida-dir "C:\Path\To\IDA" --force
```

The installer should report both `antigravity_server.py` and `api_schema.json`.
Existing differing files are backed up with a `.bak` suffix.

## 2. Start and authenticate

1. Start IDA and load a test binary.
2. Press `Ctrl+Shift+A`.
3. Confirm the IDA output reports version 6 startup, the localhost URL, and a
   token-file path. It must not print the token value.
4. Run:

```powershell
python cli.py ping
python cli.py schema
python cli.py info
```

Expected `ping` fields include:

```json
{
  "status": "ok",
  "version": "6.0.0",
  "auth_enabled": true,
  "dynamic_exec_enabled": false
}
```

## 3. Read-only regression tests

Choose a valid function address returned by `functions` and replace `<ea>`:

```powershell
python cli.py functions --limit 20
python cli.py decompile <ea>
python cli.py xrefs <ea>
python cli.py callers <ea>
python cli.py callees <ea>
python cli.py api GET /api/function/<ea>/lvar-map
python cli.py api GET /api/function/<ea>/ctree
python cli.py api GET /api/function/<ea>/microcode --param maturity=7
```

The final six function actions were previously shadowed by duplicate routes;
they must now return endpoint-specific results rather than `Unknown action`.

## 4. Write and rollback test

On a disposable database:

```powershell
python cli.py rename-func <ea> codex_test_function
python cli.py api POST /api/function/<ea>/comment --body "{\"comment\":\"bridge test\"}"
python cli.py api POST /api/undo
```

Verify the name/comment in IDA. Test `save` only when persisting the disposable
database is acceptable.

## 5. Dynamic execution opt-in

With the default configuration, this must return HTTP 403:

```powershell
python cli.py exec "result['ea'] = hex(idc.here())"
```

Close IDA, set the flag, and restart it:

```powershell
$env:IDA_BRIDGE_ALLOW_EXEC = "1"
```

After toggling the plugin, `ping` should report `dynamic_exec_enabled: true` and
the same command should return a result. Remove the environment variable after
testing if dynamic execution is not required.

## 6. MCP registration

```powershell
python verify_mcp.py
```

Expected: 54 tools and 2 resources. Then connect an MCP client using the absolute
path to `mcp_server.py` and run `ping`, `get_binary_info`, and `decompile`.

## 7. Shutdown test

Press `Ctrl+Shift+A` repeatedly to stop and restart the server. Each toggle
should produce one start/stop event, without duplicate cursor/debugger events or
an occupied-port error.

When reporting a failure, include the command, sanitized JSON response, IDA
version, and relevant IDA output. Never include the contents of the token file.

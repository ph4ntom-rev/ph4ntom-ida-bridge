# IDA test checklist

## Automated verification for 6.2.0

```powershell
python -m pip install ".[dev,mcp]"
python -m pytest -q
python -m flake8 . --select=F --exclude=.venv
gcc tests/fixtures/batch_fixture.c -o batch_fixture.exe -O0 -g
python tests/integration/run_ida.py --ida "C:\Path\To\IDA\idat.exe" --fixture batch_fixture.exe --report ida-results.json
```

The licensed integration runner creates a disposable database, exercises SDK
reads/writes, tests batch preview and injected rollback failure, then saves,
exits IDA, reopens the database in a second process and verifies persistent
local-variable metadata, function names, structures and enum widths.
Never pass an existing user database to this runner.

For an installed wheel and a running IDA instance loaded with the exact compiled
fixture, verify actual stdio MCP and REST paths from outside the source checkout:

```powershell
python tests/integration/verify_live.py --python "C:\Installed\venv\Scripts\python.exe" --fixture "C:\Test\batch_fixture.exe" --report live-results.json
```

The live test checks registration, resources, decompilation, analysis calls,
preview, reversible rename, error propagation, script-execution refusal,
saving, combined context, and concurrent event connections. It restores the
fixture function name before saving.

Local verification covers Windows and IDA Professional 9.3 with x64 Hex-Rays.
Unit tests use Python 3.10 and 3.12. This is not certification for every IDA 9.x
release, architecture, debugger backend, or third-party plugin combination.
Debugger memory/breakpoint failure cases have stubbed regression coverage;
full live debugger sessions and ARM targets require additional licensed tests.

Use IDA Pro 9.x with a disposable binary and a copy of the IDA database. Do not
use a production database for the first write/debugger tests.

## 1. Install the rebuilt plugin

```powershell
python -m pip install -e ".[dev,mcp]"
python cli.py install-plugin --ida-dir "C:\Path\To\IDA" --force
```

The installer should report both `ph4ntom_ida_bridge.py` and `api_schema.json`.
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
  "version": "6.2.0",
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

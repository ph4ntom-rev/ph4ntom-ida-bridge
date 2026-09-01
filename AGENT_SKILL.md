# ph4ntom IDE ↔ IDA Bridge agent guide

Use `cli.py` to communicate with the REST server running inside IDA Pro at
`http://127.0.0.1:13370`. Commands return JSON and automatically load the
session token from `~/.ph4ntom_ida_bridge_token`.

## Safety rules

1. Start with read-only inspection.
2. Do not rename, comment, patch, debug, execute code, or save the database
   unless the user has authorized that class of change.
3. Prefer a documented endpoint over dynamic IDAPython.
4. Treat `/api/exec` as local code execution. It is unavailable unless the IDA
   process was started with `IDA_BRIDGE_ALLOW_EXEC=1`.
5. Use `/api/batch` for related mutations so failures can be rolled back.
6. Work on a copy of the database when testing destructive operations.

## Quick reference

```bash
python cli.py ping
python cli.py info
python cli.py functions --limit 100
python cli.py strings --filter "password|token|http"
python cli.py decompile 0x140001000
python cli.py xrefs 0x140001000
python cli.py callers 0x140001000
python cli.py callees 0x140001000
python cli.py api GET /api/function/0x140001000/ctree
python cli.py api GET /api/function/0x140001000/microcode --param maturity=0
python cli.py api POST /api/function/0x140001000/rename --body "{\"name\":\"init_network\"}"
```

Dynamic execution, when explicitly enabled:

```bash
python cli.py exec "result['current_ea'] = hex(idc.here())"
python cli.py exec --file analysis.py
```

## Analysis workflow

1. Run `python cli.py ping` and check the reported capabilities.
2. If offline, ask the user to start IDA and toggle the plugin with
   `Ctrl+Shift+A`, or use `python cli.py launch <binary> --wait` when launching
   IDA is within scope.
3. Run `info`, then page through `functions` and inspect relevant strings,
   imports, and exports.
4. Decompile candidate functions and verify conclusions with xrefs, callers,
   callees, ctree, or microcode.
5. Present findings before making database changes unless the user already
   requested those changes.
6. After authorized mutations, verify the changed object and save only when the
   user asked to persist the database.

The complete API is available through `python cli.py schema` and
`api_schema.json`.

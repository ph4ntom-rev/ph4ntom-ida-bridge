# ph4ntom IDA Bridge

ph4ntom IDA Bridge is a localhost-only control layer for IDA Pro 9.x. It
combines a self-contained IDA plugin, a JSON REST API, a Python client, a CLI,
54 MCP tools, and optional standalone AI backends.

The API schema currently documents 54 read endpoints and 48 write endpoints.
The bridge has been validated against IDA Professional 9.3 in addition to the
repository test suite, which covers the client, CLI, schema, routing contract,
MCP registration, packaging, and security defaults.

## Security model

The bridge runs inside IDA, so authenticated write access is powerful. The
`/api/exec` endpoint is equivalent to local code execution as the IDA user.

Version 6 uses these defaults:

- binds only to `127.0.0.1:13370`;
- creates a 256-bit session token in `~/.ph4ntom_ida_bridge_token`;
- refreshes stale tokens automatically after an IDA restart;
- limits POST bodies to 5 MiB;
- permits browser CORS only from localhost origins;
- disables dynamic IDAPython execution by default;
- disables local C-header imports until trusted directories are configured.

Never expose port 13370 through a public interface, tunnel, or reverse proxy.
See [SECURITY.md](SECURITY.md) for the full guidance.

## Components

| Path | Purpose |
| --- | --- |
| `ida_plugin/ph4ntom_ida_bridge.py` | Canonical IDA plugin and REST server |
| `api_schema.json` | Machine-readable REST reference |
| `core/client.py` | Shared authenticated HTTP client |
| `cli.py` | CLI, plugin installer, and IDA launcher |
| `mcp_server.py` | MCP server exposing 54 tools and two resources |
| `agent.py` | Optional interactive agent with multiple LLM backends |
| `swarm_worker.py` | Optional structured-analysis worker |
| `agent_config.json` | Machine-readable integration configuration |
| `AGENT_SKILL.md` | Instructions for IDE-based agents |

`server.py` remains only as a compatibility wrapper. All server changes belong
in `ida_plugin/ph4ntom_ida_bridge.py` so the two implementations cannot drift.

## Install

Python 3.10 or newer is required for the external tools. IDA itself supplies
the IDAPython modules used by the plugin.

```bash
git clone https://github.com/ph4ntom-rev/ph4ntom-ida-bridge.git
cd ph4ntom-ida-bridge
python -m pip install -e .
```

Install the plugin and API schema into IDA:

```bash
python cli.py install-plugin --ida-dir "C:\Program Files\IDA Professional 9.0"
```

If an older installed copy differs, review it and then use `--force`. The
installer creates a `.bak` file before replacement.

Manual installation is also supported: copy both files below into IDA's
`plugins` directory.

```text
ida_plugin/ph4ntom_ida_bridge.py
api_schema.json
```

Start IDA and press `Ctrl+Shift+A` to toggle the server. The IDA output window
shows the URL and token-file location, but never prints the token itself.

## CLI quick start

```bash
python cli.py ping
python cli.py info
python cli.py functions --limit 100
python cli.py strings --filter "socket|http"
python cli.py decompile 0x140001000
python cli.py xrefs 0x140001000
python cli.py callers 0x140001000
python cli.py api GET /api/function/0x140001000/ctree
python cli.py api POST /api/function/0x140001000/rename --body "{\"name\":\"init_network\"}"
```

The installed console command is equivalent:

```bash
ph4ntom-ida ping
```

To launch IDA without silently installing or replacing anything:

```bash
python cli.py launch sample.exe --wait
```

Use `--headless` only when autonomous IDA analysis is intended.

## Optional dynamic IDAPython

Dynamic execution is intentionally off by default. Enable it before launching
IDA only on a trusted machine.

PowerShell:

```powershell
$env:IDA_BRIDGE_ALLOW_EXEC = "1"
```

Bash:

```bash
export IDA_BRIDGE_ALLOW_EXEC=1
```

Then execute inline code, a file, or stdin:

```bash
python cli.py exec "result['ea'] = hex(idc.here())"
python cli.py exec --file analysis.py
python generate_script.py | python cli.py exec -
```

Scripts receive full IDAPython access and a `result` dictionary. Standard output
and standard error are captured in the JSON response.

## Header imports

`POST /api/import-header` is disabled until trusted roots are supplied before
IDA starts. Separate multiple directories with the operating system path
separator (`;` on Windows, `:` on Unix-like systems).

```powershell
$env:IDA_BRIDGE_ALLOWED_IMPORT_ROOTS = "C:\reverse\headers;D:\sdk\include"
```

## MCP

Install the MCP extra:

```bash
python -m pip install -e ".[mcp]"
```

Use absolute paths in the MCP client configuration:

```json
{
  "mcpServers": {
    "ida-bridge": {
      "command": "python",
      "args": ["C:/path/to/ph4ntom-ida-bridge/mcp_server.py"]
    }
  }
}
```

The shared client detects token rotation, so the MCP process does not need to be
restarted every time IDA restarts.

## Optional agent backends

Install all provider integrations:

```bash
python -m pip install -e ".[agents]"
python agent.py --backend ollama
```

Available backends are Ollama, Gemini, OpenAI-compatible APIs, Anthropic, and
DeepSeek. Provider API keys are read from environment variables; they are not
stored by this repository.

## REST API

Every response is JSON. Addresses are normally written as hexadecimal strings.
Use the live schema endpoint or the checked-in schema for the complete reference:

```bash
python cli.py schema
```

Key endpoint groups include:

- binary metadata, functions, instructions, strings, imports, and exports;
- pseudocode, ctree, microcode, local variables, callers, and callees;
- cross-references, control-flow graphs, types, structures, and enums;
- database mutations with batch rollback support;
- debugger control, registers, threads, stack, and memory;
- cursor events over server-sent events.

## Development

```bash
python -m pip install -e ".[dev,mcp]"
python -m compileall -q agent.py cli.py core ida_plugin integrations mcp_server.py server.py swarm_worker.py tests
python -m flake8 . --select=F --exclude=.venv
python -m pytest -q
python verify_mcp.py
```

GitHub Actions runs syntax checks, Flake8 correctness checks, and tests on
Python 3.10, 3.11, and 3.12. Tests that exercise real IDA SDK behavior must be
performed manually inside IDA using a disposable database before release.
Follow [TESTING.md](TESTING.md) for the IDA smoke and regression checklist.

## License

MIT

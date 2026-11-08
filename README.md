# ph4ntom IDA Bridge 🌉

> **Autonomous AI & MCP Control Layer for IDA Pro 9.x**  
> Turn IDA Pro into an agentic reverse-engineering powerhouse. Connect Claude Desktop, Cursor, Antigravity, or custom LLM agents via Model Context Protocol (MCP) or high-performance REST API.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![IDA Pro 9.x](https://img.shields.io/badge/IDA_Pro-9.0--9.5-blueviolet?style=flat-square)](https://hex-rays.com)
[![MCP Compatible](https://img.shields.io/badge/MCP-98_Tools_|_2_Resources-00c853?style=flat-square&logo=anthropic&logoColor=white)](#mcp-tools-reference)
[![Glama Rating](https://glama.ai/mcp/servers/ph4ntom-rev/ph4ntom-ida-bridge/badges/score.svg)](https://glama.ai/mcp/servers/ph4ntom-rev/ph4ntom-ida-bridge)
[![REST API](https://img.shields.io/badge/REST_API-139_Endpoints-orange?style=flat-square)](#rest-api)
[![Release](https://img.shields.io/badge/release-v6.3.0-blue?style=flat-square)](https://github.com/ph4ntom-rev/ph4ntom-ida-bridge/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Security Hardened](https://img.shields.io/badge/security-localhost_only_|_token_auth-red?style=flat-square)](#security-model)

---

```
              ┌─────────────────────────────────────────────────────────┐
              │                     IDA Pro 9.0–9.5                     │
              │         ph4ntom_ida_bridge.py (139 REST Endpoints)      │
              │      127.0.0.1:13370..13389 (Bearer Token Protected)    │
              └────────────────────────────┬────────────────────────────┘
                                           │ REST / JSON / SSE
          ┌────────────────────────────────┼───────────────────────────────┐
          ▼                                ▼                               ▼
   ┌───────────────┐               ┌───────────────┐               ┌───────────────┐
   │  MCP Server   │               │   CLI / SDK   │               │   AI Agents   │
   │  98 Tools     │               │  `ph4ntom-ida`│               │  Multi-LLM    │
   │  Claude       │               │  Automation   │               │  Gemini       │
   │  Cursor       │               │  Headless     │               │  Ollama       │
   │  Antigravity  │               │  Testing      │               │  Claude / GPT │
   └───────────────┘               └───────────────┘               └───────────────┘
```

**ph4ntom IDA Bridge** is a localhost-only control layer for **IDA Pro 9.x (including 9.5)**. It combines a self-contained IDA plugin, a JSON REST API, a Python client, a CLI, 98 native MCP tools, and optional standalone AI backends.

Version **6.3.0** brings full **IDA Professional 9.5** support (including `DBG_Hooks`, `inf_is_32bit_exactly`, Hex-Rays Class Model API, decompiler timeouts, and `XREF_EXACT`), **ASLR-aware `module+RVA` addressing**, **multi-instance support** (`13370..13389`), **static analysis pagination/range filters/vtable struct generation**, **forensic evidence capture**, and a **40-tool Dynamic Debugging** suite (hardware read/write watchpoints with range size, conditional breakpoints with `log_and_continue` & thread filtering, explicit debugger states `not_attached`/`running`/`paused`/`breakpoint_hit`, breakpoint export/import across runs, register telescoping & editing, live memory map & search, instruction/function/basic-block tracing, exception handling, thread control, debugger event logs, and opt-in Appcall).

---

## ⚡ Quickstart: Claude Desktop & Cursor (1-Click MCP Setup)

Connect Claude Desktop, Cursor, or any MCP client to your running IDA Pro instance in 60 seconds:

### 1. Clone & Install
```bash
git clone https://github.com/ph4ntom-rev/ph4ntom-ida-bridge.git
cd ph4ntom-ida-bridge
python -m pip install -e ".[mcp]"
```

### 2. Install Plugin into IDA Pro
```bash
python cli.py install-plugin --ida-dir "C:\Program Files\IDA Professional 9.0"
```
*(Or copy `ida_plugin/ph4ntom_ida_bridge.py` and `api_schema.json` directly into your IDA `plugins/` directory).*

### 3. Add to your MCP Config

#### 🟣 Claude Desktop
Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "ida-bridge": {
      "command": "python",
      "args": [
        "C:/path/to/ph4ntom-ida-bridge/mcp_server.py"
      ]
    }
  }
}
```

#### 💻 Cursor / Windsurf
Add to `.cursor/mcp.json` or Cursor Settings → MCP:
```json
{
  "mcpServers": {
    "ida-bridge": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "C:/path/to/ph4ntom-ida-bridge"
    }
  }
}
```

Start IDA Pro, press `Ctrl+Shift+A` to toggle the server, and prompt your AI assistant:
> *"Inspect the function at 0x140001000. Trace cross-references, analyze microcode, decompile to C pseudocode, and rename obfuscated variables to meaningful names."*

---

## ⚔️ Comparison with Alternatives

| Feature | **ph4ntom IDA Bridge** | Gepetto / IDAGPT | Hex-Rays Copilot |
|:---|:---:|:---:|:---:|
| **Architecture** | **Bi-directional MCP + REST + CLI** | Single prompt-wrapper | Proprietary UI plugin |
| **Tool Count** | **98 Granular MCP Tools** | 1 (Decompile prompt) | Fixed prompt actions |
| **AST & Control Flow** | **Full ctree AST + Microcode IR (0-7)** | Pseudocode text only | Pseudocode text only |
| **Safe Mutations** | **Atomic batch mutations with rollback** | Comment insertion only | Suggestions in UI |
| **Live Debugger** | **40 Tools: Watchpoints, Conditional BPs, Trace, Appcall, Evidence** | No | No |
| **Dynamic Execution** | **On-the-fly IDAPython execution engine** | No | No |
| **Supported LLMs** | **Any MCP Client / Claude / GPT / Gemini / Ollama** | OpenAI API only | Proprietary cloud |
| **Security & Auth** | **Localhost-only, 256-bit token, Owner DACL** | Exposed plain API key | Proprietary |
| **IDA Pro 9.5 Support** | **Verified & fully tested (9.0–9.5)** | Broken on IDA 9+ | Official |

---

## 🛠️ MCP Tools Reference (98 Tools & 2 Resources)

The MCP server exposes 98 purpose-built tools across 8 reverse-engineering domains:

| Category | Tools | Description |
|:---|:---|:---|
| **🔍 Binary, Vtables & Multi-Instance** | `ping`, `get_binary_info`, `list_segments`, `read_bytes`, `read_vtable`, `create_vtable_struct`, `list_ida_instances`, `select_ida_instance` | Binary metadata, hashes, `module+RVA`, vtable extraction & C struct generation, multi-instance switching |
| **🧩 Decompilation, AST & IDA 9.5 Classes** | `decompile`, `decompile_batch`, `get_disassembly`, `get_disasm_range`, `get_ctree`, `get_microcode`, `get_local_variables`, `get_function_details`, `list_classes`, `get_class`, `get_decompiler_timeout`, `set_decompiler_timeout` | Hex-Rays C pseudocode, batch decompile, arbitrary range disasm, AST ctree JSON, Microcode IR (0–7), IDA 9.5 Class Model |
| **🕸️ Callgraphs & Xrefs** | `get_xrefs_to`, `get_xrefs_from`, `get_callers`, `get_callees`, `get_call_graph`, `get_basic_blocks`, `get_strings_used` | Filtered & paginated cross-references (`XREF_EXACT`), caller trees, clean string literals without machine code |
| **🔎 Search & Paginated Exploration** | `list_functions`, `search_function`, `search_bytes`, `search_text`, `list_strings`, `list_names`, `list_imports`, `list_exports` | Full pagination (`offset`/`limit`) and `[start_ea, end_ea)` range filters beyond 2000/1000 limits |
| **🏷️ Types & Structs** | `list_structs`, `get_struct`, `list_enums`, `list_types`, `get_type`, `create_type`, `create_struct` | C declaration parsing, structure definitions, enum member inspection |
| **✏️ Database Mutation** | `rename_function`, `comment_function`, `set_inline_comment`, `rename_variable`, `set_variable_type`, `set_function_type`, `patch_bytes`, `batch_mutations`, `undo`, `redo`, `save_database`, `navigate_to` | Verified renaming, local variable typing, binary patching, atomic rollback |
| **🐞 Live Debugger & Evidence** | `dbg_get_status`, `dbg_load_debugger`, `dbg_start`, `dbg_exit`, `dbg_list_processes`, `dbg_attach`, `dbg_detach`, `dbg_pause`, `dbg_set_breakpoint`, `dbg_set_watchpoint`, `dbg_list_breakpoints`, `dbg_delete_breakpoint`, `dbg_toggle_breakpoint`, `dbg_update_breakpoint`, `dbg_export_breakpoints`, `dbg_import_breakpoints`, `capture_evidence`, `dbg_continue`, `dbg_step_into`, `dbg_step_over`, `dbg_step_out`, `dbg_run_to`, `dbg_wait_event`, `dbg_get_registers`, `dbg_set_register`, `dbg_read_memory`, `dbg_write_memory`, `dbg_get_memory_map`, `dbg_refresh_memory`, `dbg_search_memory`, `dbg_list_modules`, `dbg_list_threads`, `dbg_thread_action`, `dbg_get_stack`, `dbg_configure_trace`, `dbg_get_trace`, `dbg_clear_trace`, `dbg_list_exceptions`, `dbg_configure_exception`, `dbg_get_events`, `dbg_clear_events`, `dbg_send_command`, `dbg_appcall` | Explicit debugger states, read/write/rw hardware watchpoints, conditional `log_and_continue` breakpoints with thread filtering, `module+RVA` ASLR persistence, and JSON evidence capture |
| **⚡ Dynamic IDAPython** | `execute_idapython` | Real-time IDAPython execution with structured `result` capture |
| **📦 MCP Resources** | `ida://info`, `ida://schema` | Real-time binary metadata and complete OpenAPI schema |

---

## 🔒 Security Model

The bridge runs inside IDA Pro, granting powerful capabilities. Version 6 implements defense-in-depth defaults:

- **Loopback binding only**: binds strictly to `127.0.0.1:13370`.
- **Cryptographic session token**: 256-bit token stored in `~/.ph4ntom_ida_bridge_token`.
- **Owner-only DACL**: on Windows, token files are secured with protected owner-only access before writing.
- **Constant-time authorization**: prevents timing side-channels during token validation.
- **POST body limit**: capped at 5 MiB with strict UTF-8 JSON object validation.
- **CORS restriction**: browser CORS is permitted only from localhost origins.
- **Dynamic IDAPython disabled by default**: execution requires explicit `IDA_BRIDGE_ALLOW_EXEC=1`.
- **Header imports restricted**: `POST /api/import-header` requires pre-configured trusted root paths.

> [!CAUTION]
> Never expose port 13370 through a public interface, tunnel, or reverse proxy. See [SECURITY.md](SECURITY.md) for full hardening guidance.

---

## 📦 Components

| Path | Purpose |
|:---|:---|
| `ida_plugin/ph4ntom_ida_bridge.py` | Canonical IDA plugin and REST server (139 endpoints) |
| `api_schema.json` | Machine-readable REST reference & OpenAPI schema |
| `core/client.py` | Shared authenticated HTTP client with token refresh & multi-instance discovery |
| `cli.py` | CLI, plugin installer, doctor, evidence dumper, and IDA launcher |
| `mcp_server.py` | FastMCP server exposing 98 tools and two resources |
| `agent.py` | Interactive terminal agent with 5 interchangeable LLM backends |
| `swarm_worker.py` | Structured batch-analysis worker |
| `agent_config.json` | Machine-readable integration specification for IDE agents |
| `AGENT_SKILL.md` | Skill definition for Antigravity & IDE-based agents |

---

## 💻 CLI Quick Start

The included CLI provides instant control over your IDA session from any terminal:

```bash
# Health & info
ph4ntom-ida ping
ph4ntom-ida info

# Functions & strings
python cli.py functions --limit 50
python cli.py strings --filter "socket|http|connect"

# Decompilation & Cross-references
python cli.py decompile 0x140001000
python cli.py xrefs 0x140001000
python cli.py callers 0x140001000

# Direct API queries
python cli.py api GET /api/function/0x140001000/ctree
python cli.py api POST /api/function/0x140001000/rename --body '{"name":"decrypt_payload"}'

# Launch IDA with bridge autostart
python cli.py launch malware_sample.bin --wait
```

---

## ⚡ Optional Dynamic IDAPython Execution

Dynamic execution is intentionally off by default. Enable it only on trusted environments:

**PowerShell:**
```powershell
$env:IDA_BRIDGE_ALLOW_EXEC = "1"
```

**Bash:**
```bash
export IDA_BRIDGE_ALLOW_EXEC=1
```

Execute scripts inline, from file, or piped via stdin:
```bash
python cli.py exec "result['ea'] = hex(idc.here())"
python cli.py exec --file custom_scan.py
cat analyze.py | python cli.py exec -
```

Scripts receive full IDAPython SDK access (`idc`, `idaapi`, `idautils`, `ida_hexrays`, etc.) and a global `result` dictionary returned as JSON.

---

## 🤖 Standalone Multi-Backend AI Agent

No IDE? Run the built-in terminal agent with any major LLM provider:

```bash
python -m pip install -e ".[agents]"

python agent.py --backend ollama        # 🏠 Local (Ollama, private & offline)
python agent.py --backend gemini        # ☁️ Google Gemini
python agent.py --backend anthropic     # ☁️ Anthropic Claude 3.5 Sonnet
python agent.py --backend openai        # ☁️ OpenAI GPT-4o
python agent.py --backend deepseek      # ☁️ DeepSeek V3
```

API keys are read from standard environment variables (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`).

---

## 🧪 Testing & Verification

The test suite covers client authentication, routing contracts, MCP registration, CORS boundaries, and IDA 9.3 SDK quirks:

```bash
python -m pip install -e ".[dev,mcp]"
python -m compileall -q agent.py cli.py core ida_plugin integrations mcp_server.py server.py swarm_worker.py tests
python -m flake8 . --select=F --exclude=.venv
python -m pytest -q
python verify_mcp.py
```

All 98 MCP tools and 139 REST endpoints are verified against IDA Professional 9.3–9.5. See [TESTING.md](TESTING.md) for reproducibility details and regression checklists.

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

#!/usr/bin/env python3
"""Command-line interface for Antigravity IDA Bridge."""

from __future__ import annotations

import argparse
import filecmp
import json
import os
import shutil
# Only a validated IDA executable is launched, always without a shell.
import subprocess  # nosec B404
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from core.client import BridgeClient

PROJECT_ROOT = Path(__file__).resolve().parent
PLUGIN_SOURCE = PROJECT_ROOT / "ida_plugin" / "antigravity_server.py"
SCHEMA_SOURCE = next(
    (
        path
        for path in (
            PROJECT_ROOT / "api_schema.json",
            Path(sys.prefix) / "share" / "antigravity-ida-bridge" / "api_schema.json",
        )
        if path.is_file()
    ),
    PROJECT_ROOT / "api_schema.json",
)


def format_output(data: Dict[str, Any], compact: bool = False) -> int:
    """Print one stable JSON result and return an appropriate exit code."""
    print(
        json.dumps(
            data,
            indent=None if compact else 2,
            separators=(",", ":") if compact else None,
            ensure_ascii=False,
        )
    )
    return 1 if data.get("error") or data.get("success") is False else 0


def find_ida(ida_dir: Optional[str] = None) -> str:
    """Find an IDA executable from an explicit directory, env, registry, or PATH."""
    def find_in_directory(directory: Path) -> str:
        for name in ("ida64.exe", "ida.exe", "ida64", "ida"):
            candidate = directory / name
            if candidate.is_file():
                return str(candidate.resolve())
        return ""

    candidate_dirs = []
    if ida_dir:
        candidate_dirs.append(Path(ida_dir).expanduser())
    if os.environ.get("IDA_DIR"):
        candidate_dirs.append(Path(os.environ["IDA_DIR"]).expanduser())

    for directory in candidate_dirs:
        found = find_in_directory(directory)
        if found:
            return found

    if sys.platform == "win32":
        try:
            import winreg

            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(hive, r"Software\Hex-Rays\IDA") as key:
                        install_dir = winreg.QueryValueEx(key, "InstallDir")[0]
                    found = find_in_directory(Path(install_dir))
                    if found:
                        return found
                except OSError:
                    continue
        except ImportError:
            pass

    for name in ("ida64", "ida64.exe", "ida", "ida.exe"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def _plugin_directory(ida_executable: str) -> Path:
    return Path(ida_executable).resolve().parent / "plugins"


def install_plugin(ida_executable: str, force: bool = False) -> Dict[str, Any]:
    """Install the canonical plugin and its schema beside each other."""
    plugin_dir = _plugin_directory(ida_executable)
    plugin_dir.mkdir(parents=True, exist_ok=True)
    installed = []
    unchanged = []

    for source in (PLUGIN_SOURCE, SCHEMA_SOURCE):
        if not source.is_file():
            return {"error": f"Required project file is missing: {source}", "success": False}
        destination = plugin_dir / source.name
        if destination.exists() and filecmp.cmp(source, destination, shallow=False):
            unchanged.append(str(destination))
            continue
        if destination.exists() and not force:
            return {
                "error": f"Plugin file already exists and differs: {destination}",
                "hint": "Re-run with --force to create a .bak copy and replace it.",
                "success": False,
            }
        if destination.exists():
            backup = destination.with_suffix(destination.suffix + ".bak")
            shutil.copy2(destination, backup)
        shutil.copy2(source, destination)
        installed.append(str(destination))

    return {
        "success": True,
        "plugin_directory": str(plugin_dir),
        "installed": installed,
        "unchanged": unchanged,
    }


def _parse_json_object(raw: Optional[str], label: str) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _parse_params(values: Iterable[str]) -> Dict[str, str]:
    params = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"Query parameter must use KEY=VALUE syntax: {value}")
        key, item = value.split("=", 1)
        if not key:
            raise ValueError("Query parameter key cannot be empty")
        params[key] = item
    return params


def _read_script(code: Optional[str], filename: Optional[str]) -> str:
    if filename:
        return Path(filename).expanduser().read_text(encoding="utf-8")
    if code and code != "-":
        return code
    if sys.stdin.isatty():
        raise ValueError("Provide inline code, --file PATH, or pipe the script on stdin")
    return sys.stdin.read()


def _wait_for_bridge(client: BridgeClient, timeout: float) -> Dict[str, Any]:
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if client.is_online():
            return {"success": True, "online": True, "waited": round(time.monotonic() - started, 1)}
        time.sleep(1)
    return {"error": f"Bridge did not become ready within {timeout:g} seconds", "success": False}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control IDA Pro through Antigravity IDA Bridge")
    parser.add_argument("--url", default=None, help="Bridge URL (default: IDA_BRIDGE_URL or localhost)")
    parser.add_argument("--timeout", type=float, default=30, help="HTTP timeout in seconds")
    parser.add_argument("--token", default=None, help="Bearer token override")
    parser.add_argument("--token-file", default=None, help="Bearer token file override")
    parser.add_argument("--compact", action="store_true", help="Print compact JSON")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ping", help="Check bridge connectivity and capabilities")
    sub.add_parser("info", help="Show loaded binary metadata")
    sub.add_parser("imports", help="List imported symbols")
    sub.add_parser("exports", help="List exported symbols")
    sub.add_parser("schema", help="Return the complete REST API schema")

    functions = sub.add_parser("functions", help="List functions")
    functions.add_argument("--limit", type=int, default=None)
    functions.add_argument("--offset", type=int, default=0)

    strings = sub.add_parser("strings", help="List strings")
    strings.add_argument("--filter", default=None, help="Server-side regular expression")

    for command in ("decompile", "pseudocode", "xrefs", "callers", "callees"):
        endpoint = sub.add_parser(command, help=f"Run {command} for a function")
        endpoint.add_argument("ea", help="Function address, for example 0x140001000")

    rename = sub.add_parser("rename-func", help="Rename a function")
    rename.add_argument("ea")
    rename.add_argument("name")

    execute = sub.add_parser("exec", help="Execute IDAPython (server must explicitly enable it)")
    execute.add_argument("code", nargs="?", help="Inline code or '-' for stdin")
    execute.add_argument("--file", help="Read code from a UTF-8 file")

    api = sub.add_parser("api", help="Call any documented GET or POST endpoint")
    api.add_argument("method", choices=("GET", "POST", "get", "post"))
    api.add_argument("path")
    api.add_argument("--body", help="POST body as a JSON object")
    api.add_argument("--param", action="append", default=[], help="GET parameter as KEY=VALUE")

    wait = sub.add_parser("wait", help="Wait for the bridge to become ready")
    wait.add_argument("--wait-timeout", type=float, default=120)

    install = sub.add_parser("install-plugin", help="Install the plugin and API schema into IDA")
    install.add_argument("--ida-dir", help="IDA installation directory")
    install.add_argument("--force", action="store_true", help="Back up and replace differing files")

    launch = sub.add_parser("launch", help="Launch IDA with a binary")
    launch.add_argument("binary")
    launch.add_argument("--ida-dir", help="IDA installation directory")
    launch.add_argument("--headless", action="store_true", help="Pass IDA's autonomous-analysis flag")
    launch.add_argument("--wait", action="store_true", help="Wait until the bridge responds")
    launch.add_argument("--wait-timeout", type=float, default=120)
    return parser


def _dispatch(client: BridgeClient, args: argparse.Namespace) -> Dict[str, Any]:
    command = args.command
    if command == "ping":
        return client.ping()
    if command == "info":
        return client.info()
    if command == "imports":
        return client.get("/api/imports")
    if command == "exports":
        return client.get("/api/exports")
    if command == "schema":
        return client.get("/api/schema")
    if command == "functions":
        return client.functions(limit=args.limit, offset=args.offset)
    if command == "strings":
        return client.strings(args.filter)
    if command in ("decompile", "pseudocode"):
        return client.decompile(args.ea)
    if command == "xrefs":
        return client.xrefs_to(args.ea)
    if command in ("callers", "callees"):
        ea = client.path_component(args.ea)
        return client.get(f"/api/function/{ea}/{command}")
    if command == "rename-func":
        return client.rename_func(args.ea, args.name)
    if command == "exec":
        return client.exec_python(_read_script(args.code, args.file))
    if command == "api":
        if args.method.upper() == "GET":
            payload = _parse_params(args.param)
        else:
            if args.param:
                raise ValueError("--param is only valid for GET requests")
            payload = _parse_json_object(args.body, "--body")
        return client.call_api(args.method, args.path, payload)
    if command == "wait":
        return _wait_for_bridge(client, args.wait_timeout)
    return {"error": f"Unsupported command: {command}", "success": False}


def _launch(args: argparse.Namespace, client: BridgeClient) -> Dict[str, Any]:
    target = Path(args.binary).expanduser().resolve()
    if not target.is_file():
        return {"error": f"Binary not found: {target}", "success": False}
    ida_executable = find_ida(args.ida_dir)
    if not ida_executable:
        return {"error": "IDA Pro not found. Pass --ida-dir or set IDA_DIR.", "success": False}

    command = [ida_executable]
    if args.headless:
        command.append("-A")
    command.append(str(target))
    # Both executable and binary paths were resolved and validated above.
    process = subprocess.Popen(command)  # nosec B603
    result = {"success": True, "status": "launched", "pid": process.pid, "ida": ida_executable}
    if args.wait:
        result["bridge"] = _wait_for_bridge(client, args.wait_timeout)
        if result["bridge"].get("error"):
            result["success"] = False
    return result


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.command == "install-plugin":
            ida_executable = find_ida(args.ida_dir)
            if not ida_executable:
                result = {"error": "IDA Pro not found. Pass --ida-dir or set IDA_DIR.", "success": False}
            else:
                result = install_plugin(ida_executable, force=args.force)
            return format_output(result, args.compact)

        with BridgeClient(
            url=args.url,
            timeout=args.timeout,
            token=args.token,
            token_file=args.token_file,
        ) as client:
            result = _launch(args, client) if args.command == "launch" else _dispatch(client, args)
        return format_output(result, args.compact)
    except (OSError, ValueError) as exc:
        return format_output({"error": str(exc), "success": False}, args.compact)


if __name__ == "__main__":
    raise SystemExit(main())

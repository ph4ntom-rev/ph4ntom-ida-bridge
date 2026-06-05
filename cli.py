#!/usr/bin/env python3
"""
Unified Antigravity-IDA CLI
Заменяет legacy bridge.py и bridge_cli.py.
"""
import sys
import os
import json
import time
import shutil
import argparse
import subprocess
from pathlib import Path
from core.client import BridgeClient


def format_output(data: dict) -> int:
    """Универсальный форматер JSON вывода для CLI."""
    if "error" in data and data["error"]:
        print(f"ERROR: {data['error']}", file=sys.stderr)
        return 1
    print(json.dumps(data, indent=2, ensure_ascii=False))
    return 0


def find_ida() -> str:
    """Надежный поиск бинарника IDA Pro."""
    env_dir = os.environ.get("IDA_DIR")
    if env_dir:
        for name in ["ida64.exe", "ida.exe", "ida64", "ida"]:
            p = Path(env_dir) / name
            if p.is_file():
                return str(p)

    if sys.platform == "win32":
        try:
            import winreg
            for hkey in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                try:
                    with winreg.OpenKey(hkey, r"Software\Hex-Rays\IDA") as key:
                        ida_dir = winreg.QueryValueEx(key, "InstallDir")[0]
                        for name in ["ida64.exe", "ida.exe"]:
                            p = Path(ida_dir) / name
                            if p.is_file():
                                return str(p)
                except OSError:
                    continue
        except ImportError:
            pass

    for name in ["ida64", "ida64.exe"]:
        path = shutil.which(name)
        if path:
            return path
    return ""


def cmd_launch(binary_path: str, client: BridgeClient):
    """Безопасный запуск IDA Pro с перехватом прав доступа (Устранено скрытое падение)."""
    target = Path(binary_path).resolve()
    if not target.exists():
        return format_output({"error": f"File not found: {target}"})

    if "error" not in client.ping():
        return format_output({"status": "already_online", "info": client.info()})

    ida_exe = find_ida()
    if not ida_exe:
        return format_output({"error": "IDA Pro not found. Set IDA_DIR env variable or add to PATH."})

    ida_dir = Path(ida_exe).parent
    plugin_src = Path(__file__).parent / "ida_plugin" / "antigravity_server.py"
    plugin_dst = ida_dir / "plugins" / "antigravity_server.py"

    # [FIX] Теперь юзер узнает, если у него нет админских прав на запись плагина
    if plugin_src.exists() and not plugin_dst.exists():
        try:
            plugin_dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(plugin_src, plugin_dst)
        except PermissionError:
            return format_output({"error": f"Permission denied installing plugin to {plugin_dst}. Run as Admin/Root."})

    log_file = Path.home() / ".antigravity_ida.log"
    proc = subprocess.Popen([ida_exe, "-A", f"-L{log_file}", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return format_output({"status": "launched", "pid": proc.pid, "ida": str(ida_exe), "next": "Run: python cli.py wait"})


def main():
    parser = argparse.ArgumentParser(description="Antigravity IDA Bridge CLI")
    parser.add_argument("--url", help="Bridge server URL override", default=None)

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("ping", help="Check if bridge is running")
    sub.add_parser("info", help="Get binary info")
    sub.add_parser("functions", help="List all functions")

    p = sub.add_parser("launch", help="Launch IDA Pro")
    p.add_argument("binary")
    p = sub.add_parser("wait", help="Wait for bridge")
    p.add_argument("--timeout", type=int, default=120)
    p = sub.add_parser("pseudocode", help="Decompile")
    p.add_argument("ea")
    p = sub.add_parser("rename-func", help="Rename function")
    p.add_argument("ea")
    p.add_argument("name")
    p = sub.add_parser("exec", help="Execute script")
    p.add_argument("file")

    args = parser.parse_args()
    client = BridgeClient(url=args.url)

    if args.command == "launch":
        return cmd_launch(args.binary, client)
    elif args.command == "wait":
        start = time.time()
        while time.time() - start < args.timeout:
            if "error" not in client.ping():
                return format_output({"online": True, "waited": round(time.time() - start, 1)})
            time.sleep(2)
        return format_output({"error": f"Bridge timeout ({args.timeout}s)"})

    # Диспетчеризация команд
    elif args.command == "ping":
        res = client.ping()
    elif args.command == "info":
        res = client.info()
    elif args.command == "functions":
        res = client.functions()
    elif args.command == "pseudocode":
        res = client.pseudocode(args.ea)
    elif args.command == "rename-func":
        res = client.rename_func(args.ea, args.name)
    elif args.command == "exec":
        with open(args.file, "r", encoding="utf-8") as f:
            res = client.exec_python(f.read())
    else:
        res = {"error": f"Command '{args.command}' not implemented."}

    return format_output(res)


if __name__ == "__main__":
    sys.exit(main())

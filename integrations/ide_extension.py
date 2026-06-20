"""
Antigravity IDA Bridge — IDE Extension Bridge
===============================================
Integration layer for Antigravity IDE / VS Code / Cursor.

Provides:
- Workspace config auto-discovery (.antigravity/config.json)
- IDA Bridge status panel data
- Function list / decompilation for IDE sidepanel
- Bidirectional sync (renames, comments, types)

Can run as:
1. Standalone HTTP server for IDE extensions
2. MCP server (via integrations/mcp_server.py)
3. Imported as library by an IDE plugin
"""

import os
import json
from core.client import BridgeClient


DEFAULT_CONFIG = {
    "ida_bridge": {
        "url": "http://127.0.0.1:13370",
        "auto_connect": True,
        "sync_renames": True,
        "sync_comments": True,
    },
    "agent": {
        "backend": "auto",
        "model": None,
    },
    "ui": {
        "show_decompilation_panel": True,
        "show_xrefs_panel": True,
        "show_strings_panel": True,
    },
}


class IDEBridge:
    """Bridge between IDE and IDA Pro."""

    def __init__(self, workspace_path: str = "."):
        self.workspace = workspace_path
        self.config = self._load_config()
        self.client = BridgeClient(url=self.config["ida_bridge"]["url"])

    def _load_config(self) -> dict:
        """Load config from workspace .antigravity/config.json"""
        config_path = os.path.join(self.workspace, ".antigravity", "config.json")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                user_config = json.load(f)
                # Merge with defaults
                merged = DEFAULT_CONFIG.copy()
                merged.update(user_config)
                return merged
        return DEFAULT_CONFIG.copy()

    def init_workspace(self):
        """Create .antigravity/ config directory in workspace."""
        config_dir = os.path.join(self.workspace, ".antigravity")
        os.makedirs(config_dir, exist_ok=True)
        config_path = os.path.join(config_dir, "config.json")
        if not os.path.exists(config_path):
            with open(config_path, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"[+] Created {config_path}")
        return config_path

    def get_status(self) -> dict:
        """Get bridge + binary status for IDE panel."""
        ping = self.client.ping()
        if "error" in ping:
            return {"online": False, "error": ping["error"]}

        info = self.client.info()
        return {
            "online": True,
            "version": ping.get("version"),
            "binary": info.get("file"),
            "arch": f"{info.get('proc', '?')} {info.get('bits', '?')}-bit",
            "entry": info.get("entry_point"),
            "functions": info.get("func_count"),
        }

    def get_functions(self, offset: int = 0, limit: int = 100) -> dict:
        """Get function list for IDE panel."""
        return self.client.get("/api/functions-page", offset=offset, limit=limit)

    def get_decompilation(self, ea: str) -> dict:
        """Get decompiled pseudocode for IDE editor."""
        return self.client.get(f"/api/function/{ea}/pseudocode")

    def get_xrefs(self, ea: str) -> dict:
        """Get cross-references for IDE panel."""
        return self.client.get(f"/api/function/{ea}/xrefs-to")

    def rename_function(self, ea: str, name: str) -> dict:
        """Sync function rename from IDE to IDA."""
        return self.client.post(f"/api/function/{ea}/rename", {"name": name})

    def set_comment(self, ea: str, comment: str) -> dict:
        """Sync comment from IDE to IDA."""
        return self.client.post(f"/api/function/{ea}/comment", {"comment": comment})


# ── VS Code / Antigravity IDE settings templates ─────────────────────────

VSCODE_SETTINGS = {
    "antigravity.idaBridge.enabled": True,
    "antigravity.idaBridge.url": "http://127.0.0.1:13370",
    "antigravity.idaBridge.autoConnect": True,
    "antigravity.idaBridge.syncRenames": True,
}

CURSOR_MCP_CONFIG = {
    "mcpServers": {
        "ida-bridge": {
            "command": "python",
            "args": ["integrations/mcp_server.py"],
        }
    }
}


def generate_ide_configs(workspace: str = "."):
    """Generate IDE config files for current workspace."""
    # .antigravity/config.json
    bridge = IDEBridge(workspace)
    config_path = bridge.init_workspace()

    # .vscode/settings.json (merge)
    vscode_dir = os.path.join(workspace, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)
    vscode_settings_path = os.path.join(vscode_dir, "settings.json")

    if os.path.exists(vscode_settings_path):
        with open(vscode_settings_path, "r") as f:
            settings = json.load(f)
    else:
        settings = {}

    settings.update(VSCODE_SETTINGS)
    with open(vscode_settings_path, "w") as f:
        json.dump(settings, f, indent=2)

    # .cursor/mcp.json
    cursor_dir = os.path.join(workspace, ".cursor")
    os.makedirs(cursor_dir, exist_ok=True)
    with open(os.path.join(cursor_dir, "mcp.json"), "w") as f:
        json.dump(CURSOR_MCP_CONFIG, f, indent=2)

    print(f"[+] Generated IDE configs in {workspace}")
    print(f"    {config_path}")
    print(f"    {vscode_settings_path}")
    print(f"    {os.path.join(cursor_dir, 'mcp.json')}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        workspace = sys.argv[2] if len(sys.argv) > 2 else "."
        generate_ide_configs(workspace)
    else:
        bridge = IDEBridge()
        status = bridge.get_status()
        print(json.dumps(status, indent=2))

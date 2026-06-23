"""
Antigravity IDA Bridge — Schema Loader
========================================
Loads and caches api_schema.json, generates system prompts for AI backends.

Changes (v5.2):
- Safe file loading with JSONDecodeError handling
- Separated load-attempt tracking from cached state
- Walrus operator for cleaner prompt generation
"""

import os
import json
from typing import Dict, Any, Tuple, Optional


class SchemaLoader:
    """Loads API schema and generates system prompts for any backend."""

    def __init__(self, schema_path: Optional[str] = None):
        if schema_path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            schema_path = os.path.join(base, "api_schema.json")

        self.schema_path = schema_path
        self._schema: Optional[Dict[str, Any]] = None
        self._load_attempted = False

    @property
    def schema(self) -> Dict[str, Any]:
        """Lazy-load and cache schema safely."""
        if self._schema is None and not self._load_attempted:
            self._load_attempted = True
            if os.path.isfile(self.schema_path):
                try:
                    with open(self.schema_path, "r", encoding="utf-8") as f:
                        self._schema = json.load(f)
                except (json.JSONDecodeError, OSError):
                    self._schema = {}
            else:
                self._schema = {}

        return self._schema or {}

    @property
    def is_loaded(self) -> bool:
        """Checks if schema is loaded without triggering a file read."""
        return self._schema is not None and bool(self._schema)

    @property
    def endpoint_count(self) -> Tuple[int, int]:
        """Returns (read_count, write_count)."""
        endpoints = self.schema.get("endpoints", {})
        return len(endpoints.get("read", [])), len(endpoints.get("write", []))

    def generate_system_prompt(self, tool_instructions: str = "") -> str:
        """Generate a full system prompt from schema + custom tool instructions.

        Args:
            tool_instructions: Backend-specific tool usage instructions to append.
        """
        if not self.schema:
            return (
                "You are an expert reverse engineering AI agent connected to IDA Pro "
                "via the Antigravity Bridge API. Use the available tools to analyze binaries.")

        parts = []

        # Base system prompt from schema
        if base := self.schema.get("system_prompt", ""):
            parts.append(base)

        # Endpoints reference
        if endpoints := self.schema.get("endpoints"):
            parts.extend(["## Available API Endpoints\n",
                         json.dumps(endpoints, indent=1)])

        # Workflows
        if workflows := self.schema.get("workflows"):
            parts.extend(["\n## Workflows\n", json.dumps(workflows, indent=1)])

        # Tips
        if tips := self.schema.get("tips"):
            parts.extend(["\n## Tips\n", json.dumps(tips, indent=1)])

        # Backend-specific tool instructions
        if tool_instructions:
            parts.append(f"\n## Tool Usage\n\n{tool_instructions}")

        return "\n\n".join(parts)

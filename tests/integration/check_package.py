"""Run with python -I to verify resources from an installed wheel, not cwd."""
import asyncio
from importlib.metadata import version
import json
from pathlib import Path
import sys

import cli
from core.schema import SchemaLoader
from mcp_server import mcp

prefix = Path(sys.prefix).resolve()
assert Path(cli.__file__).resolve().is_relative_to(prefix)
assert cli.PLUGIN_SOURCE.is_file() and cli.PLUGIN_SOURCE.resolve().is_relative_to(prefix)
assert cli.SCHEMA_SOURCE.is_file() and cli.SCHEMA_SOURCE.resolve().is_relative_to(prefix)
schema = SchemaLoader().schema
assert schema['meta']['version'] == version('ph4ntom-ida-bridge')
assert len(asyncio.run(mcp.list_tools())) == 54
assert len(asyncio.run(mcp.list_resources())) == 2
print(json.dumps({'success': True, 'version': version('ph4ntom-ida-bridge'),
                  'plugin': str(cli.PLUGIN_SOURCE), 'schema': str(cli.SCHEMA_SOURCE),
                  'mcp_tools': 54, 'mcp_resources': 2}, indent=2))

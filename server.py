"""Compatibility entry point for the canonical IDA plugin implementation.

New installations should copy ``ida_plugin/ph4ntom_ida_bridge.py`` and
``api_schema.json`` into IDA's plugins directory, or run
``python cli.py install-plugin``.
"""

from ida_plugin.ph4ntom_ida_bridge import PLUGIN_ENTRY, start_server, stop_server

__all__ = ["PLUGIN_ENTRY", "start_server", "stop_server"]


if __name__ == "__main__":
    start_server()

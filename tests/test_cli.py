import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import cli


def test_parser_exposes_documented_commands():
    parser = cli.build_parser()
    commands = next(action for action in parser._actions if action.dest == "command").choices
    assert {
        "ping",
        "info",
        "functions",
        "strings",
        "decompile",
        "xrefs",
        "exec",
        "api",
        "install-plugin",
        "launch",
    }.issubset(commands)


def test_parse_params_and_json_body():
    assert cli._parse_params(["depth=3", "name=a=b"]) == {"depth": "3", "name": "a=b"}
    assert cli._parse_json_object('{"name":"entry"}', "body") == {"name": "entry"}
    with pytest.raises(ValueError):
        cli._parse_params(["missing-separator"])
    with pytest.raises(ValueError):
        cli._parse_json_object("[]", "body")


def test_install_plugin_copies_plugin_and_schema(tmp_path):
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    ida_executable = ida_dir / "ida64.exe"
    ida_executable.write_bytes(b"")

    result = cli.install_plugin(str(ida_executable))

    assert result["success"] is True
    assert (ida_dir / "plugins" / "ph4ntom_ida_bridge.py").is_file()
    assert (ida_dir / "plugins" / "api_schema.json").is_file()


def test_install_plugin_requires_force_for_differing_file(tmp_path):
    ida_dir = tmp_path / "ida"
    plugin_dir = ida_dir / "plugins"
    plugin_dir.mkdir(parents=True)
    ida_executable = ida_dir / "ida64.exe"
    ida_executable.write_bytes(b"")
    destination = plugin_dir / "ph4ntom_ida_bridge.py"
    destination.write_text("custom", encoding="utf-8")

    result = cli.install_plugin(str(ida_executable))
    forced = cli.install_plugin(str(ida_executable), force=True)

    assert result["success"] is False
    assert forced["success"] is True
    assert Path(str(destination) + ".bak").read_text(encoding="utf-8") == "custom"


def test_main_dispatches_decompile(capsys):
    client = Mock()
    client.__enter__ = Mock(return_value=client)
    client.__exit__ = Mock(return_value=None)
    client.decompile.return_value = {"success": True, "ea": "0x1000"}

    with patch("cli.BridgeClient", return_value=client):
        exit_code = cli.main(["decompile", "0x1000"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["ea"] == "0x1000"
    client.decompile.assert_called_once_with("0x1000")


import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_schema_and_project_versions_match():
    schema = json.loads((ROOT / "api_schema.json").read_text(encoding="utf-8"))
    agent_config = json.loads((ROOT / "agent_config.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert schema["meta"]["version"] == "6.0.0"
    assert agent_config["version"] == "6.0.0"
    assert 'version = "6.0.0"' in pyproject


def test_schema_declares_expected_endpoint_coverage():
    schema = json.loads((ROOT / "api_schema.json").read_text(encoding="utf-8"))
    assert len(schema["endpoints"]["read"]) == 54
    assert len(schema["endpoints"]["write"]) == 48


def test_plugin_has_one_function_router_per_http_method():
    source = (ROOT / "ida_plugin" / "antigravity_server.py").read_text(encoding="utf-8")
    assert source.count("@get_route(r'/api/function/.*')") == 1
    assert source.count("@post_route(r'/api/function/.*')") == 1
    for action in ("ctree", "lvar-map", "microcode", "callers", "callees", "strings-used"):
        assert re.search(r"action == ['\"]" + re.escape(action) + r"['\"]", source)
    for action in ("lvar-set-type", "lvar-comment"):
        assert re.search(r"action == ['\"]" + re.escape(action) + r"['\"]", source)


def test_plugin_security_guards_are_present():
    source = (ROOT / "ida_plugin" / "antigravity_server.py").read_text(encoding="utf-8")
    assert "secrets.compare_digest" in source
    assert "MAX_BODY_SIZE" in source
    assert "IDA_BRIDGE_ALLOW_EXEC" in source
    assert "Access-Control-Allow-Origin', '*'" not in source
    assert source.count("ui_hooks.hook()") == 1


def test_docs_reference_current_entry_points():
    for filename in ("README.md", "AGENT_SKILL.md"):
        content = (ROOT / filename).read_text(encoding="utf-8")
        assert "python bridge.py" not in content
        assert "integrations/mcp_server.py" not in content

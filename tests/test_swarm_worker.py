from swarm_worker import _sanitize_symbol


def test_sanitize_symbol_for_ida_names():
    assert _sanitize_symbol("network handler") == "network_handler"
    assert _sanitize_symbol("123-start") == "fn_123_start"
    assert _sanitize_symbol("  ") == ""

"""Exercise real sockets and failure paths without a licensed IDA installation."""
import http.client
import os
import socket
import sys
import threading
import time
import types
from unittest.mock import Mock

import pytest

from core.client import BridgeClient
from tests.test_plugin_runtime import _load_plugin


@pytest.fixture
def bridge(monkeypatch, tmp_path):
    plugin, token_file = _load_plugin(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, 'REQUEST_TIMEOUT', 0.2)
    server = plugin.BridgeHTTPServer(('127.0.0.1', 0), plugin.BridgeHandler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
    thread.start()
    client = BridgeClient(f'http://127.0.0.1:{server.server_port}', token_file=str(token_file), timeout=2)
    try:
        yield plugin, server, client
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def raw_request(server, *, method='POST', path='/api/save', body=b'{}', headers=()):
    connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
    connection.putrequest(method, path)
    connection.putheader('Authorization', 'Bearer ' + server.auth_token)
    for key, value in headers:
        connection.putheader(key, value)
    connection.endheaders(body)
    try:
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


@pytest.mark.parametrize('body', [b'[]', b'{', b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff'])
def test_invalid_json_never_reaches_mutation(bridge, body, monkeypatch):
    plugin, server, _ = bridge
    mutation = Mock()
    monkeypatch.setattr(plugin, 'save_database', mutation)
    status, _ = raw_request(server, body=body,
        headers=[('Content-Length', str(len(body))), ('Content-Type', 'application/json')])
    assert status == 400
    mutation.assert_not_called()


@pytest.mark.parametrize('headers,status', [
    ([('Content-Length', '2'), ('Content-Length', '2'), ('Content-Type', 'application/json')], 400),
    ([('Content-Length', '2'), ('Transfer-Encoding', 'chunked'), ('Content-Type', 'application/json')], 400),
    ([('Content-Length', '2'), ('Content-Type', 'text/plain')], 415),
    ([('Content-Length', '2'), ('Content-Type', 'application/json'), ('Host', 'evil.test')], 403),
    ([('Content-Length', '2'), ('Content-Type', 'application/json'), ('Origin', 'https://evil.test')], 403),
    ([('Content-Length', '2'), ('Content-Type', 'application/json'), ('Authorization', 'Bearer duplicate')], 401),
])
def test_ambiguous_headers_rejected(bridge, headers, status):
    assert raw_request(bridge[1], headers=headers)[0] == status


def test_incomplete_body_times_out_and_server_still_responds(bridge):
    _, server, client = bridge
    status, _ = raw_request(server, headers=[('Content-Length', '100'), ('Content-Type', 'application/json')])
    assert status == 408
    assert client.ping()['status'] == 'ok'


def test_read_only_blocks_writes_and_reports_capability(bridge, monkeypatch):
    plugin, _, client = bridge
    monkeypatch.setattr(plugin, 'READ_ONLY', True)
    assert client.ping()['read_only'] is True
    assert 'read-only' in client.post('/api/save')['error']


@pytest.mark.parametrize('path', ['/api/functions-page?limit=2&limit=3',
    '/api/function/0x1000/details/ignored', '/api/bytes/0x1000/-1', '/api/bytes/0x1000/1048577'])
def test_invalid_paths_or_ranges_rejected(bridge, path):
    assert raw_request(bridge[1], method='GET', path=path, body=None)[0] == 400


def test_second_bind_does_not_rotate_working_token(bridge):
    plugin, server, _ = bridge
    before = open(server.token_path, encoding='utf-8').read()
    with pytest.raises(OSError):
        plugin.BridgeHTTPServer(server.server_address, plugin.BridgeHandler)
    assert open(server.token_path, encoding='utf-8').read() == before == server.auth_token


def test_explicit_token_failure_does_not_fall_back(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    monkeypatch.setattr(plugin, '_create_private_file', Mock(side_effect=PermissionError('denied')))
    with pytest.raises(RuntimeError, match='secure bridge token'):
        plugin.BridgeHTTPServer(('127.0.0.1', 0), plugin.BridgeHandler)
    assert plugin._create_private_file.call_count == 1


def test_non_loopback_bind_rejected(monkeypatch, tmp_path):
    plugin, _ = _load_plugin(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match='127.0.0.1'):
        plugin.BridgeHTTPServer(('0.0.0.0', 0), plugin.BridgeHandler)


def test_event_broadcast_and_overflow_are_explicit(bridge):
    plugin, _, _ = bridge
    first, second = plugin._subscribe_events(), plugin._subscribe_events()
    try:
        plugin._publish_event({'event': 'renamed'})
        assert first.get_nowait() == second.get_nowait() == {'event': 'renamed'}
        for i in range(257):
            plugin._publish_event({'event': 'cursor', 'index': i})
        assert first.get_nowait() == second.get_nowait() == {'event': 'resync_required'}
    finally:
        plugin._unsubscribe_events(first)
        plugin._unsubscribe_events(second)


def test_event_subscription_released_when_headers_fail(bridge):
    plugin, server, _ = bridge
    handler = Mock(server=server)
    handler.send_response.side_effect = BrokenPipeError()
    plugin.route_events(handler, None, {})
    assert not plugin._event_subscribers


def test_connection_limit_and_timeout_release_slots(bridge, monkeypatch):
    _, server, client = bridge
    server.slots = threading.BoundedSemaphore(1)
    stalled = socket.create_connection(server.server_address, timeout=2)
    try:
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if not server.slots.acquire(blocking=False):
                break
            server.slots.release()
            time.sleep(0.005)
        extra = socket.create_connection(server.server_address, timeout=2)
        try:
            assert extra.recv(1) == b''
        finally:
            extra.close()
        time.sleep(0.3)
        assert client.ping()['status'] == 'ok'
    finally:
        stalled.close()


@pytest.mark.parametrize('url', ['https://example.com', 'http://127.0.0.1.evil.test',
    'http://localhost:70000', 'http://user:pass@localhost', 'http://localhost/path'])
def test_client_refuses_to_send_local_token_elsewhere(url):
    with pytest.raises(ValueError):
        BridgeClient(url, token='test-only')


def test_client_ignores_proxy_and_missing_explicit_token_file(tmp_path, monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://example.com:3128')
    with BridgeClient(token_file=str(tmp_path / 'missing')) as client:
        assert not client.session.trust_env
        assert 'Authorization' not in client.session.headers
        assert len(list(client._token_candidates())) == 1


def test_redirect_is_not_followed_even_to_loopback(bridge):
    plugin, _, client = bridge
    @plugin.get_route('/api/test-redirect')
    def redirect(handler, match, params):
        handler.send_response(302)
        handler.send_header('Location', '/api/ping')
        handler.end_headers()
    assert client.get('/api/test-redirect')['error'] == 'Bridge redirects are not allowed'


def test_failed_post_is_not_retried(bridge):
    plugin, _, client = bridge
    calls = []
    @plugin.post_route('/api/test-write')
    def write(handler, match, data):
        calls.append(data)
        handler.send_error_json('injected failure', 500)
    assert client.post('/api/test-write', {'value': 1})['success'] is False
    assert calls == [{'value': 1}]


def test_post_disconnect_reports_uncertain_delivery(bridge):
    plugin, _, client = bridge
    calls = []
    @plugin.post_route('/api/test-disconnect')
    def write(handler, match, data):
        calls.append(data)
        handler.connection.shutdown(socket.SHUT_RDWR)
    result = client.post('/api/test-disconnect', {'value': 1})
    assert result['delivery_state'] == 'uncertain'
    assert len(calls) == 1


def test_token_permissions_protect_owner(bridge):
    path = bridge[1].token_path
    if os.name != 'nt':
        assert os.stat(path).st_mode & 0o777 == 0o600
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    get_security = advapi.GetNamedSecurityInfoW
    get_security.argtypes = (wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    descriptor = ctypes.c_void_p()
    assert get_security(path, 1, 4, None, None, None, None, ctypes.byref(descriptor)) == 0
    convert = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = (ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.c_void_p)
    output = wintypes.LPWSTR()
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    try:
        assert convert(descriptor, 1, 4, ctypes.byref(output), None)
        assert output.value == 'D:P(A;;FA;;;OW)'
    finally:
        kernel.LocalFree(output)
        kernel.LocalFree(descriptor)


def test_hardware_breakpoint_uses_execution_type(bridge, monkeypatch):
    plugin = bridge[0]
    add = Mock(return_value=True)
    monkeypatch.setattr(plugin.ida_dbg, 'add_bpt', add, raising=False)
    monkeypatch.setattr(plugin.ida_dbg, 'BPT_EXEC', 1, raising=False)
    assert plugin.dbg_set_bp(0x1000, True)['success']
    add.assert_called_once_with(0x1000, 1, 1)


def test_partial_debugger_memory_write_is_failure(bridge, monkeypatch):
    plugin = bridge[0]
    monkeypatch.setattr(plugin.ida_dbg, 'is_debugger_on', lambda: True, raising=False)
    monkeypatch.setitem(sys.modules, 'ida_idd', types.SimpleNamespace(dbg_write_memory=lambda ea, data: 1))
    result = plugin.dbg_write_mem(0x1000, '9090')
    assert result['success'] is False and result['written'] == 1


def test_patch_readback_detects_failed_mutation(bridge, monkeypatch):
    plugin = bridge[0]
    monkeypatch.setattr(plugin.ida_bytes, 'get_bytes', lambda ea, size: b'\x00', raising=False)
    monkeypatch.setattr(plugin.ida_bytes, 'patch_bytes', lambda ea, data: None, raising=False)
    assert plugin.patch_bytes_at(0x1000, '90')['success'] is False

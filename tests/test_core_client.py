from core.client import BridgeClient
from unittest.mock import patch, Mock

import pytest


class TestBridgeClient:
    def test_init_default(self):
        client = BridgeClient()
        assert client.base_url == "http://127.0.0.1:13370"

    def test_init_custom_url(self):
        client = BridgeClient(url="http://localhost:8080/")
        assert client.base_url == "http://localhost:8080"

    @pytest.mark.parametrize(
        "url",
        ["localhost:13370", "ftp://localhost", "http://user:pass@localhost", "http://localhost/#fragment"],
    )
    def test_init_rejects_unsafe_or_invalid_url(self, url):
        with pytest.raises(ValueError):
            BridgeClient(url=url)

    def test_init_rejects_non_positive_timeout(self):
        with pytest.raises(ValueError):
            BridgeClient(timeout=0)

    @patch('core.client.requests.Session.request')
    def test_get_success(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true, "data": "test"}'
        mock_response.json.return_value = {"success": True, "data": "test"}
        mock_request.return_value = mock_response

        client = BridgeClient()
        response = client.get("/api/test")

        assert response == {"success": True, "data": "test"}
        mock_request.assert_called_once_with('GET', 'http://127.0.0.1:13370/api/test', params={}, timeout=30, allow_redirects=False)

    @patch('core.client.requests.Session.request')
    def test_post_success(self, mock_request):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_response.json.return_value = {"success": True}
        mock_request.return_value = mock_response

        client = BridgeClient()
        response = client.post("/api/test", data={"key": "value"})

        assert response == {"success": True}
        mock_request.assert_called_once_with('POST', 'http://127.0.0.1:13370/api/test', json={"key": "value"}, timeout=30, allow_redirects=False)

    @patch('core.client.requests.Session.request')
    def test_request_connection_error(self, mock_request):
        import requests
        mock_request.side_effect = requests.ConnectionError("Connection Refused")

        client = BridgeClient()
        response = client.get("/api/test")

        assert response["success"] is False
        assert "Cannot communicate" in response["error"]

    @patch('core.client.requests.Session.request')
    def test_request_json_decode_error(self, mock_request):
        from requests.exceptions import JSONDecodeError
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "invalid json"
        mock_response.raise_for_status.return_value = None

        # We need to simulate JSONDecodeError being raised by response.json()
        def raise_json_error(*args, **kwargs):
            raise JSONDecodeError("msg", "doc", 0)
        mock_response.json.side_effect = raise_json_error

        mock_request.return_value = mock_response

        client = BridgeClient()
        response = client.get("/api/test")

        assert response["success"] is False
        assert "Invalid JSON response" in response["error"]

    def test_path_component_encodes_reserved_characters(self):
        assert BridgeClient.path_component("name/with space") == "name%2Fwith%20space"

    def test_call_api_rejects_unsupported_method(self):
        client = BridgeClient()
        response = client.call_api("DELETE", "/api/test")
        assert response == {"error": "Only GET and POST are supported", "success": False}

    @patch('core.client.requests.Session.request')
    def test_reloads_rotated_token_after_unauthorized(self, mock_request, tmp_path):
        token_file = tmp_path / "token"
        token_file.write_text("old-token", encoding="utf-8")
        client = BridgeClient(token_file=str(token_file))

        unauthorized = Mock(status_code=401, text='{"error":"Unauthorized"}')
        success = Mock(status_code=200, text='{"status":"ok"}')
        success.json.return_value = {"status": "ok"}
        success.raise_for_status.return_value = None
        mock_request.side_effect = [unauthorized, success]

        token_file.write_text("new-token", encoding="utf-8")
        response = client.ping()

        assert response == {"status": "ok"}
        assert client.session.headers["Authorization"] == "Bearer new-token"
        assert mock_request.call_count == 2

    def test_context_manager_closes_session(self):
        client = BridgeClient()
        with patch.object(client.session, "close") as close:
            with client as active:
                assert active is client
            close.assert_called_once_with()

from core.client import BridgeClient
from unittest.mock import patch, Mock


class TestBridgeClient:
    def test_init_default(self):
        client = BridgeClient()
        assert client.base_url == "http://127.0.0.1:13370"

    def test_init_custom_url(self):
        client = BridgeClient(url="http://test:8080/")
        assert client.base_url == "http://test:8080"

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
        mock_request.assert_called_once_with(
            'GET', 'http://127.0.0.1:13370/api/test', params={}, timeout=30)

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
        mock_request.assert_called_once_with(
            'POST',
            'http://127.0.0.1:13370/api/test',
            json={
                "key": "value"},
            timeout=30)

    @patch('core.client.requests.Session.request')
    def test_request_connection_error(self, mock_request):
        import requests
        mock_request.side_effect = requests.ConnectionError(
            "Connection Refused")

        client = BridgeClient()
        response = client.get("/api/test")

        assert response["success"] is False
        assert "offline" in response["error"]

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

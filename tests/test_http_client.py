import unittest
from unittest.mock import patch, MagicMock

import urllib.error
from email.message import Message
from urllib.request import Request

from modules.http.client import (
    HTTPClient,
    TrackingRedirectHandler
)
from modules.http.user_agents import get_user_agent


class TestHTTPClient(unittest.TestCase):

    def setUp(self):
        self.client = HTTPClient()

    def make_response(self, body=b"<html>Test</html>"):
        response = MagicMock()
        response.status = 200
        response.geturl.return_value = "https://example.test"
        response.headers = Message()

        response.headers["Content-Type"] = "text/html"
        response.headers["Content-Length"] = str(len(body))
        response.headers["Server"] = "ExampleServer"

        response.read.return_value = body
        return response

    def mock_opener(self, response):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        return opener

    def test_accept_https_url(self):
        self.assertEqual(
            self.client.validate_url("https://example.test"),
            "https://example.test"
        )

    def test_accept_http_url(self):
        self.assertEqual(
            self.client.validate_url("http://example.test/page"),
            "http://example.test/page"
        )

    def test_reject_ftp_url(self):
        with self.assertRaises(ValueError):
            self.client.validate_url("ftp://example.test")

    def test_reject_missing_hostname(self):
        with self.assertRaises(ValueError):
            self.client.validate_url("https://")

    def test_reject_url_credentials(self):
        with self.assertRaises(ValueError):
            self.client.validate_url(
                "https://user:password@example.test"
            )

    @patch("modules.http.client.urllib.request.build_opener")
    def test_successful_get(self, mock_build_opener):
        response = self.make_response()
        mock_build_opener.return_value = self.mock_opener(
            response
        )

        result = self.client.get("https://example.test")

        self.assertEqual(result["status"], 200)
        self.assertEqual(
            result["body"],
            "<html>Test</html>"
        )
        self.assertEqual(
            result["headers"]["Content-Type"],
            "text/html"
        )

    @patch("modules.http.client.urllib.request.build_opener")
    def test_http_error_response(self, mock_build_opener):
        headers = Message()
        headers["Content-Type"] = "text/html"

        error = urllib.error.HTTPError(
            "https://example.test/missing",
            404,
            "Not Found",
            headers,
            None
        )

        opener = MagicMock()
        opener.open.side_effect = error
        mock_build_opener.return_value = opener

        result = self.client.get(
            "https://example.test/missing"
        )

        self.assertEqual(result["status"], 404)
        self.assertEqual(result["body"], "")
        self.assertEqual(result["set_cookie_headers"], [])

    @patch("modules.http.client.urllib.request.build_opener")
    def test_response_size_limit(self, mock_build_opener):
        response = self.make_response(b"A" * 11)
        mock_build_opener.return_value = self.mock_opener(
            response
        )

        client = HTTPClient(max_size=10)

        with self.assertRaises(ValueError):
            client.get("https://example.test")

    @patch("modules.http.client.urllib.request.build_opener")
    def test_get_uses_get_method_and_user_agent(
        self,
        mock_build_opener
    ):
        response = self.make_response()
        mock_build_opener.return_value = self.mock_opener(
            response
        )

        self.client.get("https://example.test")

        opener = mock_build_opener.return_value
        request = opener.open.call_args.args[0]

        self.assertEqual(request.method, "GET")
        self.assertEqual(
            request.get_header("User-agent"),
            get_user_agent("default")
        )

    def test_unknown_user_agent_profile(self):
        self.assertEqual(
            get_user_agent("unknown"),
            get_user_agent("default")
        )

    @patch("modules.http.client.urllib.request.build_opener")
    def test_metadata_is_recorded(self, mock_build_opener):
        response = self.make_response(b"12345")
        mock_build_opener.return_value = self.mock_opener(
            response
        )

        result = self.client.get("https://example.test")

        self.assertEqual(
            result["metadata"]["content_type"],
            "text/html"
        )
        self.assertEqual(
            result["metadata"]["content_length"],
            "5"
        )
        self.assertEqual(
            result["metadata"]["server"],
            "ExampleServer"
        )
        self.assertEqual(
            result["metadata"]["body_bytes"],
            5
        )
        self.assertGreaterEqual(
            result["metadata"]["response_time_ms"],
            0
        )

    @patch("modules.http.client.urllib.request.build_opener")
    def test_multiple_set_cookie_headers_are_preserved(
        self,
        mock_build_opener
    ):
        response = self.make_response()

        response.headers.add_header(
            "Set-Cookie",
            "session=abc; Secure; HttpOnly"
        )
        response.headers.add_header(
            "Set-Cookie",
            "preference=dark; SameSite=Lax"
        )

        mock_build_opener.return_value = self.mock_opener(
            response
        )

        result = self.client.get("https://example.test")

        self.assertEqual(
            len(result["set_cookie_headers"]),
            2
        )
        self.assertIn(
            "Secure",
            result["set_cookie_headers"][0]
        )
        self.assertIn(
            "SameSite=Lax",
            result["set_cookie_headers"][1]
        )

    def test_redirect_handler_records_redirect(self):
        handler = TrackingRedirectHandler()

        request = Request("https://example.test/old")
        headers = Message()

        result = handler.redirect_request(
            request,
            None,
            301,
            "Moved Permanently",
            headers,
            "https://example.test/new"
        )

        self.assertIsNotNone(result)
        self.assertEqual(len(handler.chain), 1)
        self.assertEqual(
            handler.chain[0]["status"],
            301
        )
        self.assertEqual(
            handler.chain[0]["from_url"],
            "https://example.test/old"
        )
        self.assertEqual(
            handler.chain[0]["to_url"],
            "https://example.test/new"
        )


if __name__ == "__main__":
    unittest.main()

import unittest
from urllib.request import Request
from email.message import Message

from modules.http.client import TrackingRedirectHandler


class TestHTTPRedirectSecurity(unittest.TestCase):

    def setUp(self):
        self.handler = TrackingRedirectHandler()
        self.request = Request(
            "https://example.test/start",
            method="GET"
        )
        self.headers = Message()

    def test_accept_safe_https_redirect(self):
        result = self.handler.redirect_request(
            self.request,
            None,
            302,
            "Found",
            self.headers,
            "https://other.example.test/page"
        )

        self.assertIsNotNone(result)
        self.assertEqual(len(self.handler.chain), 1)

    def test_accept_relative_redirect(self):
        result = self.handler.redirect_request(
            self.request,
            None,
            302,
            "Found",
            self.headers,
            "/new-page"
        )

        self.assertIsNotNone(result)
        self.assertEqual(
            self.handler.chain[0]["to_url"],
            "https://example.test/new-page"
        )

    def test_reject_localhost_redirect(self):
        with self.assertRaises(ValueError):
            self.handler.redirect_request(
                self.request,
                None,
                302,
                "Found",
                self.headers,
                "http://localhost"
            )

        self.assertEqual(len(self.handler.chain), 0)

    def test_reject_private_ip_redirect(self):
        with self.assertRaises(ValueError):
            self.handler.redirect_request(
                self.request,
                None,
                302,
                "Found",
                self.headers,
                "http://127.0.0.1"
            )

        self.assertEqual(len(self.handler.chain), 0)

    def test_reject_ftp_redirect(self):
        with self.assertRaises(ValueError):
            self.handler.redirect_request(
                self.request,
                None,
                302,
                "Found",
                self.headers,
                "ftp://example.test"
            )

        self.assertEqual(len(self.handler.chain), 0)

    def test_reject_redirect_with_credentials(self):
        with self.assertRaises(ValueError):
            self.handler.redirect_request(
                self.request,
                None,
                302,
                "Found",
                self.headers,
                "https://user:pass@example.test"
            )

        self.assertEqual(len(self.handler.chain), 0)


if __name__ == "__main__":
    unittest.main()

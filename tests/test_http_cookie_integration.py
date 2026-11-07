import json
import unittest
from unittest.mock import patch

from modules.http.module import HTTPIntelligence


class TestHTTPCookieIntegration(unittest.TestCase):

    def setUp(self):
        self.module = HTTPIntelligence()
        self.findings = []

        self.context = {
            "target": "https://example.test"
        }

        self.cookie_secret = "SUPER_SECRET_COOKIE_VALUE"

        self.response = {
            "status": 200,
            "url": "https://example.test",
            "headers": {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY"
            },
            "body": "<html>Example</html>",
            "set_cookie_headers": [
                f"session={self.cookie_secret}; Secure; HttpOnly; SameSite=Lax",
                "preferences=dark; Secure; SameSite=Strict"
            ]
        }

    @patch("modules.http.module.HTTPClient.get")
    def test_cookie_analysis_saved_in_context(self, mock_get):
        mock_get.return_value = self.response

        self.module.run(
            self.context,
            self.findings.append
        )

        results = self.context["cookie_analysis"]

        self.assertEqual(len(results), 2)
        self.assertEqual(
            results[0]["cookie_name"],
            "session"
        )
        self.assertTrue(results[0]["secure"])
        self.assertTrue(results[0]["httponly"])
        self.assertEqual(results[0]["samesite"], "lax")

    @patch("modules.http.module.HTTPClient.get")
    def test_cookie_findings_generated(self, mock_get):
        mock_get.return_value = self.response

        self.module.run(
            self.context,
            self.findings.append
        )

        cookie_findings = [
            item for item in self.findings
            if item.template == "cookie-security"
        ]

        self.assertEqual(len(cookie_findings), 2)

    @patch("modules.http.module.HTTPClient.get")
    def test_cookie_value_not_in_findings(self, mock_get):
        mock_get.return_value = self.response

        self.module.run(
            self.context,
            self.findings.append
        )

        serialized = json.dumps([
            {
                "detail": item.detail,
                "evidence": item.evidence
            }
            for item in self.findings
        ])

        self.assertNotIn(self.cookie_secret, serialized)

    @patch("modules.http.module.HTTPClient.get")
    def test_missing_cookie_headers_produce_no_cookie_findings(
        self,
        mock_get
    ):
        response = dict(self.response)
        response.pop("set_cookie_headers")

        mock_get.return_value = response

        self.module.run(
            self.context,
            self.findings.append
        )

        cookie_findings = [
            item for item in self.findings
            if item.template == "cookie-security"
        ]

        self.assertEqual(cookie_findings, [])
        self.assertEqual(len(self.context["cookie_analysis"]), 0)

    @patch("modules.http.module.HTTPClient.get")
    def test_cookie_issues_are_reported(self, mock_get):
        mock_get.return_value = self.response

        self.module.run(
            self.context,
            self.findings.append
        )

        cookie_findings = [
            item for item in self.findings
            if item.template == "cookie-security"
        ]

        evidence = json.loads(cookie_findings[1].evidence)

        self.assertIn("httponly_not_observed", evidence["issues"])
        self.assertIn("samesite", evidence)


if __name__ == "__main__":
    unittest.main()

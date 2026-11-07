import unittest
from unittest.mock import patch

from modules.http.module import HTTPIntelligence
from core.events import Finding


class TestHTTPIntelligence(unittest.TestCase):

    def setUp(self):
        self.module = HTTPIntelligence()
        self.findings = []

        self.context = {
            "target": "https://example.test"
        }

        self.mock_response = {
            "status": 200,
            "url": "https://example.test",
            "headers": {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY"
            },
            "body": "<html>Example</html>"
        }

    @patch("modules.http.module.HTTPClient.get")
    def test_generates_seven_findings(self, mock_get):
        mock_get.return_value = self.mock_response

        self.module.run(
            self.context,
            self.findings.append
        )

        self.assertEqual(len(self.findings), 7)

    @patch("modules.http.module.HTTPClient.get")
    def test_first_finding_is_http_response(self, mock_get):
        mock_get.return_value = self.mock_response

        self.module.run(
            self.context,
            self.findings.append
        )

        finding = self.findings[0]

        self.assertEqual(finding.template, "http-response")
        self.assertEqual(finding.protocol, "HTTP")
        self.assertEqual(finding.severity, "info")
        self.assertIn("200", finding.detail)

    @patch("modules.http.module.HTTPClient.get")
    def test_security_header_findings(self, mock_get):
        mock_get.return_value = self.mock_response

        self.module.run(
            self.context,
            self.findings.append
        )

        templates = [
            finding.template
            for finding in self.findings
        ]

        self.assertIn(
            "header-content-security-policy",
            templates
        )

        self.assertIn(
            "header-x-frame-options",
            templates
        )

    @patch("modules.http.module.HTTPClient.get")
    def test_all_findings_are_valid(self, mock_get):
        mock_get.return_value = self.mock_response

        self.module.run(
            self.context,
            self.findings.append
        )

        for finding in self.findings:
            self.assertIsInstance(finding, Finding)
            self.assertTrue(finding.validate())

    @patch("modules.http.module.HTTPClient.get")
    def test_findings_use_response_url(self, mock_get):
        mock_get.return_value = self.mock_response

        self.module.run(
            self.context,
            self.findings.append
        )

        for finding in self.findings:
            self.assertEqual(
                finding.target,
                "https://example.test"
            )

    @patch("modules.http.module.HTTPClient.get")
    def test_missing_headers_are_not_observed(self, mock_get):
        response = {
            "status": 200,
            "url": "https://example.test",
            "headers": {},
            "body": ""
        }

        mock_get.return_value = response

        self.module.run(
            self.context,
            self.findings.append
        )

        for finding in self.findings[1:]:
            self.assertIn("not_observed", finding.detail)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

from modules.tls.module import TLSIntelligence


class TLSTests(unittest.TestCase):
    def setUp(self):
        self.module = TLSIntelligence()
        self.context = {"target": "https://example.test"}
        self.findings = []

    def emit(self, finding):
        self.findings.append(finding)

    def test_missing_hostname(self):
        self.module.run(self.context, self.emit)

        self.assertEqual(len(self.findings), 1)
        self.assertEqual(
            self.findings[0].template,
            "tls-no-hostname"
        )
        self.assertEqual(
            self.findings[0].severity,
            "unknown"
        )

    @patch("modules.tls.module.TLSAnalyzer")
    @patch("modules.tls.module.TLSReader")
    def test_successful_inspection(self, mock_reader, mock_analyzer):
        self.context["hostname"] = "example.test"

        mock_reader.return_value.inspect.return_value = {
            "tls_version": "TLSv1.3",
            "cipher": "TEST-CIPHER"
        }

        mock_analyzer.return_value.analyze.return_value = {
            "status": "valid_period",
            "days_remaining": 90
        }

        self.module.run(self.context, self.emit)

        self.assertEqual(len(self.findings), 1)
        self.assertEqual(
            self.findings[0].template,
            "tls-certificate"
        )
        self.assertIn(
            "TLSv1.3",
            self.findings[0].evidence
        )

    @patch("modules.tls.module.TLSReader")
    def test_connection_error(self, mock_reader):
        self.context["hostname"] = "example.test"
        mock_reader.return_value.inspect.side_effect = (
            ConnectionError("Connection failed")
        )

        self.module.run(self.context, self.emit)

        self.assertEqual(len(self.findings), 1)
        self.assertEqual(
            self.findings[0].template,
            "tls-connection-error"
        )
        self.assertEqual(
            self.findings[0].severity,
            "error"
        )

    def test_all_findings_are_valid(self):
        self.module.run(self.context, self.emit)

        for finding in self.findings:
            self.assertTrue(finding.validate())


if __name__ == "__main__":
    unittest.main()

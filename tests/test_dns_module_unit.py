import unittest
from unittest.mock import patch

from modules.dns.module import DNSIntelligence


class DNSTests(unittest.TestCase):

    def setUp(self):
        self.module = DNSIntelligence()
        self.context = {
            "target": "example.test",
            "hostname": "example.test",
            "dns_fixture": "example.test test fixture"
        }
        self.findings = []

    def emit(self, finding):
        self.findings.append(finding)

    def test_missing_dns_data(self):
        self.context["dns_fixture"] = ""

        self.module.run(self.context, self.emit)

        self.assertEqual(len(self.findings), 1)
        self.assertEqual(
            self.findings[0].template,
            "dns-no-data"
        )
        self.assertEqual(
            self.findings[0].severity,
            "unknown"
        )

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_dns_records_are_emitted(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = [
            {
                "type": "A",
                "name": "example.test",
                "value": "192.0.2.10"
            }
        ]

        mock_parser.return_value.errors = []
        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        self.module.run(self.context, self.emit)

        self.assertEqual(len(self.findings), 1)
        self.assertEqual(
            self.findings[0].template,
            "dns-a"
        )
        self.assertEqual(
            self.findings[0].evidence,
            "192.0.2.10"
        )

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_spf_policy_is_emitted(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = [
            {
                "type": "TXT",
                "name": "example.test",
                "value": "v=spf1 -all"
            }
        ]

        mock_parser.return_value.errors = []
        mock_spf.return_value.analyze.return_value = [
            {
                "status": "strict",
                "record": "v=spf1 -all"
            }
        ]
        mock_dmarc.return_value.analyze.return_value = []

        self.module.run(self.context, self.emit)

        templates = [
            finding.template for finding in self.findings
        ]

        self.assertIn("dns-txt", templates)
        self.assertIn("dns-spf-policy", templates)

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_dmarc_policy_is_emitted(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = [
            {
                "type": "TXT",
                "name": "_dmarc.example.test",
                "value": "v=DMARC1; p=none"
            }
        ]

        mock_parser.return_value.errors = []
        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = [
            {
                "status": "monitoring",
                "record": "v=DMARC1; p=none"
            }
        ]

        self.module.run(self.context, self.emit)

        templates = [
            finding.template for finding in self.findings
        ]

        self.assertIn("dns-dmarc-policy", templates)

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_txt_records_are_filtered_by_owner_name(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        records = [
            {
                "type": "TXT",
                "name": "example.test.",
                "value": "v=spf1 -all"
            },
            {
                "type": "TXT",
                "name": "example.test",
                "value": "google-site-verification=sample"
            },
            {
                "type": "TXT",
                "name": "mail.example.test",
                "value": "v=spf1 ~all"
            },
            {
                "type": "TXT",
                "name": "_dmarc.example.test.",
                "value": "v=DMARC1; p=none"
            },
            {
                "type": "TXT",
                "name": "_dmarc.mail.example.test",
                "value": "v=DMARC1; p=reject"
            }
        ]

        mock_parser.return_value.parse.return_value = records
        mock_parser.return_value.errors = []

        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        self.module.run(self.context, self.emit)

        spf_input = (
            mock_spf.return_value.analyze.call_args[0][0]
        )

        dmarc_input = (
            mock_dmarc.return_value.analyze.call_args[0][0]
        )

        self.assertEqual(
            [record["value"] for record in spf_input],
            ["v=spf1 -all"]
        )

        self.assertEqual(
            [record["value"] for record in dmarc_input],
            ["v=DMARC1; p=none"]
        )

        # Semua TXT tetap dicatat sebagai observasi.
        txt_findings = [
            finding for finding in self.findings
            if finding.template == "dns-txt"
        ]

        self.assertEqual(len(txt_findings), 5)

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_dns_names_are_case_insensitive(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = [
            {
                "type": "TXT",
                "name": "EXAMPLE.TEST.",
                "value": "v=spf1 -all"
            },
            {
                "type": "TXT",
                "name": "_DMARC.EXAMPLE.TEST.",
                "value": "v=DMARC1; p=reject"
            }
        ]

        mock_parser.return_value.errors = []
        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        self.module.run(self.context, self.emit)

        spf_input = (
            mock_spf.return_value.analyze.call_args[0][0]
        )

        dmarc_input = (
            mock_dmarc.return_value.analyze.call_args[0][0]
        )

        self.assertEqual(len(spf_input), 1)
        self.assertEqual(len(dmarc_input), 1)

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_parser_error_propagates(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.side_effect = (
            ValueError("Invalid DNS fixture")
        )

        with self.assertRaises(ValueError):
            self.module.run(self.context, self.emit)

        self.assertEqual(self.findings, [])

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_parser_warning_is_emitted(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = []
        mock_parser.return_value.errors = [
            {
                "line": 2,
                "reason": "Invalid TTL"
            }
        ]

        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        self.context["dns_fixture"] = (
            "example.test. 3600 IN A 192.0.2.10\n"
            "example.test. abc IN A 192.0.2.20"
        )

        self.module.run(self.context, self.emit)

        warnings = [
            finding for finding in self.findings
            if finding.template == "dns-parse-warning"
        ]

        self.assertEqual(len(warnings), 1)
        self.assertEqual(
            warnings[0].severity,
            "warning"
        )

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_parser_warning_contains_line_number(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = []
        mock_parser.return_value.errors = [
            {
                "line": 1,
                "reason": "Missing record value"
            }
        ]

        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        self.context["dns_fixture"] = (
            "example.test. 3600 IN A"
        )

        self.module.run(self.context, self.emit)

        warnings = [
            finding for finding in self.findings
            if finding.template == "dns-parse-warning"
        ]

        self.assertEqual(len(warnings), 1)
        self.assertIn(
            "line 1",
            warnings[0].detail
        )

    @patch("modules.dns.module.DMARCAnalyzer")
    @patch("modules.dns.module.SPFAnalyzer")
    @patch("modules.dns.module.DNSRecordParser")
    def test_parser_warning_contains_bad_line_evidence(
        self,
        mock_parser,
        mock_spf,
        mock_dmarc
    ):
        mock_parser.return_value.parse.return_value = []
        mock_parser.return_value.errors = [
            {
                "line": 1,
                "reason": "Invalid TTL"
            }
        ]

        mock_spf.return_value.analyze.return_value = []
        mock_dmarc.return_value.analyze.return_value = []

        bad_line = "example.test. abc IN A 192.0.2.10"
        self.context["dns_fixture"] = bad_line

        self.module.run(self.context, self.emit)

        warnings = [
            finding for finding in self.findings
            if finding.template == "dns-parse-warning"
        ]

        self.assertEqual(len(warnings), 1)
        self.assertEqual(
            warnings[0].evidence,
            bad_line
        )


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest

from pathlib import Path

from core.events import Finding
from output.json_report import (
    build_json_report,
    write_json_report
)


class JSONReportTests(unittest.TestCase):

    def setUp(self):
        self.context = {
            "target": "https://example.test",
            "hostname": "example.test",
            "component_inventory": [
                {
                    "product": "plugin",
                    "slug": "example-plugin",
                    "version": None,
                    "status": "referenced",
                    "version_source": None,
                    "source": "html-asset-path",
                    "evidence": [
                        "/wp-content/plugins/example-plugin/app.js"
                    ]
                }
            ]
        }

        self.findings = [
            Finding(
                template="http-response",
                protocol="HTTP",
                severity="info",
                target="https://example.test",
                detail="HTTP response received: 200",
                evidence="Status code: 200"
            )
        ]

    def test_build_report_metadata(self):
        report = build_json_report(
            self.context,
            self.findings
        )

        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(
            report["target"],
            "https://example.test"
        )
        self.assertEqual(
            report["hostname"],
            "example.test"
        )
        self.assertTrue(report["generated_at"])

    def test_finding_is_serialized(self):
        report = build_json_report(
            self.context,
            self.findings
        )

        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(
            report["findings"][0]["template"],
            "http-response"
        )
        self.assertEqual(
            report["findings"][0]["severity"],
            "info"
        )

    def test_unknown_component_version_remains_null(self):
        report = build_json_report(
            self.context,
            self.findings
        )

        item = report["component_inventory"][0]

        self.assertIsNone(item["version"])
        self.assertIsNone(item["version_source"])
        self.assertEqual(item["status"], "referenced")

    def test_write_and_read_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"

            result = write_json_report(
                path,
                self.context,
                self.findings
            )

            self.assertTrue(result.exists())

            loaded = json.loads(
                result.read_text(encoding="utf-8")
            )

            self.assertEqual(
                loaded["target"],
                "https://example.test"
            )
            self.assertEqual(
                len(loaded["findings"]),
                1
            )

    def test_invalid_inventory_is_rejected(self):
        context = {
            "target": "https://example.test",
            "component_inventory": "invalid"
        }

        with self.assertRaises(TypeError):
            build_json_report(context, [])

    def test_invalid_finding_is_rejected(self):
        with self.assertRaises(TypeError):
            build_json_report(
                self.context,
                ["not-a-finding"]
            )

    def test_dns_metadata_is_reported(self):
        self.context["dns_observations"] = {
            "hostname": "example.test",
            "resolver_source": "android-getprop",
            "nameservers": ["192.0.2.53"],
            "records": [
                {
                    "name": "example.test",
                    "type": "A",
                    "value": "192.0.2.10"
                }
            ],
            "queries": [
                {
                    "name": "example.test",
                    "type": "A",
                    "status": "answer",
                    "detail": "1 record(s) observed"
                },
                {
                    "name": "example.test",
                    "type": "AAAA",
                    "status": "timeout",
                    "detail": "DNS query timed out"
                }
            ]
        }

        report = build_json_report(
            self.context,
            self.findings
        )

        dns = report["dns"]

        self.assertEqual(
            dns["resolver_source"],
            "android-getprop"
        )
        self.assertEqual(
            dns["nameservers"],
            ["192.0.2.53"]
        )
        self.assertEqual(dns["record_count"], 1)
        self.assertEqual(len(dns["queries"]), 2)
        self.assertEqual(
            dns["queries"][1]["status"],
            "timeout"
        )

    def test_dns_metadata_is_none_when_unavailable(self):
        report = build_json_report(
            self.context,
            self.findings
        )

        self.assertIsNone(report["dns"])

    def test_invalid_dns_queries_are_rejected(self):
        self.context["dns_observations"] = {
            "records": [],
            "queries": "invalid",
            "nameservers": []
        }

        with self.assertRaises(TypeError):
            build_json_report(
                self.context,
                self.findings
            )


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from core.events import Finding
from output.html_report import build_html_report, write_html_report


class HTMLReportTests(unittest.TestCase):
    def setUp(self):
        self.context = {
            "target": "https://example.test",
            "hostname": "example.test",
            "component_inventory": [
                {
                    "product": "plugin",
                    "slug": "sample",
                    "status": "referenced",
                    "version": None,
                    "source": "html"
                }
            ]
        }
        self.findings = [
            Finding(
                template="http-header",
                protocol="HTTP",
                severity="warning",
                target="https://example.test",
                detail="Missing header",
                evidence="Strict-Transport-Security absent"
            )
        ]

    def test_report_contains_target_and_summary(self):
        result = build_html_report(self.context, self.findings)
        self.assertIn("https://example.test", result)
        self.assertIn("Finding summary", result)
        self.assertIn(">Warning</span>", result)
        self.assertIn("Observed component references", result)

    def test_report_escapes_untrusted_html(self):
        self.context["target"] = '<script>alert("x")</script>'
        self.findings[0].detail = '<img src=x onerror="alert(1)">'
        result = build_html_report(self.context, self.findings)
        self.assertNotIn('<script>alert("x")</script>', result)
        self.assertNotIn('<img src=x onerror="alert(1)">', result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&lt;img", result)

    def test_write_html_report_creates_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.html"
            result = write_html_report(path, self.context, self.findings)
            self.assertTrue(result.exists())
            self.assertIn("<!doctype html>", result.read_text(encoding="utf-8"))

    def test_empty_findings_are_explained(self):
        result = build_html_report(self.context, [])
        self.assertIn("No findings were recorded.", result)
        self.assertIn("does not prove that a site is secure", result)


if __name__ == "__main__":
    unittest.main()

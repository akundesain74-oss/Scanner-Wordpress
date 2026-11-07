import unittest

from modules.dns.dmarc import DMARCAnalyzer


class DMARCAnalyzerTests(unittest.TestCase):

    def setUp(self):
        self.analyzer = DMARCAnalyzer()

    def analyze(self, value):
        return self.analyzer.analyze([
            {"type": "TXT", "value": value}
        ])

    def test_reject_policy(self):
        result = self.analyze("v=DMARC1; p=reject")
        self.assertEqual(result[0]["status"], "strict")

    def test_quarantine_policy(self):
        result = self.analyze("v=DMARC1; p=quarantine")
        self.assertEqual(result[0]["status"], "quarantine")

    def test_none_policy(self):
        result = self.analyze("v=DMARC1; p=none")
        self.assertEqual(result[0]["status"], "monitoring")

    def test_invalid_version(self):
        result = self.analyze("v=DMARC10; p=reject")
        self.assertEqual(result[0]["status"], "invalid")

    def test_missing_policy(self):
        result = self.analyze("v=DMARC1")
        self.assertEqual(result[0]["status"], "invalid")

    def test_invalid_policy(self):
        result = self.analyze("v=DMARC1; p=invalid")
        self.assertEqual(result[0]["status"], "invalid")

    def test_duplicate_tag(self):
        result = self.analyze(
            "v=DMARC1; p=reject; p=none"
        )
        self.assertEqual(result[0]["status"], "invalid")

    def test_version_must_be_first(self):
        result = self.analyze("p=reject; v=DMARC1")
        self.assertEqual(result[0]["status"], "invalid")

    def test_non_dmarc_record_is_ignored(self):
        result = self.analyze(
            "google-site-verification=sample"
        )
        self.assertEqual(result, [])

    def test_rua_is_extracted(self):
        result = self.analyze(
            "v=DMARC1; p=none; rua=mailto:dmarc@example.test"
        )
        self.assertEqual(
            result[0]["rua"],
            "mailto:dmarc@example.test"
        )


if __name__ == "__main__":
    unittest.main()

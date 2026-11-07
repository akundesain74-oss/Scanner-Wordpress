import unittest

from modules.dns.spf import SPFAnalyzer


class SPFAnalyzerTests(unittest.TestCase):

    def setUp(self):
        self.analyzer = SPFAnalyzer()

    def analyze(self, value):
        return self.analyzer.analyze([
            {"type": "TXT", "value": value}
        ])

    def test_strict_policy(self):
        result = self.analyze('"v=spf1 -all"')
        self.assertEqual(result[0]["status"], "strict")

    def test_softfail_policy(self):
        result = self.analyze("v=spf1 ~all")
        self.assertEqual(result[0]["status"], "softfail")

    def test_neutral_policy(self):
        result = self.analyze("v=spf1 ?all")
        self.assertEqual(result[0]["status"], "neutral")

    def test_permissive_policy(self):
        result = self.analyze("v=spf1 +all")
        self.assertEqual(result[0]["status"], "permissive")

    def test_missing_all_mechanism(self):
        result = self.analyze("v=spf1 include:example.test")
        self.assertEqual(result[0]["status"], "missing-all")

    def test_invalid_version(self):
        result = self.analyze("v=spf10 -all")
        self.assertEqual(result[0]["status"], "invalid")

    def test_duplicate_all_mechanisms(self):
        result = self.analyze("v=spf1 -all ~all")
        self.assertEqual(result[0]["status"], "invalid")

    def test_non_spf_record_is_ignored(self):
        result = self.analyze("google-site-verification=sample")
        self.assertEqual(result, [])

    def test_empty_value_is_ignored(self):
        result = self.analyze("")
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()

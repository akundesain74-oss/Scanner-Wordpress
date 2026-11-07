
import unittest
from datetime import datetime, timedelta, timezone

from modules.tls.analyzer import TLSAnalyzer


class TestTLSAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = TLSAnalyzer()
        now = datetime.now(timezone.utc)

        self.valid_certificate = {
            "not_before": (
                now - timedelta(days=10)
            ).strftime("%b %d %H:%M:%S %Y GMT"),
            "not_after": (
                now + timedelta(days=80)
            ).strftime("%b %d %H:%M:%S %Y GMT"),
            "hostname_match": True,
            "verified": True
        }

    def test_valid_certificate(self):
        result = self.analyzer.analyze(
            self.valid_certificate
        )
        self.assertEqual(result["status"], "valid_period")

    def test_hostname_match(self):
        result = self.analyzer.analyze(
            self.valid_certificate
        )
        self.assertTrue(result["hostname_match"])

    def test_verified_certificate(self):
        result = self.analyzer.analyze(
            self.valid_certificate
        )
        self.assertTrue(result["verified"])

    def test_missing_dates(self):
        result = self.analyzer.analyze({})
        self.assertEqual(result["status"], "unknown")

    def test_expired_certificate(self):
        now = datetime.now(timezone.utc)

        certificate = {
            "not_before": (
                now - timedelta(days=100)
            ).strftime("%b %d %H:%M:%S %Y GMT"),
            "not_after": (
                now - timedelta(days=10)
            ).strftime("%b %d %H:%M:%S %Y GMT")
        }

        result = self.analyzer.analyze(certificate)
        self.assertEqual(result["status"], "expired")


if __name__ == "__main__":
    unittest.main()

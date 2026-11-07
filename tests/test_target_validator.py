
import unittest

from core.validation.target import TargetValidator


class TestTargetValidator(unittest.TestCase):

    def setUp(self):
        self.validator = TargetValidator()

    def test_valid_https(self):
        valid, result = self.validator.validate(
            "https://example.test"
        )
        self.assertTrue(valid)
        self.assertEqual(result, "example.test")

    def test_valid_http_path(self):
        valid, result = self.validator.validate(
            "http://example.test/path"
        )
        self.assertTrue(valid)

    def test_reject_ftp(self):
        valid, _ = self.validator.validate(
            "ftp://example.test"
        )
        self.assertFalse(valid)

    def test_reject_empty_hostname(self):
        valid, _ = self.validator.validate("https://")
        self.assertFalse(valid)

    def test_reject_credentials(self):
        valid, _ = self.validator.validate(
            "https://user:pass@example.test"
        )
        self.assertFalse(valid)

    def test_reject_localhost(self):
        valid, _ = self.validator.validate(
            "http://localhost"
        )
        self.assertFalse(valid)

    def test_reject_private_ip(self):
        valid, _ = self.validator.validate(
            "http://127.0.0.1"
        )
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()

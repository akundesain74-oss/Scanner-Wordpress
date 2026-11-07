import unittest

from modules.http.cookies import CookieAnalyzer


class CookieAnalyzerTests(unittest.TestCase):

    def setUp(self):
        self.analyzer = CookieAnalyzer()

    def test_all_security_attributes_present(self):
        result = self.analyzer.analyze([
            "session=abc; Secure; HttpOnly; SameSite=Strict"
        ])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cookie_name"], "session")
        self.assertTrue(result[0]["secure"])
        self.assertTrue(result[0]["httponly"])
        self.assertEqual(result[0]["samesite"], "strict")
        self.assertEqual(result[0]["issues"], [])

    def test_missing_attributes_are_reported(self):
        result = self.analyzer.analyze([
            "session=abc"
        ])

        self.assertEqual(
            result[0]["issues"],
            [
                "secure_not_observed",
                "httponly_not_observed",
                "samesite_not_observed"
            ]
        )

    def test_multiple_cookies_are_analyzed(self):
        result = self.analyzer.analyze([
            "session=abc; Secure; HttpOnly",
            "preference=dark; SameSite=Lax"
        ])

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["cookie_name"], "session")
        self.assertEqual(result[1]["cookie_name"], "preference")

    def test_attribute_names_are_case_insensitive(self):
        result = self.analyzer.analyze([
            "session=abc; secure; HTTPONLY; SAMESITE=Lax"
        ])

        self.assertTrue(result[0]["secure"])
        self.assertTrue(result[0]["httponly"])
        self.assertEqual(result[0]["samesite"], "lax")

    def test_samesite_none_without_secure(self):
        result = self.analyzer.analyze([
            "session=abc; SameSite=None"
        ])

        self.assertIn(
            "samesite_none_without_secure",
            result[0]["issues"]
        )

    def test_samesite_none_with_secure(self):
        result = self.analyzer.analyze([
            "session=abc; Secure; SameSite=None"
        ])

        self.assertNotIn(
            "samesite_none_without_secure",
            result[0]["issues"]
        )

    def test_invalid_cookie_format(self):
        result = self.analyzer.analyze([
            "invalid-cookie"
        ])

        self.assertEqual(result[0]["status"], "invalid")
        self.assertIsNone(result[0]["cookie_name"])

    def test_empty_cookie_name(self):
        result = self.analyzer.analyze([
            "=abc; Secure"
        ])

        self.assertEqual(result[0]["status"], "invalid")

    def test_cookie_value_is_not_stored(self):
        result = self.analyzer.analyze([
            "session=secret-token-123; Secure; HttpOnly"
        ])

        self.assertNotIn(
            "secret-token-123",
            str(result)
        )

    def test_empty_input(self):
        self.assertEqual(
            self.analyzer.analyze([]),
            []
        )

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            self.analyzer.analyze("session=abc")


if __name__ == "__main__":
    unittest.main()

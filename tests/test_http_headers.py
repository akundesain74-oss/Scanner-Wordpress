import unittest

from modules.http.headers import (
    analyze_headers,
    SECURITY_HEADERS
)


class TestHTTPHeaders(unittest.TestCase):

    def test_all_headers_detected(self):
        headers = {
            header: "test-value"
            for header in SECURITY_HEADERS
        }

        result = analyze_headers(headers)

        self.assertEqual(
            len(result),
            len(SECURITY_HEADERS)
        )

        for item in result:
            self.assertEqual(item["status"], "present")

    def test_missing_headers(self):
        result = analyze_headers({})

        self.assertEqual(
            len(result),
            len(SECURITY_HEADERS)
        )

        for item in result:
            self.assertEqual(
                item["status"],
                "not_observed"
            )

            self.assertIsNone(item["value"])

    def test_case_insensitive_headers(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY"
        }

        result = analyze_headers(headers)

        csp = next(
            item for item in result
            if item["header"] == "content-security-policy"
        )

        frame = next(
            item for item in result
            if item["header"] == "x-frame-options"
        )

        self.assertEqual(csp["status"], "present")
        self.assertEqual(frame["status"], "present")

    def test_header_value_preserved(self):
        headers = {
            "strict-transport-security":
                "max-age=31536000; includeSubDomains"
        }

        result = analyze_headers(headers)

        item = next(
            item for item in result
            if item["header"] == "strict-transport-security"
        )

        self.assertEqual(
            item["value"],
            "max-age=31536000; includeSubDomains"
        )

    def test_unknown_header_ignored(self):
        headers = {
            "x-custom-header": "custom-value"
        }

        result = analyze_headers(headers)

        self.assertEqual(
            len(result),
            len(SECURITY_HEADERS)
        )


if __name__ == "__main__":
    unittest.main()

import unittest
from pathlib import Path

from modules.wordpress.fingerprint import analyze_html


class TestWordPressFingerprint(unittest.TestCase):

    def setUp(self):
        fixture = Path("tests/fixtures/wordpress_sample.html")
        self.html = fixture.read_text(encoding="utf-8")

    def test_detect_wordpress(self):
        result = analyze_html(self.html)

        self.assertTrue(result["likely_wordpress"])

    def test_confidence_high(self):
        result = analyze_html(self.html)

        self.assertEqual(result["confidence"], "high")

    def test_detect_generator(self):
        result = analyze_html(self.html)

        names = [
            item["name"]
            for item in result["indicators"]
        ]

        self.assertIn("generator-meta", names)

    def test_detect_wp_content(self):
        result = analyze_html(self.html)

        names = [
            item["name"]
            for item in result["indicators"]
        ]

        self.assertIn("wp-content", names)

    def test_detect_wp_includes(self):
        result = analyze_html(self.html)

        names = [
            item["name"]
            for item in result["indicators"]
        ]

        self.assertIn("wp-includes", names)

    def test_detect_api_link(self):
        result = analyze_html(self.html)

        names = [
            item["name"]
            for item in result["indicators"]
        ]

        self.assertIn("wordpress-api-link", names)

    def test_non_wordpress_html(self):
        html = """
        <html>
            <head><title>Example Website</title></head>
            <body><h1>Hello World</h1></body>
        </html>
        """

        result = analyze_html(html)

        self.assertFalse(result["likely_wordpress"])
        self.assertEqual(result["confidence"], "low")


if __name__ == "__main__":
    unittest.main()

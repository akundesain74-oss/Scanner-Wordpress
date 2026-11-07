import unittest
from unittest.mock import patch

from modules.http.module import HTTPIntelligence


class HTTPInventoryIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.module = HTTPIntelligence()
        self.findings = []

        self.context = {
            "target": "https://example.test"
        }

    @patch("modules.http.module.HTTPClient.get")
    def test_plugin_inventory_is_stored(self, mock_get):
        mock_get.return_value = {
            "status": 200,
            "url": "https://example.test",
            "headers": {
                "Content-Type": "text/html"
            },
            "body": """
                <script src="/wp-content/plugins/example-plugin/app.js">
                </script>
            """
        }

        self.module.run(
            self.context,
            self.findings.append
        )

        inventory = self.context["component_inventory"]

        self.assertEqual(len(inventory), 1)
        self.assertEqual(inventory[0]["product"], "plugin")
        self.assertEqual(inventory[0]["slug"], "example-plugin")

    @patch("modules.http.module.HTTPClient.get")
    def test_inventory_version_remains_unknown(self, mock_get):
        mock_get.return_value = {
            "status": 200,
            "url": "https://example.test",
            "headers": {
                "Content-Type": "text/html"
            },
            "body": """
                <script src="/wp-content/plugins/example-plugin/app.js?ver=9.9.9">
                </script>
            """
        }

        self.module.run(
            self.context,
            self.findings.append
        )

        item = self.context["component_inventory"][0]

        self.assertIsNone(item["version"])
        self.assertIsNone(item["version_source"])
        self.assertEqual(item["status"], "referenced")

    @patch("modules.http.module.HTTPClient.get")
    def test_non_html_response_has_empty_inventory(self, mock_get):
        mock_get.return_value = {
            "status": 200,
            "url": "https://example.test/data.json",
            "headers": {
                "Content-Type": "application/json"
            },
            "body": """
                <script src="/wp-content/plugins/example-plugin/app.js">
                </script>
            """
        }

        self.module.run(
            self.context,
            self.findings.append
        )

        self.assertEqual(
            self.context["component_inventory"],
            []
        )

    @patch("modules.http.module.HTTPClient.get")
    def test_http_response_is_stored_in_context(self, mock_get):
        response = {
            "status": 200,
            "url": "https://example.test",
            "headers": {
                "Content-Type": "text/html"
            },
            "body": "<html></html>"
        }

        mock_get.return_value = response

        self.module.run(
            self.context,
            self.findings.append
        )

        self.assertIs(
            self.context["http_response"],
            response
        )


if __name__ == "__main__":
    unittest.main()

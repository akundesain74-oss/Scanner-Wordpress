import unittest

from modules.wordpress.component_inventory import (
    analyze_components
)


class ComponentInventoryTests(unittest.TestCase):

    def test_detect_plugin_reference(self):
        html = """
        <script src="/wp-content/plugins/example-plugin/js/app.js">
        </script>
        """

        results = analyze_components(html)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["product"], "plugin")
        self.assertEqual(results[0]["slug"], "example-plugin")

    def test_detect_theme_reference(self):
        html = """
        <link
            href="/wp-content/themes/example-theme/css/style.css"
            rel="stylesheet"
        >
        """

        results = analyze_components(html)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["product"], "theme")
        self.assertEqual(results[0]["slug"], "example-theme")

    def test_version_is_never_guessed_from_query(self):
        html = """
        <script src="/wp-content/plugins/example-plugin/app.js?ver=9.9.9">
        </script>
        """

        results = analyze_components(html)

        self.assertEqual(results[0]["version"], None)
        self.assertIsNone(results[0]["version_source"])

    def test_duplicate_references_are_deduplicated(self):
        html = """
        <script src="/wp-content/plugins/example-plugin/a.js"></script>
        <script src="/wp-content/plugins/example-plugin/b.js"></script>
        """

        results = analyze_components(html)

        self.assertEqual(len(results), 1)
        self.assertEqual(len(results[0]["evidence"]), 2)

    def test_unrelated_path_is_ignored(self):
        html = """
        <script src="/assets/plugins/example-plugin/app.js"></script>
        """

        results = analyze_components(html)

        self.assertEqual(results, [])

    def test_external_asset_reference(self):
        html = """
        <script src="https://cdn.example.test/wp-content/plugins/example-plugin/app.js">
        </script>
        """

        results = analyze_components(html)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "referenced")

    def test_invalid_html_input(self):
        with self.assertRaises(TypeError):
            analyze_components(None)


if __name__ == "__main__":
    unittest.main()

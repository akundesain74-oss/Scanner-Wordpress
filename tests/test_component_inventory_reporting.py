import unittest
from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout

from modules.wordpress.component_inventory import analyze_components
from output.terminal import Terminal


class ComponentInventoryReportingTests(unittest.TestCase):

    def test_fixture_parser_to_terminal_report(self):
        fixture_path = Path(
            "tests/fixtures/component_inventory_sample.html"
        )

        html = fixture_path.read_text(encoding="utf-8")
        inventory = analyze_components(html)

        context = {
            "component_inventory": inventory
        }

        output = StringIO()

        with redirect_stdout(output):
            Terminal(color=False).report_component_inventory(context)

        report = output.getvalue()

        self.assertEqual(len(inventory), 2)

        self.assertIn("Plugin references: 1", report)
        self.assertIn("Theme references:  1", report)

        self.assertIn("contact-form", report)
        self.assertIn("example-theme", report)

        self.assertIn("Version: unknown", report)
        self.assertIn("Status:  referenced", report)

        self.assertIn(
            "/wp-content/plugins/contact-form/assets/style.css",
            report
        )

        self.assertIn(
            "/wp-content/themes/example-theme/style.css",
            report
        )

        for item in inventory:
            self.assertIsNone(item["version"])
            self.assertEqual(item["status"], "referenced")


if __name__ == "__main__":
    unittest.main()

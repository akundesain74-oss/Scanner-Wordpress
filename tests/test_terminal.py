import unittest
from io import StringIO
from contextlib import redirect_stdout

from output.terminal import Terminal
from core.events import Finding


def make_finding(
    severity="info",
    evidence=None,
    source=None
):
    return Finding(
        template="test-finding",
        protocol="HTTP",
        severity=severity,
        target="example.test",
        detail="Example detail",
        evidence=evidence,
        source=source
    )


class TerminalTests(unittest.TestCase):
    def test_emit_without_color(self):
        terminal = Terminal(color=False)
        output = StringIO()

        with redirect_stdout(output):
            terminal.emit(make_finding())

        result = output.getvalue()

        self.assertIn("[test-finding]", result)
        self.assertIn("[HTTP]", result)
        self.assertIn("Example detail", result)
        self.assertNotIn("\033[", result)

    def test_emit_with_color(self):
        terminal = Terminal(color=True)
        output = StringIO()

        with redirect_stdout(output):
            terminal.emit(make_finding())

        self.assertIn("\033[96m", output.getvalue())
        self.assertIn("\033[0m", output.getvalue())

    def test_emit_shows_evidence(self):
        terminal = Terminal(color=False)
        output = StringIO()

        with redirect_stdout(output):
            terminal.emit(
                make_finding(evidence="Status code: 200")
            )

        self.assertIn("Evidence: Status code: 200", output.getvalue())

    def test_emit_shows_source(self):
        terminal = Terminal(color=False)
        output = StringIO()

        with redirect_stdout(output):
            terminal.emit(
                make_finding(source="Local test")
            )

        self.assertIn("Source: Local test", output.getvalue())

    def test_emit_rejects_invalid_finding(self):
        terminal = Terminal(color=False)
        finding = make_finding()
        finding.severity = "critical"

        with self.assertRaises(ValueError):
            terminal.emit(finding)

    def test_banner_contains_project_name(self):
        terminal = Terminal()
        output = StringIO()

        with redirect_stdout(output):
            terminal.banner()

        self.assertIn("ANDIKZZ WORDPRESS v8.0", output.getvalue())


if __name__ == "__main__":
    unittest.main()


class ComponentInventoryReportTests(unittest.TestCase):

    def test_empty_inventory_report(self):
        terminal = Terminal(color=False)
        output = StringIO()

        with redirect_stdout(output):
            terminal.report_component_inventory({
                "component_inventory": []
            })

        result = output.getvalue()

        self.assertIn("Plugin references: 0", result)
        self.assertIn("Theme references:  0", result)
        self.assertIn("does not prove", result)

    def test_inventory_report_shows_evidence(self):
        terminal = Terminal(color=False)
        output = StringIO()

        context = {
            "component_inventory": [
                {
                    "product": "plugin",
                    "slug": "example-plugin",
                    "version": None,
                    "status": "referenced",
                    "source": "html-asset-path",
                    "evidence": [
                        "/wp-content/plugins/example-plugin/app.js"
                    ]
                },
                {
                    "product": "theme",
                    "slug": "example-theme",
                    "version": None,
                    "status": "referenced",
                    "source": "html-asset-path",
                    "evidence": [
                        "/wp-content/themes/example-theme/style.css"
                    ]
                }
            ]
        }

        with redirect_stdout(output):
            terminal.report_component_inventory(context)

        result = output.getvalue()

        self.assertIn("Plugin references: 1", result)
        self.assertIn("Theme references:  1", result)
        self.assertIn("example-plugin", result)
        self.assertIn("example-theme", result)
        self.assertIn("Version: unknown", result)
        self.assertIn("referenced", result)
        self.assertIn("/wp-content/plugins/example-plugin/app.js", result)
        self.assertIn("does not confirm installation", result)

    def test_invalid_inventory_format(self):
        terminal = Terminal(color=False)
        output = StringIO()

        with redirect_stdout(output):
            terminal.report_component_inventory({
                "component_inventory": "invalid"
            })

        self.assertIn(
            "invalid format",
            output.getvalue()
        )

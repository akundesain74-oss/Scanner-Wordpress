import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import main


class MainTests(unittest.TestCase):

    def setUp(self):
        self.terminal = Mock()
        self.engine = Mock()

        self.engine.modules = []
        self.engine.findings = []
        self.engine.register.side_effect = self.engine.modules.append

        self.terminal_class = patch(
            "main.Terminal",
            return_value=self.terminal
        )

        self.engine_class = patch(
            "main.Engine",
            return_value=self.engine
        )

        self.validator_class = patch("main.TargetValidator")

        self.json_report = patch(
            "main.write_json_report",
            return_value=Path("output/report.json")
        )

        self.terminal_class.start()
        self.engine_class.start()
        self.mock_validator = self.validator_class.start()
        self.mock_json_report = self.json_report.start()

        self.addCleanup(self.terminal_class.stop)
        self.addCleanup(self.engine_class.stop)
        self.addCleanup(self.validator_class.stop)
        self.addCleanup(self.json_report.stop)

    @patch("builtins.input", return_value="https://example.test/")
    def test_valid_target_executes_engine(self, mock_input):
        self.mock_validator.return_value.validate.return_value = (
            True,
            "example.test"
        )

        main.main()

        self.engine.execute.assert_called_once()

        context = self.engine.execute.call_args.args[0]

        self.assertEqual(
            context["target"],
            "https://example.test/"
        )

        self.assertEqual(
            context["hostname"],
            "example.test"
        )

        self.assertNotIn("dns_fixture", context)

        self.mock_json_report.assert_called_once_with(
            Path("output/report.json"),
            context,
            self.engine.findings
        )

    @patch("builtins.input", return_value="invalid-target")
    def test_invalid_target_stops_execution(self, mock_input):
        self.mock_validator.return_value.validate.return_value = (
            False,
            "Invalid hostname"
        )

        main.main()

        self.engine.execute.assert_not_called()
        self.mock_json_report.assert_not_called()

    @patch("builtins.input", return_value="https://example.test/")
    def test_dns_fixture_is_not_required(self, mock_input):
        self.mock_validator.return_value.validate.return_value = (
            True,
            "example.test"
        )

        main.main()

        self.engine.execute.assert_called_once()

    @patch("builtins.input", return_value="  https://example.test/  ")
    def test_input_is_stripped(self, mock_input):
        self.mock_validator.return_value.validate.return_value = (
            True,
            "example.test"
        )

        main.main()

        context = self.engine.execute.call_args.args[0]

        self.assertEqual(
            context["target"],
            "https://example.test/"
        )

    @patch("builtins.input", return_value="https://example.test/")
    def test_registers_four_modules(self, mock_input):
        self.mock_validator.return_value.validate.return_value = (
            True,
            "example.test"
        )

        main.main()

        self.assertEqual(
            self.engine.register.call_count,
            4
        )


if __name__ == "__main__":
    unittest.main()

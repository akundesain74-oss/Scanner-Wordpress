import unittest
from unittest.mock import Mock, patch

from core.engine import Engine
from core.events import Finding


def make_finding():
    return Finding(
        template="test-finding",
        protocol="TEST",
        severity="info",
        target="example.test",
        detail="Test detail"
    )


class FakeModule:
    name = "Fake Module"

    def run(self, context, emit):
        emit(make_finding())


class BrokenModule:
    name = "Broken Module"

    def run(self, context, emit):
        raise RuntimeError("Module crashed")


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.terminal = Mock()
        self.engine = Engine(self.terminal)

    def test_register_valid_module(self):
        module = FakeModule()
        self.engine.register(module)
        self.assertEqual(len(self.engine.modules), 1)

    def test_register_rejects_invalid_module(self):
        with self.assertRaises(TypeError):
            self.engine.register(object())

    def test_emit_stores_finding(self):
        finding = make_finding()
        self.engine.emit(finding)

        self.assertEqual(len(self.engine.findings), 1)
        self.assertIs(self.engine.findings[0], finding)

    def test_emit_calls_terminal(self):
        finding = make_finding()
        self.engine.emit(finding)

        self.terminal.emit.assert_called_once_with(finding)

    def test_emit_rejects_invalid_finding(self):
        finding = make_finding()
        finding.severity = "critical"

        with self.assertRaises(ValueError):
            self.engine.emit(finding)

        self.assertEqual(self.engine.findings, [])
        self.terminal.emit.assert_not_called()

    def test_execute_calls_banner(self):
        self.engine.execute({})
        self.terminal.banner.assert_called_once()

    def test_execute_runs_registered_module(self):
        module = FakeModule()
        self.engine.register(module)

        self.engine.execute({"target": "example.test"})

        self.assertEqual(len(self.engine.findings), 1)

    def test_execute_continues_after_module_error(self):
        self.engine.register(BrokenModule())
        self.engine.register(FakeModule())

        with patch("builtins.print"):
            self.engine.execute({})

        self.assertEqual(len(self.engine.findings), 1)

    def test_execute_reports_module_error(self):
        self.engine.register(BrokenModule())

        with patch("builtins.print") as mocked_print:
            self.engine.execute({})

        output = " ".join(
            str(call.args)
            for call in mocked_print.call_args_list
        )

        self.assertIn("Broken Module", output)
        self.assertIn("RuntimeError", output)
        self.assertIn("Module crashed", output)


if __name__ == "__main__":
    unittest.main()

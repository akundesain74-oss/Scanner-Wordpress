import unittest
import importlib

TEST_MODULES = [
    "tests.test_http_module",
    "tests.test_engine",
    "tests.test_terminal",
    "tests.test_main",
    "tests.test_tls_module",
    "tests.test_dns_module_unit",
    "tests.test_dns_parser",
    "tests.test_fingerprint",
    "tests.test_http_client",
    "tests.test_http_redirect_security",
    "tests.test_core_version",
    "tests.test_dns",
    "tests.test_spf",
    "tests.test_dmarc",
    "tests.test_dns_module",
    "tests.test_http_headers",
    "tests.test_tls",
    "tests.test_tls_analyzer",
    "tests.test_target_validator",
    "tests.test_vulnerability_matcher",
    "tests.test_vulnerability_database",
    "tests.test_vulnerability_integration",
    "tests.test_http_inventory_integration",
    "tests.test_component_inventory",
    "tests.test_component_inventory_reporting",
    "tests.test_json_report",
    "tests.test_html_report",
]


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    for module_name in TEST_MODULES:
        module = importlib.import_module(module_name)
        module_suite = loader.loadTestsFromModule(module)
        suite.addTests(module_suite)

    print("\nANDIKZZ WORDPRESS TEST RUNNER")
    print("=" * 40)

    result = unittest.TextTestRunner(
        verbosity=2
    ).run(suite)

    print("\nANDIKZZ TEST SUMMARY")
    print("=" * 40)
    print("Tests run:", result.testsRun)
    print("Failures:", len(result.failures))
    print("Errors:", len(result.errors))
    print("Skipped:", len(result.skipped))

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

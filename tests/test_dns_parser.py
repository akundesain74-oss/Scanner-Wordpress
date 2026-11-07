import unittest

from modules.dns.records import DNSRecordParser


class DNSRecordParserTests(unittest.TestCase):

    def setUp(self):
        self.parser = DNSRecordParser()

    def test_parse_standard_records(self):
        content = (
            "example.test. 3600 IN A 192.0.2.10\n"
            "example.test. 3600 IN AAAA 2001:db8::10\n"
            "example.test. 3600 IN MX 10 mail.example.test.\n"
            "example.test. 3600 IN NS ns1.example.test.\n"
            "example.test. 3600 IN TXT \"v=spf1 -all\"\n"
            "www.example.test. 3600 IN CNAME example.test.\n"
        )

        records = self.parser.parse(content)

        self.assertEqual(len(records), 6)
        self.assertEqual(self.parser.errors, [])

    def test_parse_txt_with_spaces(self):
        records = self.parser.parse(
            'example.test. 3600 IN TXT "v=spf1 -all"'
        )

        self.assertEqual(records[0]["value"], "v=spf1 -all")

    def test_parse_without_ttl(self):
        records = self.parser.parse(
            "example.test. IN A 192.0.2.10"
        )

        self.assertEqual(records[0]["ttl"], None)
        self.assertEqual(records[0]["class"], "IN")

    def test_parse_without_class(self):
        records = self.parser.parse(
            "example.test. 3600 A 192.0.2.10"
        )

        self.assertEqual(records[0]["ttl"], "3600")
        self.assertIsNone(records[0]["class"])

    def test_parse_without_ttl_and_class(self):
        records = self.parser.parse(
            "example.test. A 192.0.2.10"
        )

        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0]["ttl"])
        self.assertIsNone(records[0]["class"])

    def test_empty_input(self):
        self.assertEqual(self.parser.parse(""), [])
        self.assertEqual(self.parser.errors, [])

    def test_comment_lines_are_ignored(self):
        content = (
            "; DNS comment\n"
            "\n"
            "example.test. 3600 IN A 192.0.2.10"
        )

        records = self.parser.parse(content)

        self.assertEqual(len(records), 1)

    def test_incomplete_record_is_reported(self):
        records = self.parser.parse(
            "example.test. 3600 IN"
        )

        self.assertEqual(records, [])
        self.assertEqual(len(self.parser.errors), 1)
        self.assertEqual(self.parser.errors[0]["line"], 1)

    def test_missing_record_value_is_reported(self):
        records = self.parser.parse(
            "example.test. 3600 IN A"
        )

        self.assertEqual(records, [])
        self.assertEqual(
            self.parser.errors[0]["reason"],
            "Missing record value"
        )

    def test_invalid_ttl_is_reported(self):
        records = self.parser.parse(
            "example.test. abc IN A 192.0.2.10"
        )

        self.assertEqual(records, [])
        self.assertEqual(len(self.parser.errors), 1)

    def test_invalid_quoted_value_is_reported(self):
        records = self.parser.parse(
            'example.test. 3600 IN TXT "unfinished'
        )

        self.assertEqual(records, [])
        self.assertIn(
            "Invalid quoting",
            self.parser.errors[0]["reason"]
        )

    def test_non_string_input_is_rejected(self):
        with self.assertRaises(TypeError):
            self.parser.parse(None)

    def test_errors_reset_between_runs(self):
        self.parser.parse("invalid record")

        self.assertTrue(self.parser.errors)

        self.parser.parse(
            "example.test. 3600 IN A 192.0.2.10"
        )

        self.assertEqual(self.parser.errors, [])

    def test_valid_ipv4_address(self):
        records = self.parser.parse(
            "example.test. IN A 192.0.2.10"
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["value"], "192.0.2.10")
        self.assertEqual(self.parser.errors, [])

    def test_valid_ipv6_address(self):
        records = self.parser.parse(
            "example.test. IN AAAA 2001:db8::10"
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["value"], "2001:db8::10")
        self.assertEqual(self.parser.errors, [])

    def test_invalid_ipv4_address(self):
        records = self.parser.parse(
            "example.test. IN A 999.999.999.999"
        )

        self.assertEqual(records, [])
        self.assertTrue(self.parser.errors)

    def test_invalid_ipv6_address(self):
        records = self.parser.parse(
            "example.test. IN AAAA invalid-ipv6"
        )

        self.assertEqual(records, [])
        self.assertTrue(self.parser.errors)

    def test_a_record_rejects_ipv6(self):
        records = self.parser.parse(
            "example.test. IN A 2001:db8::10"
        )

        self.assertEqual(records, [])
        self.assertIn(
            "A record requires an IPv4 address",
            self.parser.errors[0]["reason"]
        )

    def test_aaaa_record_rejects_ipv4(self):
        records = self.parser.parse(
            "example.test. IN AAAA 192.0.2.10"
        )

        self.assertEqual(records, [])
        self.assertIn(
            "AAAA record requires an IPv6 address",
            self.parser.errors[0]["reason"]
        )


if __name__ == "__main__":
    unittest.main()

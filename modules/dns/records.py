
import ipaddress
import shlex


class DNSRecordParser:

    SUPPORTED_TYPES = {
        "A", "AAAA", "CNAME",
        "MX", "NS", "TXT"
    }

    SUPPORTED_CLASSES = {
        "IN", "CH", "HS", "ANY"
    }

    def __init__(self):
        self.errors = []

    def parse(self, content):
        if not isinstance(content, str):
            raise TypeError("DNS content must be a string")

        results = []
        self.errors = []

        for line_number, raw_line in enumerate(
            content.splitlines(), start=1
        ):
            line = raw_line.strip()

            if not line or line.startswith(";"):
                continue

            try:
                lexer = shlex.shlex(line, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = ""
                parts = list(lexer)

            except ValueError as error:
                self._add_error(
                    line_number,
                    f"Invalid quoting: {error}"
                )
                continue

            if len(parts) < 3:
                self._add_error(
                    line_number,
                    "Incomplete DNS record"
                )
                continue

            record_index = None

            for index in range(1, min(4, len(parts))):
                if parts[index].upper() in self.SUPPORTED_TYPES:
                    record_index = index
                    break

            if record_index is None:
                self._add_error(
                    line_number,
                    "Unsupported or missing record type"
                )
                continue

            if record_index + 1 >= len(parts):
                self._add_error(
                    line_number,
                    "Missing record value"
                )
                continue

            name = parts[0]
            ttl = None
            record_class = None
            invalid_prefix = False

            for item in parts[1:record_index]:
                upper_item = item.upper()

                if item.isdigit():
                    if ttl is not None:
                        invalid_prefix = True
                        break
                    ttl = item

                elif upper_item in self.SUPPORTED_CLASSES:
                    if record_class is not None:
                        invalid_prefix = True
                        break
                    record_class = upper_item

                else:
                    invalid_prefix = True
                    break

            if invalid_prefix:
                self._add_error(
                    line_number,
                    "Invalid or duplicate TTL/class field"
                )
                continue

            record_type = parts[record_index].upper()
            value_parts = parts[record_index + 1:]

            if record_type in {"A", "AAAA"}:
                if len(value_parts) != 1:
                    self._add_error(
                        line_number,
                        f"{record_type} record must contain one IP address"
                    )
                    continue

                if not self._validate_ip(
                    value_parts[0],
                    record_type,
                    line_number
                ):
                    continue

            results.append({
                "name": name,
                "ttl": ttl,
                "class": record_class,
                "type": record_type,
                "value": " ".join(value_parts)
            })

        return results

    def _validate_ip(self, value, record_type, line_number):
        try:
            address = ipaddress.ip_address(value)

        except ValueError:
            self._add_error(
                line_number,
                f"Invalid IP address for {record_type} record"
            )
            return False

        if record_type == "A" and address.version != 4:
            self._add_error(
                line_number,
                "A record requires an IPv4 address"
            )
            return False

        if record_type == "AAAA" and address.version != 6:
            self._add_error(
                line_number,
                "AAAA record requires an IPv6 address"
            )
            return False

        return True

    def _add_error(self, line_number, reason):
        self.errors.append({
            "line": line_number,
            "reason": reason
        })

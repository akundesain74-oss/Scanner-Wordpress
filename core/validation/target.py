
from urllib.parse import urlparse
import ipaddress
import re


class TargetValidator:

    ALLOWED_SCHEMES = {"http", "https"}

    def validate(self, target):
        if not isinstance(target, str):
            return False, "Target must be text"

        target = target.strip()

        if not target:
            return False, "Target cannot be empty"

        if any(char.isspace() for char in target):
            return False, "Whitespace is not allowed in URL"

        try:
            parsed = urlparse(target)

            if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
                return False, "Only HTTP and HTTPS are allowed"

            if not parsed.hostname:
                return False, "Hostname is missing"

            if parsed.username or parsed.password:
                return False, "URL credentials are not allowed"

            if parsed.port is not None and not (
                1 <= parsed.port <= 65535
            ):
                return False, "Invalid port"

            hostname = parsed.hostname.rstrip(".").lower()

            if len(hostname) > 253:
                return False, "Hostname is too long"

            try:
                ip = ipaddress.ip_address(hostname)

                if not ip.is_global:
                    return False, "Non-public IP addresses are not allowed"

            except ValueError:
                labels = hostname.split(".")

                if len(labels) < 2:
                    return False, "A fully qualified domain is required"

                for label in labels:
                    if (
                        not label
                        or len(label) > 63
                        or not re.fullmatch(
                            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                            label
                        )
                    ):
                        return False, "Invalid hostname format"

            return True, hostname

        except ValueError:
            return False, "Malformed URL"

import ipaddress
import subprocess

import dns.exception
import dns.resolver


class DNSLiveResolver:
    QUERY_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

    def __init__(self, timeout=2.0, lifetime=4.0, resolver=None):
        if resolver is not None:
            self.resolver = resolver
            self.nameserver_source = "injected"
        else:
            self.resolver = self._create_resolver()

        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime

    @staticmethod
    def _android_nameservers():
        nameservers = []

        for prop in ("net.dns1", "net.dns2", "net.dns3", "net.dns4"):
            try:
                result = subprocess.run(
                    ["getprop", prop],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False
                )

                value = result.stdout.strip()

                if value:
                    try:
                        ipaddress.ip_address(value)
                        if value not in nameservers:
                            nameservers.append(value)
                    except ValueError:
                        continue

            except (OSError, subprocess.TimeoutExpired):
                continue

        return nameservers

    def _create_resolver(self):
        try:
            resolver = dns.resolver.Resolver(configure=True)
            self.nameserver_source = "system"
            return resolver

        except dns.resolver.NoResolverConfiguration:
            resolver = dns.resolver.Resolver(configure=False)

            nameservers = self._android_nameservers()

            if nameservers:
                resolver.nameservers = nameservers
                self.nameserver_source = "android-getprop"
            else:
                resolver.nameservers = ["1.1.1.1"]
                self.nameserver_source = "public-fallback"

            return resolver

    def resolve(self, hostname):
        if not isinstance(hostname, str) or not hostname.strip():
            raise ValueError("Hostname must be a non-empty string")

        hostname = hostname.strip().rstrip(".")

        records = []
        queries = []

        requests = [
            (hostname, record_type)
            for record_type in self.QUERY_TYPES
        ]

        requests.append((f"_dmarc.{hostname}", "TXT"))

        for query_name, record_type in requests:
            result = self._query(query_name, record_type)

            queries.append({
                "name": query_name,
                "type": record_type,
                "status": result["status"],
                "detail": result["detail"]
            })

            records.extend(result["records"])

        return {
            "hostname": hostname,
            "resolver_source": self.nameserver_source,
            "nameservers": list(self.resolver.nameservers),
            "records": records,
            "queries": queries
        }

    def _query(self, name, record_type):
        try:
            answer = self.resolver.resolve(
                name,
                record_type,
                search=False,
                raise_on_no_answer=True
            )

            records = []

            ttl = (
                answer.rrset.ttl
                if answer.rrset is not None
                else None
            )

            for item in answer:
                value = self._format_value(record_type, item)

                records.append({
                    "name": name,
                    "ttl": ttl,
                    "class": "IN",
                    "type": record_type,
                    "value": value
                })

            return {
                "status": "answer",
                "detail": f"{len(records)} record(s) observed",
                "records": records
            }

        except dns.resolver.NXDOMAIN:
            return self._empty_result(
                "nxdomain",
                "DNS name does not exist"
            )

        except dns.resolver.NoAnswer:
            return self._empty_result(
                "no-answer",
                "No answer returned for this record type"
            )

        except dns.resolver.LifetimeTimeout:
            return self._empty_result(
                "timeout",
                "DNS query exceeded its lifetime"
            )

        except dns.exception.Timeout:
            return self._empty_result(
                "timeout",
                "DNS query timed out"
            )

        except dns.resolver.NoNameservers:
            return self._empty_result(
                "error",
                "No nameserver returned a usable response"
            )

        except (dns.exception.DNSException, OSError) as error:
            return self._empty_result(
                "error",
                f"{type(error).__name__}: {error}"
            )

    @staticmethod
    def _format_value(record_type, item):
        if record_type in ("A", "AAAA"):
            return item.address

        if record_type == "MX":
            return f"{item.preference} {item.exchange.to_text()}"

        if record_type == "NS":
            return item.target.to_text()

        if record_type == "TXT":
            return b"".join(item.strings).decode(
                "utf-8",
                errors="replace"
            )

        return item.to_text()

    @staticmethod
    def _empty_result(status, detail):
        return {
            "status": status,
            "detail": detail,
            "records": []
        }

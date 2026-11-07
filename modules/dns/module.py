from core.events import Finding
from modules.dns.records import DNSRecordParser
from modules.dns.spf import SPFAnalyzer
from modules.dns.dmarc import DMARCAnalyzer


class DNSIntelligence:
    name = "DNS Intelligence"

    def __init__(self):
        self.resolver = None

    @staticmethod
    def _normalize_name(name):
        if not isinstance(name, str):
            return ""

        return name.strip().rstrip(".").lower()

    @staticmethod
    def _is_spf_candidate(record):
        value = record.get("value", "")

        if not isinstance(value, str):
            return False

        value = value.strip().strip('"').strip("'").strip()

        if not value:
            return False

        first_token = value.split()[0]

        return first_token.lower().startswith("v=spf")

    @staticmethod
    def _is_dmarc_candidate(record):
        value = record.get("value", "")

        if not isinstance(value, str):
            return False

        value = value.strip().strip('"').strip("'").strip()

        if not value:
            return False

        return any(
            item.strip().lower().startswith("v=dmarc")
            for item in value.split(";")
        )

    def run(self, context, emit):
        hostname = context.get(
            "hostname",
            context.get("target", "unknown")
        )

        observations = context.get("dns_observations")

        if observations is None and self.resolver is not None:
            observations = self.resolver.resolve(hostname)

        if observations is not None:
            context["dns_observations"] = observations

            records = observations.get("records", [])

            self._emit_query_status(
                observations,
                hostname,
                emit
            )

            self._emit_records(records, context, emit)
            return

        content = context.get("dns_fixture", "")

        if not content:
            emit(Finding(
                template="dns-no-data",
                protocol="DNS",
                severity="unknown",
                target=hostname,
                detail=(
                    "No DNS observations supplied; "
                    "live DNS resolver is not configured"
                )
            ))
            return

        parser = DNSRecordParser()
        records = parser.parse(content)

        self._emit_records(records, context, emit)

        lines = content.splitlines()

        for error in parser.errors:
            line_number = error["line"]

            evidence = (
                lines[line_number - 1].strip()
                if 0 < line_number <= len(lines)
                else None
            )

            emit(Finding(
                template="dns-parse-warning",
                protocol="DNS",
                severity="warning",
                target=hostname,
                detail=(
                    f"Malformed DNS record at line "
                    f"{line_number}: {error['reason']}"
                ),
                evidence=evidence
            ))

    def _emit_query_status(self, observations, hostname, emit):
        for query in observations.get("queries", []):
            status = query.get("status", "unknown")

            if status == "answer":
                continue

            severity = (
                "error" if status == "error"
                else "unknown"
            )

            emit(Finding(
                template=f"dns-query-{status}",
                protocol="DNS",
                severity=severity,
                target=query.get("name", hostname),
                detail=(
                    f"{query.get('type', 'UNKNOWN')} query: "
                    f"{query.get('detail', 'No details supplied')}"
                )
            ))

    def _emit_records(self, records, context, emit):
        # Semua record tetap dicatat sebagai observasi DNS.
        for record in records:
            emit(Finding(
                template=f"dns-{record['type'].lower()}",
                protocol="DNS",
                severity="info",
                target=record["name"],
                detail=f"{record['type']} record observed",
                evidence=record["value"]
            ))

        hostname = self._normalize_name(
            context.get(
                "hostname",
                context.get("target", "unknown")
            )
        )

        dmarc_hostname = f"_dmarc.{hostname}"

        txt_records = [
            record for record in records
            if record.get("type") == "TXT"
        ]

        # SPF: hanya TXT kandidat SPF pada hostname utama.
        spf_records = [
            record for record in txt_records
            if (
                self._normalize_name(record.get("name")) == hostname
                and self._is_spf_candidate(record)
            )
        ]

        # DMARC: hanya TXT kandidat DMARC pada owner _dmarc.
        dmarc_records = [
            record for record in txt_records
            if (
                self._normalize_name(record.get("name")) == dmarc_hostname
                and self._is_dmarc_candidate(record)
            )
        ]

        for result in SPFAnalyzer().analyze(spf_records):
            emit(Finding(
                template="dns-spf-policy",
                protocol="DNS",
                severity="info",
                target=hostname,
                detail=f"SPF policy: {result['status']}",
                evidence=result["record"]
            ))

        for result in DMARCAnalyzer().analyze(dmarc_records):
            emit(Finding(
                template="dns-dmarc-policy",
                protocol="DNS",
                severity="info",
                target=hostname,
                detail=f"DMARC policy: {result['status']}",
                evidence=result["record"]
            ))

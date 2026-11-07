from datetime import datetime, timezone


class TLSCertificateAnalyzer:

    def analyze(self, certificate):
        now = datetime.now(timezone.utc)

        not_before = certificate["not_before"]
        not_after = certificate["not_after"]

        if now < not_before:
            status = "not_yet_valid"
        elif now > not_after:
            status = "expired"
        else:
            status = "valid_period"

        remaining = not_after - now

        return {
            "subject": certificate["subject"],
            "issuer": certificate["issuer"],
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": remaining.days,
            "status": status,
            "hostname_match": certificate.get(
                "hostname_match",
                None
            ),
            "verified": certificate.get(
                "verified",
                False
            )
        }

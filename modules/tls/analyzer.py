import ssl
from datetime import datetime, timezone


class TLSAnalyzer:

    def analyze(self, certificate):
        not_before = certificate.get("not_before")
        not_after = certificate.get("not_after")

        if not not_before or not not_after:
            return {
                "status": "unknown",
                "days_remaining": None,
                "hostname_match": certificate.get(
                    "hostname_match", False
                ),
                "verified": certificate.get("verified", False)
            }

        try:
            start_timestamp = ssl.cert_time_to_seconds(
                not_before
            )
            end_timestamp = ssl.cert_time_to_seconds(
                not_after
            )

            now = datetime.now(timezone.utc).timestamp()

            if now < start_timestamp:
                status = "not_yet_valid"
            elif now > end_timestamp:
                status = "expired"
            else:
                remaining = (end_timestamp - now) / 86400

                if remaining <= 30:
                    status = "expiring_soon"
                else:
                    status = "valid_period"

            days_remaining = int(
                (end_timestamp - now) / 86400
            )

            return {
                "status": status,
                "days_remaining": days_remaining,
                "hostname_match": certificate.get(
                    "hostname_match", False
                ),
                "verified": certificate.get("verified", False)
            }

        except (ValueError, TypeError, OverflowError):
            return {
                "status": "unknown",
                "days_remaining": None,
                "hostname_match": False,
                "verified": False
            }

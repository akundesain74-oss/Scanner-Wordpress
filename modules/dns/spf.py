class SPFAnalyzer:

    POLICIES = {
        "-all": (
            "strict",
            "Unauthorized senders are rejected"
        ),
        "~all": (
            "softfail",
            "Unauthorized senders receive softfail"
        ),
        "?all": (
            "neutral",
            "SPF policy is neutral"
        ),
        "+all": (
            "permissive",
            "All senders are permitted"
        ),
        "all": (
            "permissive",
            "All senders are permitted"
        )
    }

    def analyze(self, txt_records):
        results = []

        for record in txt_records:
            value = record.get("value", "").strip()
            value = value.strip('"').strip("'").strip()

            if not value:
                continue

            first_token = value.split()[0]

            # Abaikan TXT record yang bukan kandidat SPF.
            if not first_token.lower().startswith("v=spf"):
                continue

            # Versi SPF harus tepat v=spf1.
            if first_token.lower() != "v=spf1":
                results.append({
                    "record": value,
                    "status": "invalid",
                    "detail": "Invalid SPF version"
                })
                continue

            mechanisms = value.split()[1:]

            all_mechanisms = [
                item.lower()
                for item in mechanisms
                if item.lower() in self.POLICIES
            ]

            if len(all_mechanisms) > 1:
                results.append({
                    "record": value,
                    "status": "invalid",
                    "detail": "Multiple all mechanisms detected"
                })
                continue

            if not all_mechanisms:
                results.append({
                    "record": value,
                    "status": "missing-all",
                    "detail": "No all mechanism observed"
                })
                continue

            status, detail = self.POLICIES[
                all_mechanisms[0]
            ]

            results.append({
                "record": value,
                "status": status,
                "detail": detail
            })

        return results

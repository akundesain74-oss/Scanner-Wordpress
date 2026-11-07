class DMARCAnalyzer:

    VALID_POLICIES = {
        "none",
        "quarantine",
        "reject"
    }

    def analyze(self, txt_records):
        results = []

        for record in txt_records:
            value = record.get("value", "").strip()
            value = value.strip('"').strip("'").strip()

            if not value:
                continue

            parts = value.split(";")
            first_tag = parts[0].strip()

            # Cari kandidat DMARC di seluruh tag.
            is_dmarc = any(
                item.strip().lower().startswith("v=dmarc")
                for item in parts
            )

            if not is_dmarc:
                continue

            tags = {}
            invalid_reason = None

            # Versi harus menjadi tag pertama.
            if first_tag.lower() != "v=dmarc1":
                invalid_reason = "Version tag must be first"

            for item in parts:
                item = item.strip()

                if not item:
                    continue

                if "=" not in item:
                    invalid_reason = (
                        invalid_reason or "Malformed DMARC tag"
                    )
                    continue

                key, val = item.split("=", 1)
                key = key.strip().lower()
                val = val.strip()

                if not key or not val:
                    invalid_reason = (
                        invalid_reason or "Empty DMARC tag"
                    )
                    continue

                if key in tags:
                    invalid_reason = (
                        invalid_reason or "Duplicate DMARC tag"
                    )
                    continue

                tags[key] = val

            policy = tags.get("p", "").lower()

            if first_tag.lower() == "v=dmarc1":
                if not policy:
                    invalid_reason = (
                        invalid_reason or "Missing required p tag"
                    )
                elif policy not in self.VALID_POLICIES:
                    invalid_reason = (
                        invalid_reason or "Invalid DMARC policy"
                    )

            if invalid_reason:
                results.append({
                    "record": value,
                    "policy": policy or "missing",
                    "status": "invalid",
                    "detail": invalid_reason,
                    "rua": tags.get("rua"),
                    "ruf": tags.get("ruf"),
                    "adkim": tags.get("adkim"),
                    "aspf": tags.get("aspf")
                })
                continue

            if policy == "reject":
                status = "strict"
            elif policy == "quarantine":
                status = "quarantine"
            else:
                status = "monitoring"

            results.append({
                "record": value,
                "policy": policy,
                "status": status,
                "detail": "Valid DMARC policy observed",
                "rua": tags.get("rua"),
                "ruf": tags.get("ruf"),
                "adkim": tags.get("adkim"),
                "aspf": tags.get("aspf")
            })

        return results

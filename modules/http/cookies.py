class CookieAnalyzer:

    @staticmethod
    def analyze(set_cookie_headers):
        if not isinstance(set_cookie_headers, list):
            raise TypeError(
                "Set-Cookie headers must be a list"
            )

        results = []

        for raw_cookie in set_cookie_headers:
            if not isinstance(raw_cookie, str):
                continue

            parts = [
                part.strip()
                for part in raw_cookie.split(";")
            ]

            if not parts or "=" not in parts[0]:
                results.append({
                    "cookie_name": None,
                    "status": "invalid",
                    "secure": None,
                    "httponly": None,
                    "samesite": None,
                    "issues": ["invalid_cookie_format"]
                })
                continue

            name = parts[0].split("=", 1)[0].strip()

            if not name:
                results.append({
                    "cookie_name": None,
                    "status": "invalid",
                    "secure": None,
                    "httponly": None,
                    "samesite": None,
                    "issues": ["missing_cookie_name"]
                })
                continue

            attributes = {}

            for part in parts[1:]:
                if not part:
                    continue

                key, separator, value = part.partition("=")
                key = key.strip().lower()

                if not key:
                    continue

                if separator:
                    attributes[key] = value.strip()
                else:
                    attributes[key] = None

            secure = "secure" in attributes
            httponly = "httponly" in attributes

            samesite = attributes.get("samesite")

            if isinstance(samesite, str):
                samesite = samesite.lower()

            if samesite not in ("strict", "lax", "none"):
                samesite = None

            issues = []

            if not secure:
                issues.append("secure_not_observed")

            if not httponly:
                issues.append("httponly_not_observed")

            if samesite is None:
                issues.append("samesite_not_observed")

            elif samesite == "none" and not secure:
                issues.append("samesite_none_without_secure")

            results.append({
                "cookie_name": name,
                "status": "observed",
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "issues": issues
            })

        return results

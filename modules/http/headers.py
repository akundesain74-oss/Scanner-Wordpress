SECURITY_HEADERS = {
    "content-security-policy":
        "Content Security Policy",

    "strict-transport-security":
        "HTTP Strict Transport Security",

    "x-content-type-options":
        "MIME sniffing protection",

    "x-frame-options":
        "Clickjacking protection",

    "referrer-policy":
        "Referrer information policy",

    "permissions-policy":
        "Browser permissions policy"
}


def analyze_headers(headers):
    normalized = {
        key.lower(): value
        for key, value in headers.items()
    }

    results = []

    for header, description in SECURITY_HEADERS.items():
        value = normalized.get(header)

        if value:
            results.append({
                "header": header,
                "status": "present",
                "description": description,
                "value": value
            })
        else:
            results.append({
                "header": header,
                "status": "not_observed",
                "description": description,
                "value": None
            })

    return results

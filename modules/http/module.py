import json

from core.events import Finding
from modules.http.client import HTTPClient
from modules.http.headers import analyze_headers
from modules.http.cookies import CookieAnalyzer
from modules.wordpress.component_inventory import analyze_components


class HTTPIntelligence:
    name = "HTTP Intelligence"

    def __init__(self):
        self.client = HTTPClient()

    def run(self, context, emit):
        target = context["target"]

        response = self.client.get(target)

        # Simpan respons untuk kebutuhan modul berikutnya.
        context["http_response"] = response

        # Inventaris hanya dibuat dari respons HTML.
        headers = response.get("headers", {})

        content_type = ""

        for name, value in headers.items():
            if name.lower() == "content-type":
                content_type = str(value).lower()
                break

        body = response.get("body", "")

        if (
            isinstance(body, str)
            and (
                "text/html" in content_type
                or "application/xhtml+xml" in content_type
            )
        ):
            context["component_inventory"] = (
                analyze_components(body)
            )
        else:
            context["component_inventory"] = []

        # Analisis atribut keamanan cookie.
        set_cookie_headers = response.get(
            "set_cookie_headers",
            []
        )

        cookie_results = CookieAnalyzer.analyze(
            set_cookie_headers
        )

        # Hasil analisis tidak menyimpan nilai cookie.
        context["cookie_analysis"] = cookie_results

        emit(Finding(
            template="http-response",
            protocol="HTTP",
            severity="info",
            target=response["url"],
            detail=f"HTTP response received: {response['status']}",
            evidence=f"Status code: {response['status']}"
        ))

        # Analisis header keamanan.
        header_findings = analyze_headers(
            response["headers"]
        )

        for item in header_findings:
            status = item["status"]

            emit(Finding(
                template=f"header-{item['header']}",
                protocol="HTTP",
                severity="info",
                target=response["url"],
                detail=(
                    f"{item['description']}: "
                    f"{status}"
                ),
                evidence=item["value"]
            ))

        # Finding observasi atribut cookie.
        for cookie in cookie_results:
            evidence = {
                "cookie_name": cookie["cookie_name"],
                "secure": cookie["secure"],
                "httponly": cookie["httponly"],
                "samesite": cookie["samesite"],
                "issues": cookie["issues"]
            }

            emit(Finding(
                template="cookie-security",
                protocol="HTTP",
                severity="info",
                target=response["url"],
                detail=(
                    "Cookie security attributes observed: "
                    f"{cookie['cookie_name'] or 'unknown'}"
                ),
                evidence=json.dumps(
                    evidence,
                    sort_keys=True
                )
            ))

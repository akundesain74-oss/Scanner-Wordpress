import time
import urllib.request
import urllib.error

from urllib.parse import urljoin
from modules.http.user_agents import get_user_agent
from core.validation.target import TargetValidator


class TrackingRedirectHandler(urllib.request.HTTPRedirectHandler):

    def __init__(self, validator=None):
        super().__init__()
        self.chain = []
        self.validator = validator or TargetValidator()

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl
    ):
        absolute_url = urljoin(req.full_url, newurl)

        valid, reason = self.validator.validate(absolute_url)

        if not valid:
            raise ValueError(
                f"Unsafe redirect rejected: {reason}"
            )

        self.chain.append({
            "status": code,
            "from_url": req.full_url,
            "to_url": absolute_url
        })

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            absolute_url
        )


class HTTPClient:

    def __init__(self, timeout=10, max_size=1024 * 1024):
        self.timeout = timeout
        self.max_size = max_size
        self.validator = TargetValidator()

    def validate_url(self, url):
        valid, result = self.validator.validate(url)

        if not valid:
            raise ValueError(result)

        return url

    @staticmethod
    def _extract_headers(headers):
        if headers is None:
            return {}

        return {
            str(key): str(value)
            for key, value in headers.items()
        }

    @staticmethod
    def _extract_cookies(headers):
        if headers is None:
            return []

        if hasattr(headers, "get_all"):
            values = headers.get_all("Set-Cookie", [])
            return [str(value) for value in values]

        if isinstance(headers, dict):
            return [
                str(value)
                for key, value in headers.items()
                if key.lower() == "set-cookie"
            ]

        return []

    @staticmethod
    def _get_header(headers, name):
        for key, value in headers.items():
            if key.lower() == name.lower():
                return str(value)

        return None

    def get(self, url):
        self.validate_url(url)

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": get_user_agent("default"),
                "Accept": "text/html,application/json,*/*"
            },
            method="GET"
        )

        redirect_handler = TrackingRedirectHandler(
            validator=self.validator
        )

        opener = urllib.request.build_opener(
            redirect_handler
        )

        started = time.perf_counter()

        try:
            with opener.open(
                request,
                timeout=self.timeout
            ) as response:

                body = response.read(self.max_size + 1)

                if len(body) > self.max_size:
                    raise ValueError(
                        "Response exceeds size limit"
                    )

                elapsed = (
                    time.perf_counter() - started
                ) * 1000

                headers = self._extract_headers(
                    response.headers
                )

                return self._build_result(
                    status=response.status,
                    url=response.geturl(),
                    headers=headers,
                    header_source=response.headers,
                    body=body,
                    elapsed=elapsed,
                    redirect_chain=redirect_handler.chain
                )

        except urllib.error.HTTPError as error:
            elapsed = (
                time.perf_counter() - started
            ) * 1000

            headers = self._extract_headers(
                error.headers
            )

            return self._build_result(
                status=error.code,
                url=error.url,
                headers=headers,
                header_source=error.headers,
                body=b"",
                elapsed=elapsed,
                redirect_chain=redirect_handler.chain
            )

    def _build_result(
        self,
        status,
        url,
        headers,
        header_source,
        body,
        elapsed,
        redirect_chain
    ):
        return {
            "status": status,
            "url": url,
            "headers": headers,
            "body": body.decode(
                "utf-8",
                errors="replace"
            ),

            "redirect_chain": list(redirect_chain),

            "set_cookie_headers": self._extract_cookies(
                header_source
            ),

            "metadata": {
                "content_type": self._get_header(
                    headers,
                    "Content-Type"
                ),
                "content_length": self._get_header(
                    headers,
                    "Content-Length"
                ),
                "server": self._get_header(
                    headers,
                    "Server"
                ),
                "body_bytes": len(body),
                "response_time_ms": round(elapsed, 3)
            }
        }

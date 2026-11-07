import socket
import ssl


class TLSReader:

    def __init__(self, timeout=8):
        self.timeout = timeout

    def inspect(self, hostname):
        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=self.timeout
        ) as connection:

            with context.wrap_socket(
                connection,
                server_hostname=hostname
            ) as tls:

                certificate = tls.getpeercert()

                return {
                    "hostname": hostname,
                    "tls_version": tls.version(),
                    "cipher": tls.cipher()[0],
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "not_before": certificate.get("notBefore"),
                    "not_after": certificate.get("notAfter"),
                    "verified": True
                }

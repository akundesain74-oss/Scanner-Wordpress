from core.events import Finding
from modules.tls.reader import TLSReader
from modules.tls.analyzer import TLSAnalyzer


class TLSIntelligence:

    name = "TLS Intelligence"

    def run(self, context, emit):
        hostname = context.get("hostname")

        if not hostname:
            emit(Finding(
                template="tls-no-hostname",
                protocol="TLS",
                severity="unknown",
                target=context["target"],
                detail="Hostname unavailable"
            ))
            return

        try:
            certificate = TLSReader().inspect(hostname)
            result = TLSAnalyzer().analyze(certificate)

            emit(Finding(
                template="tls-certificate",
                protocol="TLS",
                severity="verified",
                target=hostname,
                detail=(
                    f"Certificate status: "
                    f"{result['status']}"
                ),
                evidence=(
                    f"TLS: {certificate['tls_version']} | "
                    f"Cipher: {certificate['cipher']} | "
                    f"Days remaining: "
                    f"{result['days_remaining']}"
                )
            ))

        except Exception as error:
            emit(Finding(
                template="tls-connection-error",
                protocol="TLS",
                severity="error",
                target=hostname,
                detail=f"TLS inspection failed: {error}"
            ))

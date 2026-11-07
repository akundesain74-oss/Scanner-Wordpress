from datetime import datetime, timedelta, timezone

from modules.tls_certificate import TLSCertificateAnalyzer


now = datetime.now(timezone.utc)

certificate = {
    "subject": "example.test",
    "issuer": "Example Test CA",
    "not_before": now - timedelta(days=10),
    "not_after": now + timedelta(days=80),
    "hostname_match": True,
    "verified": True
}

result = TLSCertificateAnalyzer().analyze(certificate)

print("ANDIKZZ TLS INTELLIGENCE")
print("=" * 35)

print("Subject:", result["subject"])
print("Issuer:", result["issuer"])
print("Status:", result["status"])
print("Days remaining:", result["days_remaining"])
print("Hostname match:", result["hostname_match"])
print("Verified:", result["verified"])

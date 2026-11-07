from pathlib import Path

from modules.dns.module import DNSIntelligence


fixture = Path("tests/fixtures/dns_sample.txt")

context = {
    "target": "example.test",
    "dns_fixture": fixture.read_text(encoding="utf-8")
}


class TestEmitter:

    def __call__(self, finding):
        finding.validate()

        print(
            f"[{finding.template}] "
            f"[{finding.severity}] "
            f"{finding.detail}"
        )

        if finding.evidence:
            print(" Evidence:", finding.evidence)


print("ANDIKZZ DNS INTEGRATION TEST")
print("=" * 40)

DNSIntelligence().run(context, TestEmitter())

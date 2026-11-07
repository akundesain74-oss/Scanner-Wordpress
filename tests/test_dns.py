from pathlib import Path
from modules.dns.records import DNSRecordParser


fixture = Path(
    "tests/fixtures/dns_sample.txt"
)

content = fixture.read_text(encoding="utf-8")

parser = DNSRecordParser()
records = parser.parse(content)

print("ANDIKZZ DNS INTELLIGENCE")
print("=" * 35)

for record in records:
    print(
        f"[DNS] [{record['type']}] "
        f"{record['name']} -> {record['value']}"
    )

print()
print("Total records:", len(records))

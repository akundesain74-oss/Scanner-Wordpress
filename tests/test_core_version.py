from pathlib import Path
from modules.wordpress.core_version import analyze_core_version

fixture = Path(
    "tests/fixtures/wordpress_sample.html"
)

html = fixture.read_text(encoding="utf-8")

result = analyze_core_version(html)

print("WORDPRESS CORE VERSION TEST")
print("=" * 35)

for item in result["versions"]:
    print("[OBSERVED]", item["version"])
    print("Source:", item["source"])
    print("Confirmed:", item["confirmed"])

print("Confirmed version:", result["confirmed_version"])
print("Note:", result["note"])

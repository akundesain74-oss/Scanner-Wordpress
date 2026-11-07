import re
from html.parser import HTMLParser


class VersionParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generators = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "meta":
            return

        attrs = dict(attrs)

        if attrs.get("name", "").lower() == "generator":
            self.generators.append(
                attrs.get("content", "")
            )


def analyze_core_version(html):
    parser = VersionParser()
    parser.feed(html)

    results = []

    for value in parser.generators:
        match = re.search(
            r"wordpress\s+(\d+\.\d+(?:\.\d+)?)",
            value,
            re.IGNORECASE
        )

        if match:
            results.append({
                "version": match.group(1),
                "source": "generator-meta",
                "status": "observed",
                "confirmed": False
            })

    return {
        "versions": results,
        "confirmed_version": None,
        "note": (
            "Generator metadata is an observation, "
            "not proof of installed core version."
        )
    }

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit


COMPONENT_PATTERN = re.compile(
    r"(?:^|/)wp-content/(plugins|themes)/([^/]+)/",
    re.IGNORECASE
)

SLUG_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9._-]*$"
)


class ComponentParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.references = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        for attribute in ("src", "href"):
            value = attributes.get(attribute)

            if not isinstance(value, str) or not value:
                continue

            self.references.append(value)


def analyze_components(html):

    if not isinstance(html, str):
        raise TypeError("HTML must be a string")

    parser = ComponentParser()
    parser.feed(html)
    parser.close()

    components = {}

    for reference in parser.references:

        try:
            path = urlsplit(reference).path
        except ValueError:
            continue

        match = COMPONENT_PATTERN.search(path)

        if not match:
            continue

        component_type = match.group(1).lower()
        slug = match.group(2).lower()

        if not SLUG_PATTERN.fullmatch(slug):
            continue

        key = (component_type, slug)

        if key not in components:
            components[key] = {
                "product": (
                    "plugin"
                    if component_type == "plugins"
                    else "theme"
                ),
                "slug": slug,
                "version": None,
                "status": "referenced",
                "version_source": None,
                "source": "html-asset-path",
                "evidence": []
            }

        if reference not in components[key]["evidence"]:
            components[key]["evidence"].append(reference)

    return sorted(
        components.values(),
        key=lambda item: (
            item["product"],
            item["slug"]
        )
    )

import re
from html.parser import HTMLParser
from urllib.parse import urlparse


class WordPressParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generator = []
        self.assets = []
        self.api_links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        # Generator metadata
        if tag.lower() == "meta":
            if attrs.get("name", "").lower() == "generator":
                self.generator.append(
                    attrs.get("content", "")
                )

        # CSS dan JavaScript assets
        for attribute in ("src", "href"):
            value = attrs.get(attribute, "")

            if value:
                self.assets.append(value)

        # WordPress API discovery link
        if tag.lower() == "link":
            if attrs.get("rel", "").lower() == "https://api.w.org/":
                self.api_links.append(
                    attrs.get("href", "")
                )


def analyze_html(html):
    parser = WordPressParser()
    parser.feed(html)

    content = html.lower()

    indicators = []

    if parser.generator:
        indicators.append({
            "name": "generator-meta",
            "status": "observed",
            "evidence": parser.generator
        })

    if "wp-content/" in content:
        indicators.append({
            "name": "wp-content",
            "status": "observed",
            "evidence": "wp-content reference found"
        })

    if "wp-includes/" in content:
        indicators.append({
            "name": "wp-includes",
            "status": "observed",
            "evidence": "wp-includes reference found"
        })

    if parser.api_links:
        indicators.append({
            "name": "wordpress-api-link",
            "status": "observed",
            "evidence": parser.api_links
        })

    confidence = "low"

    if len(indicators) >= 3:
        confidence = "high"
    elif len(indicators) >= 1:
        confidence = "medium"

    return {
        "likely_wordpress": len(indicators) > 0,
        "confidence": confidence,
        "indicators": indicators
    }

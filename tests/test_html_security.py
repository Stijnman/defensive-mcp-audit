import unittest
from html.parser import HTMLParser

from defensive_mcp_audit.html_report import generate_html_report


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)


class HtmlSecurityTests(unittest.TestCase):
    def test_report_fields_cannot_inject_elements_or_event_handlers(self):
        payload = '\"><img src=x onerror=alert(1)><script>alert(1)</script>'
        report = {'risk_score': payload, 'findings': [{
            'severity': payload, 'title': payload, 'note': payload, 'value': payload,
        }]}
        document = generate_html_report(report)
        parser = Elements()
        parser.feed(document)
        self.assertNotIn('script', parser.tags)
        self.assertNotIn('img', parser.tags)
        self.assertFalse(any(name.startswith('on') for name, _ in parser.attributes))
        self.assertIn('sev-info', document)
        self.assertIn('&lt;script&gt;', document)

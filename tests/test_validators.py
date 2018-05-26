from django.core.validators import ValidationError
from django.test import TestCase

from oauth2_provider.settings import oauth2_settings
from oauth2_provider.validators import RedirectURIValidator


class TestValidators(TestCase):
    def test_validate_good_uris(self):
        validator = RedirectURIValidator(allowed_schemes=["https"])
        good_uris = [
            "https://example.com/",
            "https://example.org/?key=val",
            "https://example",
            "https://localhost",
            "https://1.1.1.1",
            "https://127.0.0.1",
            "https://255.255.255.255",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_custom_uri_scheme(self):
        validator = RedirectURIValidator(allowed_schemes=["my-scheme", "https", "git+ssh"])
        good_uris = [
            "my-scheme://example.com",
            "my-scheme://example",
            "my-scheme://localhost",
            "https://example.com",
            "HTTPS://example.com",
            "git+ssh://example.com",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_bad_uris(self):
        validator = RedirectURIValidator(allowed_schemes=["https"])
        oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https", "good"]
        bad_uris = [
            "http:/example.com",
            "HTTP://localhost",
            "HTTP://example.com",
            "HTTP://example.com.",
            "http://example.com/#fragment",
            "123://example.com",
            "http://fe80::1",
            "git+ssh://example.com",
            "my-scheme://example.com",
            "uri-without-a-scheme",
            "https://example.com/#fragment",
            "good://example.com/#fragment",
            "    ",
            "",
            # Bad IPv6 URL, urlparse behaves differently for these
            'https://["><script>alert()</script>',
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

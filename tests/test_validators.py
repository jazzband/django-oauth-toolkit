from django.core.validators import ValidationError
from django.test import TestCase

from oauth2_provider.settings import oauth2_settings
from oauth2_provider.validators import RedirectURIValidator, validate_uris


class TestValidators(TestCase):
    def test_validate_good_uris(self):
        validator = RedirectURIValidator(allowed_schemes=["https"])
        good_uris = [
            "https://example.com/",
            "https://example.org/?key=val",
            "https://example",
            "https://localhost",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_custom_uri_scheme(self):
        validator = RedirectURIValidator(allowed_schemes=["my-scheme", "https"])
        good_uris = [
            "my-scheme://example.com",
            "my-scheme://example",
            "my-scheme://localhost",
            "https://example.com",
            "HTTPS://example.com",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_whitespace_separators(self):
        # Check that whitespace can be used as a separator
        good_uris = "https://example.com\r\nhttps://example.com\thttps://example.com"
        # Check ValidationError not thrown
        validate_uris(good_uris)

    def test_validate_bad_uris(self):
        validator = RedirectURIValidator(allowed_schemes=["https"])
        oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https"]
        bad_uris = [
            "http:/example.com",
            "HTTP://localhost",
            "HTTP://example.com",
            "HTTP://example.com.",
            "http://example.com/#fragment",
            "my-scheme://example.com"
            "uri-without-a-scheme",
            "    ",
            "",
            # Bad IPv6 URL, urlparse behaves differently for these
            'https://["><script>alert()</script>',
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

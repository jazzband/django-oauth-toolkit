import pytest
from django.core.validators import ValidationError
from django.test import TestCase

from oauth2_provider.validators import RedirectURIValidator, AllowedURIValidator


@pytest.mark.usefixtures("oauth2_settings")
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

        validator = AllowedURIValidator(["my-scheme", "https", "git+ssh"], "Origin")
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_bad_uris(self):
        validator = RedirectURIValidator(allowed_schemes=["https"])
        self.oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES = ["https", "good"]
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

    def test_validate_good_origin_uris(self):
        """
        Test AllowedURIValidator validates origin URIs if they match requirements
        """
        validator = AllowedURIValidator(
            ["https"],
            "Origin",
            allow_path=False,
            allow_query=False,
            allow_fragments=False,
        )
        good_uris = [
            "https://example.com",
            "https://example.com:8080",
            "https://example",
            "https://localhost",
            "https://1.1.1.1",
            "https://127.0.0.1",
            "https://255.255.255.255",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_validate_bad_origin_uris(self):
        """
        Test AllowedURIValidator rejects origin URIs if they do not match requirements
        """
        validator = AllowedURIValidator(
            ["https"],
            "Origin",
            allow_path=False,
            allow_query=False,
            allow_fragments=False,
        )
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
            # Origin uri should not contain path, query of fragment parts
            # https://www.rfc-editor.org/rfc/rfc6454#section-7.1
            "https:/example.com/",
            "https:/example.com/test",
            "https:/example.com/?q=test",
            "https:/example.com/#test",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

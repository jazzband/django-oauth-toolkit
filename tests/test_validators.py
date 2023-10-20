import pytest
from django.core.validators import ValidationError
from django.test import TestCase

from oauth2_provider.validators import AllowedURIValidator, RedirectURIValidator, WildcardSet


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

    def test_validate_wildcard_scheme__bad_uris(self):
        validator = RedirectURIValidator(allowed_schemes=WildcardSet())
        bad_uris = [
            "http:/example.com#fragment",
            "HTTP://localhost#fragment",
            "http://example.com/#fragment",
            "good://example.com/#fragment",
            "    ",
            "",
            # Bad IPv6 URL, urlparse behaves differently for these
            'https://["><script>alert()</script>',
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError, msg=uri):
                validator(uri)

    def test_validate_wildcard_scheme_good_uris(self):
        validator = RedirectURIValidator(allowed_schemes=WildcardSet())
        good_uris = [
            "my-scheme://example.com",
            "my-scheme://example",
            "my-scheme://localhost",
            "https://example.com",
            "HTTPS://example.com",
            "HTTPS://example.com.",
            "git+ssh://example.com",
            "ANY://localhost",
            "scheme://example.com",
            "at://example.com",
            "all://example.com",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)


@pytest.mark.usefixtures("oauth2_settings")
class TestAllowedURIValidator(TestCase):
    # TODO: verify the specifics of the ValidationErrors
    def test_valid_schemes(self):
        validator = AllowedURIValidator(["my-scheme", "https", "git+ssh"], "test")
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

    def test_invalid_schemes(self):
        validator = AllowedURIValidator(["https"], "test")
        bad_uris = [
            "http:/example.com",
            "HTTP://localhost",
            "HTTP://example.com",
            "https://-exa",  # triggers an exception in the upstream validators
            "HTTP://example.com/path",
            "HTTP://example.com/path?query=string",
            "HTTP://example.com/path?query=string#fragmemt",
            "HTTP://example.com.",
            "http://example.com/path/#fragment",
            "http://example.com?query=string#fragment",
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

    def test_allow_paths_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_path=True)
        good_uris = [
            "https://example.com",
            "https://example.com:8080",
            "https://example",
            "https://example.com/path",
            "https://example.com:8080/path",
            "https://example/path",
            "https://localhost/path",
            "myapp://host/path",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_allow_paths_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_path=True)
        bad_uris = [
            "https://example.com?query=string",
            "https://example.com#fragment",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "bad://example.com/path",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_query_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_query=True)
        good_uris = [
            "https://example.com",
            "https://example.com:8080",
            "https://example.com?query=string",
            "https://example",
            "myapp://example.com?query=string",
            "myapp://example?query=string",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_allow_query_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_query=True)
        bad_uris = [
            "https://example.com/path",
            "https://example.com#fragment",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "https://example.com:8080/path",
            "https://example/path",
            "https://localhost/path",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "bad://example.com/path",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

    def test_allow_fragment_valid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_fragments=True)
        good_uris = [
            "https://example.com",
            "https://example.com#fragment",
            "https://example.com:8080",
            "https://example.com:8080#fragment",
            "https://example",
            "https://example#fragment",
            "myapp://example",
            "myapp://example#fragment",
            "myapp://example.com",
            "myapp://example.com#fragment",
        ]
        for uri in good_uris:
            # Check ValidationError not thrown
            validator(uri)

    def test_allow_fragment_invalid_urls(self):
        validator = AllowedURIValidator(["https", "myapp"], "test", allow_fragments=True)
        bad_uris = [
            "https://example.com?query=string",
            "https://example.com?query=string#fragment",
            "https://example.com/path",
            "https://example.com/path?query=string",
            "https://example.com/path#fragment",
            "https://example.com/path?query=string#fragment",
            "https://example.com:8080/path",
            "https://example?query=string",
            "https://example?query=string#fragment",
            "https://example/path",
            "https://example/path?query=string",
            "https://example/path#fragment",
            "https://example/path?query=string#fragment",
            "myapp://example?query=string",
            "myapp://example?query=string#fragment",
            "myapp://example/path",
            "myapp://example/path?query=string",
            "myapp://example/path#fragment",
            "myapp://example.com/path?query=string",
            "myapp://example.com/path#fragment",
            "myapp://example.com/path?query=string#fragment",
            "myapp://example.com?query=string",
            "bad://example.com",
        ]

        for uri in bad_uris:
            with self.assertRaises(ValidationError):
                validator(uri)

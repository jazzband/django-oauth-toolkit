import re
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.encoding import force_str


class URIValidator(URLValidator):
    scheme_re = r"^(?:[a-z][a-z0-9\.\-\+]*)://"

    dotless_domain_re = r"(?!-)[A-Z\d-]{1,63}(?<!-)"
    host_re = "|".join(
        (r"(?:" + URLValidator.host_re, URLValidator.ipv4_re, URLValidator.ipv6_re, dotless_domain_re + ")")
    )
    port_re = r"(?::\d{2,5})?"
    path_re = r"(?:[/?#][^\s]*)?"
    regex = re.compile(scheme_re + host_re + port_re + path_re, re.IGNORECASE)


class RedirectURIValidator(URIValidator):
    def __init__(self, allowed_schemes, allow_fragments=False):
        super().__init__(schemes=allowed_schemes)
        self.allow_fragments = allow_fragments

    def __call__(self, value):
        super().__call__(value)
        value = force_str(value)
        scheme, netloc, path, query, fragment = urlsplit(value)
        if fragment and not self.allow_fragments:
            raise ValidationError("Redirect URIs must not contain fragments")


class AllowedURIValidator(URIValidator):
    def __init__(self, schemes, name, allow_path=False, allow_query=False, allow_fragments=False):
        """
        :params schemes: List of allowed schemes. E.g.: ["https"]
        :params name: Name of the validater URI required for validation message. E.g.: "Origin"
        :params allow_path: If URI can contain path part
        :params allow_query: If URI can contain query part
        :params allow_fragments: If URI can contain fragments part
        """
        super().__init__(schemes=schemes)
        self.name = name
        self.allow_path = allow_path
        self.allow_query = allow_query
        self.allow_fragments = allow_fragments

    def __call__(self, value):
        super().__call__(value)
        value = force_str(value)
        scheme, netloc, path, query, fragment = urlsplit(value)
        if path and not self.allow_path:
            raise ValidationError("{} URIs must not contain path".format(self.name))
        if query and not self.allow_query:
            raise ValidationError("{} URIs must not contain query".format(self.name))
        if fragment and not self.allow_fragments:
            raise ValidationError("{} URIs must not contain fragments".format(self.name))

##
# WildcardSet is a special set that contains everything.
# This is required in order to move validation of the scheme from
# URLValidator (the base class of URIValidator), to OAuth2Application.clean().


class WildcardSet(set):
    """
    A set that always returns True on `in`.
    """

    def __contains__(self, item):
        return True

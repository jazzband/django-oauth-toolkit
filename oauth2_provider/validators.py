import re
from urllib.parse import urlsplit, urlunsplit

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils.encoding import force_text
from django.utils.translation import ugettext_lazy as _

from .settings import oauth2_settings


class URIValidator(URLValidator):
    scheme_re = r"^(?:[a-z][a-z0-9\.\-\+]*)://"

    dotless_domain_re = r"(?!-)[A-Z\d-]{1,63}(?<!-)"
    host_re = "|".join((
        r"(?:"+ URLValidator.host_re,
        URLValidator.ipv4_re,
        URLValidator.ipv6_re,
        dotless_domain_re + ")"
    ))
    port_re = r"(?::\d{2,5})?"
    path_re = r"(?:[/?#][^\s]*)?"
    regex = re.compile(scheme_re + host_re + port_re + path_re, re.IGNORECASE)


class RedirectURIValidator(URIValidator):
    def __init__(self, allowed_schemes):
        super().__init__(schemes=allowed_schemes)

    def __call__(self, value):
        super().__call__(value)
        value = force_text(value)
        if len(value.split("#")) > 1:
            raise ValidationError("Redirect URIs must not contain fragments")
        scheme, netloc, path, query, fragment = urlsplit(value)
        if scheme.lower() not in self.schemes:
            raise ValidationError("Redirect URI scheme is not allowed.")


def validate_uris(value):
    """
    This validator ensures that `value` contains valid blank-separated URIs"
    """
    v = RedirectURIValidator(oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES)
    uris = value.split()
    if not uris:
        raise ValidationError("Redirect URI cannot be empty")
    for uri in uris:
        v(uri)

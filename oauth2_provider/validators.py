from __future__ import unicode_literals

import re

from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from django.utils.encoding import force_text
from django.utils.six.moves.urllib.parse import urlsplit, urlunsplit
from django.core.validators import RegexValidator


class URIValidator(RegexValidator):
    regex = re.compile(
        r'^(?:[a-z0-9\.\-]*)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'(?!-)[A-Z\d-]{1,63}(?<!-)|'  # also cover non-dotted domain
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    message = _('Enter a valid URL.')

    def __call__(self, value):
        try:
            super(URIValidator, self).__call__(value)
        except ValidationError as e:
            # Trivial case failed. Try for possible IDN domain
            if value:
                value = force_text(value)
                scheme, netloc, path, query, fragment = urlsplit(value)
                try:
                    netloc = netloc.encode('idna').decode('ascii')  # IDN -> ACE
                except UnicodeError:  # invalid domain part
                    raise e
                url = urlunsplit((scheme, netloc, path, query, fragment))
                super(URIValidator, self).__call__(url)
            else:
                raise
        else:
            url = value


class RedirectURIValidator(URIValidator):
    def __call__(self, value):
        super(RedirectURIValidator, self).__call__(value)
        if len(value.split('#')) > 1:
            raise ValidationError('Redirect URIs must not contain fragments')


def validate_uris(value):
    """
    This validator ensures that `value` contains valid blank-separated urls"
    """
    v = RedirectURIValidator()
    for uri in value.split():
        v(uri)

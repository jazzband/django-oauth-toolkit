from django.http import HttpResponseRedirect
from django.core.exceptions import DisallowedRedirect
from django.utils.encoding import force_text
from django.utils.six.moves.urllib.parse import urlparse


class CustomSchemesHttpResponseRedirect(HttpResponseRedirect):
    """
    HttpResponseRedirect subclass that accepts an `allowed_schemes`
    positional argument to overwrite the default set of schemes.
    Warning: if `allowed_schemes` is empty, all schemes are allowed.
    """
    def __init__(self, redirect_to, *args, **kwargs):
        parsed = urlparse(force_text(redirect_to))
        try:
            self.allowed_schemes = kwargs.pop('allowed_schemes')
        except KeyError:
            pass
        if self.allowed_schemes and parsed.scheme and parsed.scheme not in self.allowed_schemes:
            raise DisallowedRedirect("Unsafe redirect to URL with protocol '%s'" % parsed.scheme)
        super(HttpResponseRedirect, self).__init__(*args, **kwargs)
        self['Location'] = iri_to_uri(redirect_to)

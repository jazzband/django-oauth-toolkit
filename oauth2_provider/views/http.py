from django.http import HttpResponse
from django.utils.encoding import iri_to_uri


class UnsafeHttpResponseRedirectBase(HttpResponse):
    """
    HttpResponseRedirectBase-like class that does not check the URI scheme.
    You should validate user-controlled URIs before redirecting to them through
    this class.
    """
    def __init__(self, redirect_to, *args, **kwargs):
        super(UnsafeHttpResponseRedirectBase, self).__init__(*args, **kwargs)
        self['Location'] = iri_to_uri(redirect_to)

    url = property(lambda self: self['Location'])


class UnsafeHttpResponseRedirect(UnsafeHttpResponseRedirectBase):
    status_code = 302


class UnsafeHttpResponsePermanentRedirect(UnsafeHttpResponseRedirectBase):
    status_code = 301

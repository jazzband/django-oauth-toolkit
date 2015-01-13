from django.http.response import HttpResponseRedirectBase


class SchemedHttpResponseRedirectBase(HttpResponseRedirectBase):
    """
    HttpResponseRedirectBase-like class that accepts an `allowed_schemes`
    positional argument to overwrite the default set of schemes.
    Warning: if `allowed_schemes` is empty, no scheme is allowed.
    """

    def __init__(self, redirect_to, *args, **kwargs):
        try:
            self.allowed_schemes = kwargs.pop('allowed_schemes')
        except KeyError:
            pass
        super(HttpResponseRedirectBase, self).__init__(redirect_to, *args, **kwargs)


class SchemedHttpResponseRedirect(SchemedHttpResponseRedirectBase):
    status_code = 302


class SchemedHttpResponsePermanentRedirect(SchemedHttpResponseRedirectBase):
    status_code = 301

from django.http import HttpResponseRedirect


class HttpResponseUriRedirect(HttpResponseRedirect):
    def __init__(self, redirect_to, allowed_schemes, *args, **kwargs):
        self.allowed_schemes = allowed_schemes
        super(HttpResponseUriRedirect, self).__init__(redirect_to, *args, **kwargs)

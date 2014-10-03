from django.http import HttpResponseRedirect

from .settings import oauth2_settings


class HttpResponseUriRedirect(HttpResponseRedirect):
    def __init__(self, redirect_to, *args, **kwargs):
        self.allowed_schemes = oauth2_settings.ALLOWED_REDIRECT_URI_SCHEMES
        super(HttpResponseUriRedirect, self).__init__(redirect_to, *args, **kwargs)

from django.views.generic import View

from ..settings import oauth2_settings
from .mixins import (
    ClientProtectedResourceMixin, OAuthLibMixin, ProtectedResourceMixin,
    ReadWriteScopedResourceMixin, ScopedResourceMixin
)


class InitializationMixin(OAuthLibMixin):

    """Initializer for OauthLibMixin
    """

    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS


class ProtectedResourceView(ProtectedResourceMixin, InitializationMixin, View):
    """
    Generic view protecting resources by providing OAuth2 authentication out of the box
    """
    pass


class ScopedProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources by providing OAuth2 authentication and Scopes handling
    out of the box
    """
    pass


class ReadWriteScopedResourceView(ReadWriteScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources with OAuth2 authentication and read/write scopes.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.
    """
    pass


class ClientProtectedResourceView(ClientProtectedResourceMixin, InitializationMixin, View):

    """View for protecting a resource with client-credentials method.
    This involves allowing access tokens, Basic Auth and plain credentials in request body.
    """

    pass


class ClientProtectedScopedResourceView(ScopedResourceMixin, ClientProtectedResourceView):

    """Impose scope restrictions if client protection fallsback to access token.
    """

    pass

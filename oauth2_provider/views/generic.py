from django.views.generic import View

from oauthlib.oauth2 import Server

from ..oauth2_validators import OAuth2Validator
from .mixins import ProtectedResourceMixin, ScopedResourceMixin


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    Generic view protecting resources by providing OAuth2 authentication out of the box
    """
    server_class = Server
    validator_class = OAuth2Validator


class ScopeProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources by providing OAuth2 authentication and Scopes handling out of the box
    """

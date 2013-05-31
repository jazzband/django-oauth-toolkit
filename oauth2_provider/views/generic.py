from django.views.generic import View

from oauthlib.oauth2 import Server

from ..oauth2_validators import OAuth2Validator
from .mixins import ProtectedResourceMixin, ScopedResourceMixin


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    """
    server_class = Server
    validator_class = OAuth2Validator


class ScopeProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    """

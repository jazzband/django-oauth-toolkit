from django.views.generic import View

from oauthlib.oauth2 import Server

from ..oauth2_validators import OAuth2Validator
from .mixins import ProtectedResourceMixin, ScopedResourceMixin, ReadWriteScopedResourceMixin


class ProtectedResourceView(ProtectedResourceMixin, View):
    """
    Generic view protecting resources by providing OAuth2 authentication out of the box
    """
    server_class = Server
    validator_class = OAuth2Validator


class ScopedProtectedResourceView(ScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources by providing OAuth2 authentication and Scopes handling out of the box
    """


class ReadWriteScopedResourceView(ReadWriteScopedResourceMixin, ProtectedResourceView):
    """
    Generic view protecting resources with OAuth2 authentication and read/write scopes.
    GET, HEAD, OPTIONS http methods require "read" scope. Otherwise "write" scope is required.
    """
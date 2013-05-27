import logging
from datetime import timedelta

from django.utils import timezone
from oauthlib.oauth2 import RequestValidator

from .models import Application, Grant


log = logging.getLogger('oauth2_provider')


class OAuth2Validator(RequestValidator):
    def __init__(self, user):
        self.user = user

    def validate_client_id(self, client_id, request, *args, **kwargs):
        try:
            request.client = Application.objects.get(client_id=client_id)
            return True

        except Application.DoesNotExist:
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        if response_type == 'code':
            return client.grant_type == Application.GRANT_AUTHORIZATION_CODE
        return False

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # TODO: check scopes are a subset of allowes scopes for current Application
        log.debug('scopes: {0}'.format(scopes))
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ['r', 'w', 'rw']  # TODO do not make assumptions HERE about the default. Ask Application!

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.redirect_uri_allowed(redirect_uri)

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        expires = timezone.now() + timedelta(seconds=60)  # TODO put delta in settings
        g = Grant(application=request.client, user=self.user, code=code['code'], expires=expires,
                  redirect_uri=request.redirect_uri, scope=' '.join(request.scopes))
        g.save()

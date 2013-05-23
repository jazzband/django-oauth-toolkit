from oauthlib.oauth2 import RequestValidator

from .models import Application

import logging
log = logging.getLogger('oauth2_provider')


class OAuth2Validator(RequestValidator):
    def validate_client_id(self, client_id, request, *args, **kwargs):
        try:
            app = Application.objects.get(client_id=client_id)
            request.client = app
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
        log.debug('scopes: %s' % ''.join(scopes))
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ''

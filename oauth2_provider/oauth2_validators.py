from oauthlib.oauth2 import RequestValidator

from .models import Application, Grant

import datetime
import logging
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
        """
        No need to validate scopes at the moment
        """
        log.debug('scopes: {0}'.format(scopes))
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ['r', 'w', 'rw']  # TODO move it in the settings

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.redirect_uri_allowed(redirect_uri)

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # TODO: what about user has already a grant for given Client?
        # proposal: destroy it and re-create
        g,created = Grant.objects.get_or_create(application=request.client, user=self.user)
        g.code = code['code']
        g.expires = datetime.datetime.now()  # TODO generate expire time
        g.redirect_uri = request.redirect_uri
        g.scope = ' '.join(request.scopes)
        g.save()

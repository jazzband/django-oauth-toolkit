import logging
from datetime import timedelta

from django.utils import timezone
from oauthlib.oauth2 import RequestValidator

from .models import Application, Grant, AccessToken, RefreshToken


log = logging.getLogger('oauth2_provider')

GRANT_TYPE_MAPPING = {
    'authorization_code': (Application.GRANT_ALLINONE, Application.GRANT_AUTHORIZATION_CODE),
    #'authorization_code': (Application.GRANT_ALLINONE, Application.GRANT_AUTHORIZATION_CODE),
    'password': (Application.GRANT_ALLINONE, Application.GRANT_PASSWORD),
    'client_credential': (Application.GRANT_ALLINONE, Application.GRANT_CLIENT_CREDENTIAL)
}


class OAuth2Validator(RequestValidator):
    def __init__(self, user):
        self.user = user

    def authenticate_client(self, request, *args, **kwargs):
        """

        """
        auth = request.headers.get('HTTP_AUTHORIZATION', None)

        if not auth:
            return False

        basic, base64 = auth.split(' ')
        client_id, client_secret = base64.decode('base64').split(':')

        try:
            request.client = Application.objects.get(client_id=client_id, client_secret=client_secret)
            return True
        except Application.DoesNotExist:
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # TODO: see the parent method doc
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        grant = Grant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # TODO: cleanup of dangling grants here?
        grant = Grant.objects.get(code=code, application=request.client)
        grant.delete()

    def validate_client_id(self, client_id, request, *args, **kwargs):
        try:
            request.client = Application.objects.get(client_id=client_id)
            return True

        except Application.DoesNotExist:
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        try:
            access_token = AccessToken.objects.get(token=token)
            return access_token.is_valid(scopes)
        except AccessToken.DoesNotExist:
            return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        try:
            grant = Grant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.user = grant.user
                request.scopes = grant.scope.split(' ')
                return True

        except Grant.DoesNotExist:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        try:
            return request.client.authorization_grant_type in GRANT_TYPE_MAPPING[grant_type]
        except KeyError:
            return False

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        if response_type == 'code':
            return client.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
        elif response_type == 'token':
            return client.authorization_grant_type == Application.GRANT_IMPLICIT
        # TODO: missing other validation
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

    def save_bearer_token(self, token, request, *args, **kwargs):
        expires = timezone.now() + timedelta(seconds=36000)  # TODO put delta in settings
        access_token = AccessToken(
            user=self.user,  # TODO check why if response_type==token request.user is None
            scope=token['scope'],
            expires=expires,
            token=token['access_token'],
            application=request.client)
        access_token.save()

        if 'refresh_token' in token:
            refresh_token = RefreshToken(
                user=request.user,
                token=token['refresh_token'],
                application=request.client,
                access_token=access_token
            )
            refresh_token.save()

        token['expires_in'] = 36000  # TODO put delta in settings

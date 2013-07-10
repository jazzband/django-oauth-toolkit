import base64
import logging
from datetime import timedelta

from django.utils import timezone
from django.contrib.auth import authenticate
from oauthlib.oauth2 import RequestValidator

from .models import Application, Grant, AccessToken, RefreshToken
from .settings import oauth2_settings


log = logging.getLogger('oauth2_provider')

GRANT_TYPE_MAPPING = {
    'authorization_code': (Application.GRANT_ALLINONE, Application.GRANT_AUTHORIZATION_CODE),
    'password': (Application.GRANT_ALLINONE, Application.GRANT_PASSWORD),
    'client_credentials': (Application.GRANT_ALLINONE, Application.GRANT_CLIENT_CREDENTIALS),
    'refresh_token': (Application.GRANT_ALLINONE, Application.GRANT_AUTHORIZATION_CODE, Application.GRANT_PASSWORD,
                      Application.GRANT_CLIENT_CREDENTIALS)
}


class OAuth2Validator(RequestValidator):
    def authenticate_client(self, request, *args, **kwargs):
        """
        Check if client exists and it's authenticating itself as in rfc:`3.2.1`
        """
        auth = request.headers.get('HTTP_AUTHORIZATION', None)

        if not auth:
            return False

        auth_type, auth_string = auth.split(' ')
        encoding = request.encoding or 'utf-8'

        auth_string_decoded = base64.b64decode(auth_string).decode(encoding)
        client_id, client_secret = auth_string_decoded.split(':', 1)

        try:
            request.client = Application.objects.get(client_id=client_id, client_secret=client_secret)
            return True

        except Application.DoesNotExist:
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """
        If we are here, the client did not authenticate itself as in rfc:`3.2.1` and we can proceed only if the client
        exists and it's not of type 'Confidential'. Also assign Application instance to request.client.
        """
        client_secret = request.client_secret

        try:
            request.client = request.client or Application.objects.get(client_id=client_id, client_secret=client_secret)
            return request.client.client_type != Application.CLIENT_CONFIDENTIAL

        except Application.DoesNotExist:
            return False

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """
        Ensure the redirect_uri is listed in the Application instance redirect_uris field
        """
        grant = Grant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        Remove the temporary grant used to swap the authorization token
        """
        grant = Grant.objects.get(code=code, application=request.client)
        grant.delete()

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        Ensure an Application exists with given client_id. Also assign Application instance to request.client.
        """
        try:
            request.client = request.client or Application.objects.get(client_id=client_id)
            return True

        except Application.DoesNotExist:
            return False

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided token is valid
        """
        try:
            access_token = AccessToken.objects.get(token=token)
            if access_token.is_valid(scopes):
                request.client = access_token.application
                request.user = access_token.user
                request.scopes = scopes

                # this is needed by django rest framework
                request.access_token = access_token
                return True
            return False
        except AccessToken.DoesNotExist:
            return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        try:
            grant = Grant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.scopes = grant.scope.split(' ')
                request.user = grant.user
                return True
            return False

        except Grant.DoesNotExist:
            return False

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        """
        Validate both grant_type is a valid string and grant_type is allowed for current workflow
        """
        assert(grant_type in GRANT_TYPE_MAPPING)  # mapping misconfiguration
        return request.client.authorization_grant_type in GRANT_TYPE_MAPPING[grant_type]

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        """
        We currently do not support the Authorization Endpoint Response Types registry as in rfc:`8.4`, so validate
        the response_type only if it matches 'code' or 'token'
        """
        if response_type == 'code':
            return client.authorization_grant_type == Application.GRANT_AUTHORIZATION_CODE
        elif response_type == 'token':
            return client.authorization_grant_type == Application.GRANT_IMPLICIT
        else:
            return False

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        Ensure required scopes are permitted (as specified in the settings file)
        """
        return set(scopes).issubset(set(oauth2_settings.SCOPES))

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return oauth2_settings.SCOPES

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return request.client.redirect_uri_allowed(redirect_uri)

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        expires = timezone.now() + timedelta(seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)
        g = Grant(application=request.client, user=request.user, code=code['code'], expires=expires,
                  redirect_uri=request.redirect_uri, scope=' '.join(request.scopes))
        g.save()

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token, If refresh token is issued, remove old refresh tokens as in rfc:`6`
        """
        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        if request.grant_type == 'client_credentials':
            request.user = request.client.user

        access_token = AccessToken(
            user=request.user,
            scope=token['scope'],
            expires=expires,
            token=token['access_token'],
            application=request.client)
        access_token.save()

        if 'refresh_token' in token:
            # discard old refresh tokens
            RefreshToken.objects.filter(user=request.user).filter(application=request.client).delete()

            refresh_token = RefreshToken(
                user=request.user,
                token=token['refresh_token'],
                application=request.client,
                access_token=access_token
            )
            refresh_token.save()

        # TODO check out a more reliable way to communicate expire time to oauthlib
        token['expires_in'] = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Check username and password correspond to a valid and active User
        """
        u = authenticate(username=username, password=password)
        if u is not None and u.is_active:
            request.user = u
            return True
        return False

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # TODO: since this method is invoked *after* validate_refresh_token, could we avoid this second query for RefreshToken?
        rt = RefreshToken.objects.get(token=refresh_token)
        return rt.access_token.scope

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        Check refresh_token exists and refers to the right client.
        Also attach User instance to the request object
        """
        try:
            rt = RefreshToken.objects.get(token=refresh_token)
            request.user = rt.user
            return rt.application == client

        except RefreshToken.DoesNotExist:
            return False
